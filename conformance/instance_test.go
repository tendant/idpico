//go:build conformance

package conformance

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ---- binaries ---------------------------------------------------------

var (
	buildOnce sync.Once
	buildDir  string // holds idpico and idpicoctl for the whole run
	buildErr  error
)

// binaries builds ./cmd/idpico and ./cmd/idpicoctl from the enclosing
// module once per run and returns the directory holding them.
func binaries() (string, error) {
	buildOnce.Do(func() {
		root, err := moduleRoot()
		if err != nil {
			buildErr = err
			return
		}
		buildDir, err = os.MkdirTemp("", "idpico-conformance-bin-")
		if err != nil {
			buildErr = err
			return
		}
		for _, pkg := range []string{"idpico", "idpicoctl"} {
			build := exec.Command("go", "build", "-o", filepath.Join(buildDir, pkg), "./cmd/"+pkg)
			build.Dir = root
			build.Stdout, build.Stderr = os.Stderr, os.Stderr
			if err := build.Run(); err != nil {
				buildErr = fmt.Errorf("go build ./cmd/%s: %w", pkg, err)
				return
			}
		}
	})
	return buildDir, buildErr
}

// moduleRoot is the directory containing go.mod, i.e. the parent of this
// package. go test runs with the package directory as working directory.
func moduleRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	root := filepath.Dir(wd)
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return "", fmt.Errorf("go.mod not found in %s: %w", root, err)
	}
	return root, nil
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// ---- instance ---------------------------------------------------------

// live holds every running instance so that an interrupted run (TestMain's
// signal handler) can stop them all, not just the default server.
var live sync.Map // *instance -> struct{}

func stopAllInstances() {
	live.Range(func(k, _ any) bool {
		i := k.(*instance)
		i.stop()
		_ = os.RemoveAll(i.workDir)
		return true
	})
}

// instance is one idpico server process under the suite's control. It
// keeps its port and data directory across restarts, so the issuer — and
// therefore `iss` in every token it issued — stays the same.
type instance struct {
	dataDir string
	workDir string // HOME/TMPDIR/cwd for the process; no .env can leak in
	port    int
	issuer  string            // as configured: env IDPICO_ISSUER_URL or the loopback URL
	env     map[string]string // overrides on top of baseEnv, kept for restart
	logPath string

	// binary overrides the current build, e.g. a previous release built
	// from git for the upgrade test. Empty means the current build.
	binary string

	cmd    *exec.Cmd
	exited chan error
}

// baseEnv is the deterministic configuration every instance starts from:
// the clients and user in cfg, no rate limiting or lockout (tests log in
// dozens of times a minute from one address), no playground, default
// lifetimes. It is built from scratch so nothing from the caller's shell
// reaches the server.
func baseEnv(port int, dataDir string) map[string]string {
	return map[string]string{
		"IDPICO_HOST":                 "127.0.0.1",
		"IDPICO_PORT":                 strconv.Itoa(port),
		"IDPICO_ISSUER_URL":           "http://127.0.0.1:" + strconv.Itoa(port),
		"IDPICO_DATA_DIR":             dataDir,
		"IDPICO_LOG_FORMAT":           "text",
		"IDPICO_LOG_LEVEL":            "warn",
		"IDPICO_PLAYGROUND_ENABLED":   "false",
		"IDPICO_LOGIN_RATE_LIMIT":     "0",
		"IDPICO_LOCKOUT_MAX_ATTEMPTS": "0",
		"IDPICO_BOOTSTRAP_USERS":      cfg.bootstrapUsers(),
		"IDPICO_BOOTSTRAP_CLIENTS":    cfg.bootstrapClients(),
	}
}

// launch starts a new instance on a free port. env overrides baseEnv; a
// value of "" removes the variable. The caller stops it.
func launch(ctx context.Context, dataDir string, env map[string]string) (*instance, error) {
	port, err := freePort()
	if err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp("", "idpico-conformance-")
	if err != nil {
		return nil, err
	}
	if dataDir == "" {
		dataDir = filepath.Join(work, "data")
	}
	i := &instance{dataDir: dataDir, workDir: work, port: port, env: map[string]string{}, logPath: filepath.Join(work, "server.log")}
	if err := i.start(ctx, env); err != nil {
		i.stop()
		return nil, err
	}
	return i, nil
}

// startInstance is launch for tests: failures are fatal and the instance is
// stopped when the test ends. Pass dataDir "" for a fresh directory that is
// removed with the instance, or a t.TempDir() to keep control of it.
func startInstance(t *testing.T, dataDir string, env map[string]string) *instance {
	t.Helper()
	i, err := launch(context.Background(), dataDir, env)
	if err != nil {
		t.Fatalf("start idpico: %v", err)
	}
	t.Cleanup(func() {
		i.stop()
		_ = os.RemoveAll(i.workDir) // holds the data dir too unless the caller supplied one
	})
	return i
}

// start runs the process with baseEnv + the instance's accumulated
// overrides + env, and waits for /healthz.
func (i *instance) start(ctx context.Context, env map[string]string) error {
	bin, err := binaries()
	if err != nil {
		return err
	}
	for k, v := range env {
		i.env[k] = v
	}
	merged := baseEnv(i.port, i.dataDir)
	for k, v := range i.env {
		if v == "" {
			delete(merged, k)
		} else {
			merged[k] = v
		}
	}
	i.issuer = merged["IDPICO_ISSUER_URL"]

	logFile, err := os.OpenFile(i.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logFile.Close()

	binary := i.binary
	if binary == "" {
		binary = filepath.Join(bin, "idpico")
	}
	cmd := exec.Command(binary)
	cmd.Dir = i.workDir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + i.workDir, "TMPDIR=" + i.workDir}
	for k, v := range merged {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start idpico: %w", err)
	}
	i.cmd = cmd
	i.exited = make(chan error, 1)
	go func() { i.exited <- cmd.Wait() }()
	live.Store(i, struct{}{})

	health := "http://127.0.0.1:" + strconv.Itoa(i.port) + "/healthz"
	deadline := time.Now().Add(15 * time.Second)
	for {
		select {
		case err := <-i.exited:
			i.cmd = nil
			return fmt.Errorf("idpico exited before becoming ready: %v\n%s", err, redact(i.log()))
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		resp, err := http.Get(health)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				// Alive; it must also report ready (the backend answers).
				ready, err := http.Get(strings.TrimSuffix(health, "/healthz") + "/readyz")
				if err != nil {
					return err
				}
				ready.Body.Close()
				if ready.StatusCode != http.StatusOK {
					return fmt.Errorf("/readyz answered HTTP %d after /healthz was OK", ready.StatusCode)
				}
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("idpico did not become ready within 15s\n%s", redact(i.log()))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// stop terminates the process (SIGTERM, then SIGKILL after 5 s) and waits
// for it. The data directory is kept; safe to call twice.
func (i *instance) stop() {
	if i.cmd == nil {
		return
	}
	_ = i.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-i.exited:
	case <-time.After(5 * time.Second):
		_ = i.cmd.Process.Kill()
		<-i.exited
	}
	i.cmd = nil
	live.Delete(i)
}

// restart stops the process and starts it again on the same port and data
// directory, with env applied on top of the previous overrides.
func (i *instance) restart(t *testing.T, env map[string]string) {
	t.Helper()
	i.stop()
	if err := i.start(context.Background(), env); err != nil {
		t.Fatalf("restart idpico: %v", err)
	}
}

// idpicoctl runs the CLI against this instance's data directory and returns
// its combined output; a non-zero exit is fatal.
func (i *instance) idpicoctl(t *testing.T, args ...string) string {
	t.Helper()
	bin, err := binaries()
	if err != nil {
		t.Fatal(err)
	}
	driver := i.env["IDPICO_STORE_DRIVER"]
	if driver == "" {
		driver = "sqlite"
	}
	cmd := exec.Command(filepath.Join(bin, "idpicoctl"), append([]string{"-driver", driver, "-data-dir", i.dataDir}, args...)...)
	cmd.Dir = i.workDir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + i.workDir}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("idpicoctl %s: %v\n%s", strings.Join(args, " "), err, redact(string(out)))
	}
	if cfg.Verbose {
		t.Logf("idpicoctl %s:\n%s", strings.Join(args, " "), redact(string(out)))
	}
	return string(out)
}

// provider returns a client-side view of this instance that talks to it
// directly (no proxy in between).
func (i *instance) provider() *provider {
	return newProvider(i.issuer, nil)
}

func (i *instance) log() string {
	b, _ := os.ReadFile(i.logPath)
	return string(b)
}

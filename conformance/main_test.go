//go:build conformance

package conformance

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

// cfg is the provider under test, set by TestMain.
var cfg Config

// serverLogPath holds the throwaway server's combined output, printed
// (redacted) when it fails to start.
var serverLogPath string

func TestMain(m *testing.M) {
	cfg = loadConfig()

	if cfg.External() {
		os.Exit(m.Run())
	}

	// Ctrl-C during a run must still stop the server and remove its data.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cleanup, err := startServer(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "conformance: cannot start idpico:", err)
		if cleanup != nil {
			cleanup()
		}
		os.Exit(1)
	}
	var once sync.Once
	go func() {
		<-ctx.Done()
		once.Do(cleanup)
		os.Exit(130)
	}()

	code := m.Run()
	once.Do(cleanup)
	os.Exit(code)
}

// startServer builds ./cmd/idpico from the enclosing module, starts it on a
// free loopback port with deterministic test data in a temporary directory,
// and waits for /healthz. The returned cleanup stops the process and removes
// the directory; it is safe to call after a failed start.
func startServer(ctx context.Context) (cleanup func(), err error) {
	root, err := moduleRoot()
	if err != nil {
		return nil, err
	}

	tmp, err := os.MkdirTemp("", "idpico-conformance-")
	if err != nil {
		return nil, err
	}
	// Until the process is started there is only the directory to remove.
	cleanup = func() { _ = os.RemoveAll(tmp) }

	bin := filepath.Join(tmp, "idpico")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/idpico")
	build.Dir = root
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		return cleanup, fmt.Errorf("go build ./cmd/idpico: %w", err)
	}

	port, err := freePort()
	if err != nil {
		return cleanup, err
	}
	cfg.Issuer = "http://127.0.0.1:" + strconv.Itoa(port)

	serverLogPath = filepath.Join(tmp, "server.log")
	logFile, err := os.Create(serverLogPath)
	if err != nil {
		return cleanup, err
	}
	defer logFile.Close()

	data := filepath.Join(tmp, "data")
	cmd := exec.Command(bin)
	// Run inside the temp dir so a developer's .env (loaded by the server
	// from its working directory) cannot leak into the test instance.
	cmd.Dir = tmp
	// The environment is built from scratch for the same reason: no
	// IDPICO_* from the caller's shell reaches the server.
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + tmp,
		"TMPDIR=" + tmp,
		"IDPICO_HOST=127.0.0.1",
		"IDPICO_PORT=" + strconv.Itoa(port),
		"IDPICO_ISSUER_URL=" + cfg.Issuer,
		"IDPICO_DATA_DIR=" + data,
		"IDPICO_LOG_FORMAT=text",
		"IDPICO_LOG_LEVEL=warn",
		"IDPICO_PLAYGROUND_ENABLED=false",
		// Security tests issue many requests per minute from one address and
		// deliberately fail logins; neither limiter is under test.
		"IDPICO_LOGIN_RATE_LIMIT=0",
		"IDPICO_LOCKOUT_MAX_ATTEMPTS=0",
		// Short lifetimes so expiry can be observed with a short sleep. Every
		// other test finishes its flow in milliseconds.
		"IDPICO_AUTH_CODE_TTL=" + shortTTL.String(),
		"IDPICO_ACCESS_TOKEN_TTL=" + shortTTL.String(),
		"IDPICO_BOOTSTRAP_USERS=" + cfg.bootstrapUsers(),
		"IDPICO_BOOTSTRAP_CLIENTS=" + cfg.bootstrapClients(),
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		return cleanup, fmt.Errorf("start idpico: %w", err)
	}

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	cleanup = func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
		_ = os.RemoveAll(tmp)
	}

	deadline := time.Now().Add(15 * time.Second)
	for {
		select {
		case err := <-exited:
			dumpServerLog()
			return cleanup, fmt.Errorf("idpico exited before becoming ready: %v", err)
		case <-ctx.Done():
			return cleanup, ctx.Err()
		default:
		}
		resp, err := http.Get(cfg.Issuer + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return cleanup, nil
			}
		}
		if time.Now().After(deadline) {
			dumpServerLog()
			return cleanup, fmt.Errorf("idpico did not become ready within 15s")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// shortTTL is the auth code and access token lifetime on the throwaway
// server; see TestSecurityToken/expired_code and TestSecurityJWT/expired.
const shortTTL = 4 * time.Second

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

func dumpServerLog() {
	if serverLogPath == "" {
		return
	}
	b, err := os.ReadFile(serverLogPath)
	if err != nil {
		return
	}
	fmt.Fprintf(os.Stderr, "---- idpico output ----\n%s---- end ----\n", redact(string(b)))
}

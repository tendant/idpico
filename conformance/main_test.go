//go:build conformance

package conformance

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"
)

// cfg is the provider under test, set by TestMain.
var cfg Config

// def is the default server every non-operational test talks to: the
// throwaway instance TestMain starts, or the external issuer.
var def *provider

func TestMain(m *testing.M) {
	cfg = loadConfig()

	if cfg.External() {
		def = newProvider(cfg.Issuer, nil)
		os.Exit(m.Run())
	}

	// Ctrl-C during a run must still stop the server and remove its data.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	inst, err := launch(ctx, "", map[string]string{
		// Short lifetimes so expiry can be observed with a short sleep. Every
		// other test finishes its flow in milliseconds.
		"IDPICO_AUTH_CODE_TTL":    shortTTL.String(),
		"IDPICO_ACCESS_TOKEN_TTL": shortTTL.String(),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "conformance: cannot start idpico:", err)
		if buildDir != "" {
			_ = os.RemoveAll(buildDir)
		}
		os.Exit(1)
	}
	cfg.Issuer = inst.issuer
	def = inst.provider()

	var once sync.Once
	cleanup := func() {
		stopAllInstances() // the default server and any an operational test has running
		_ = os.RemoveAll(buildDir)
	}
	go func() {
		<-ctx.Done()
		once.Do(cleanup)
		os.Exit(130)
	}()

	code := m.Run()
	once.Do(cleanup)
	os.Exit(code)
}

// shortTTL is the auth code and access token lifetime on the default
// throwaway server; see TestSecurityToken/expired_code and
// TestSecurityJWT/expired.
const shortTTL = 4 * time.Second

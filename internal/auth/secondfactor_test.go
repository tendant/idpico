package auth

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tendant/idpico/internal/domain"
)

// Attempts are counted before the code is checked, so concurrent
// submissions on one pending login cannot exceed the limit.
func TestPendingLoginReserveIsAtomic(t *testing.T) {
	p := newPendingLogins()
	token, err := p.add(&domain.User{ID: "u", Email: "u@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	var granted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := p.reserve(token); ok {
				granted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := granted.Load(); got != pendingLoginAttempts {
		t.Errorf("%d attempts granted, want %d", got, pendingLoginAttempts)
	}
	if _, ok := p.get(token); ok {
		t.Error("pending login survived the limit")
	}
}

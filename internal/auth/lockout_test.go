package auth

import (
	"testing"
	"time"
)

func TestLockoutServiceDisabled(t *testing.T) {
	// maxAttempts = 0 means disabled
	svc := NewLockoutService(0, time.Minute)

	// Should never lock
	for i := 0; i < 100; i++ {
		if svc.RecordFailure("test@example.com") {
			t.Error("Lockout should not trigger when disabled")
		}
	}

	if svc.IsLocked("test@example.com") {
		t.Error("Account should not be locked when service is disabled")
	}
}

func TestLockoutAfterMaxAttempts(t *testing.T) {
	svc := NewLockoutService(3, time.Minute)
	email := "test@example.com"

	// First 2 attempts should not lock
	if svc.RecordFailure(email) {
		t.Error("First attempt should not lock")
	}
	if svc.RecordFailure(email) {
		t.Error("Second attempt should not lock")
	}
	if svc.IsLocked(email) {
		t.Error("Should not be locked before max attempts")
	}

	// Third attempt should lock
	if !svc.RecordFailure(email) {
		t.Error("Third attempt should lock")
	}
	if !svc.IsLocked(email) {
		t.Error("Should be locked after max attempts")
	}
}

func TestLockoutExpires(t *testing.T) {
	// Use very short duration for testing
	svc := NewLockoutService(2, 50*time.Millisecond)
	email := "test@example.com"

	// Lock the account
	svc.RecordFailure(email)
	svc.RecordFailure(email)

	if !svc.IsLocked(email) {
		t.Error("Should be locked")
	}

	// Wait for lockout to expire
	time.Sleep(60 * time.Millisecond)

	if svc.IsLocked(email) {
		t.Error("Lockout should have expired")
	}
}

func TestLockoutClearedOnSuccess(t *testing.T) {
	svc := NewLockoutService(3, time.Minute)
	email := "test@example.com"

	// Record some failures
	svc.RecordFailure(email)
	svc.RecordFailure(email)

	// Success should clear the counter
	svc.RecordSuccess(email)

	// Should be able to fail 3 more times before lock
	svc.RecordFailure(email)
	svc.RecordFailure(email)
	if svc.IsLocked(email) {
		t.Error("Should not be locked after success cleared counter")
	}

	svc.RecordFailure(email)
	if !svc.IsLocked(email) {
		t.Error("Should be locked after 3 new failures")
	}
}

func TestLockoutRemainingAttempts(t *testing.T) {
	svc := NewLockoutService(5, time.Minute)
	email := "test@example.com"

	if svc.GetRemainingAttempts(email) != 5 {
		t.Errorf("Expected 5 remaining attempts, got %d", svc.GetRemainingAttempts(email))
	}

	svc.RecordFailure(email)
	if svc.GetRemainingAttempts(email) != 4 {
		t.Errorf("Expected 4 remaining attempts, got %d", svc.GetRemainingAttempts(email))
	}

	svc.RecordFailure(email)
	svc.RecordFailure(email)
	if svc.GetRemainingAttempts(email) != 2 {
		t.Errorf("Expected 2 remaining attempts, got %d", svc.GetRemainingAttempts(email))
	}
}

func TestLockoutRemainingTime(t *testing.T) {
	duration := 100 * time.Millisecond
	svc := NewLockoutService(1, duration)
	email := "test@example.com"

	// Not locked yet
	if svc.GetLockoutRemaining(email) != 0 {
		t.Error("Should have no remaining time when not locked")
	}

	// Lock it
	svc.RecordFailure(email)

	remaining := svc.GetLockoutRemaining(email)
	if remaining <= 0 || remaining > duration {
		t.Errorf("Remaining time should be between 0 and %v, got %v", duration, remaining)
	}

	// Wait for expiry
	time.Sleep(duration + 10*time.Millisecond)

	if svc.GetLockoutRemaining(email) != 0 {
		t.Error("Should have no remaining time after expiry")
	}
}

func TestLockoutMultipleAccounts(t *testing.T) {
	svc := NewLockoutService(2, time.Minute)

	// Lock account 1
	svc.RecordFailure("user1@example.com")
	svc.RecordFailure("user1@example.com")

	// Account 2 should not be affected
	if svc.IsLocked("user2@example.com") {
		t.Error("Account 2 should not be locked")
	}

	if !svc.IsLocked("user1@example.com") {
		t.Error("Account 1 should be locked")
	}
}

func TestLockoutResetAfterExpiry(t *testing.T) {
	svc := NewLockoutService(2, 50*time.Millisecond)
	email := "test@example.com"

	// Lock it
	svc.RecordFailure(email)
	svc.RecordFailure(email)

	// Wait for expiry
	time.Sleep(60 * time.Millisecond)

	// Counter should be reset, so 2 more failures to lock again
	if svc.RecordFailure(email) {
		t.Error("First failure after expiry should not lock")
	}
	if !svc.RecordFailure(email) {
		t.Error("Second failure after expiry should lock")
	}
}

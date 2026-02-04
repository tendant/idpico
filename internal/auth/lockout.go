// Package auth provides authentication functionality.
package auth

import (
	"sync"
	"time"
)

// LockoutService tracks failed login attempts and locks accounts.
type LockoutService struct {
	maxAttempts int
	duration    time.Duration
	attempts    map[string]*lockoutEntry
	mu          sync.RWMutex
}

type lockoutEntry struct {
	count    int
	lockedAt time.Time
}

// NewLockoutService creates a new LockoutService.
// maxAttempts: number of failed attempts before lockout (0 = disabled)
// duration: how long the account stays locked
func NewLockoutService(maxAttempts int, duration time.Duration) *LockoutService {
	return &LockoutService{
		maxAttempts: maxAttempts,
		duration:    duration,
		attempts:    make(map[string]*lockoutEntry),
	}
}

// IsLocked checks if an account is currently locked.
func (s *LockoutService) IsLocked(email string) bool {
	if s.maxAttempts <= 0 {
		return false // Lockout disabled
	}

	s.mu.RLock()
	entry, exists := s.attempts[email]
	s.mu.RUnlock()

	if !exists {
		return false
	}

	// Check if lock has expired
	if !entry.lockedAt.IsZero() && time.Since(entry.lockedAt) < s.duration {
		return true
	}

	return false
}

// RecordFailure records a failed login attempt and returns true if account is now locked.
func (s *LockoutService) RecordFailure(email string) bool {
	if s.maxAttempts <= 0 {
		return false // Lockout disabled
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.attempts[email]
	if !exists {
		entry = &lockoutEntry{}
		s.attempts[email] = entry
	}

	// If previously locked but expired, reset
	if !entry.lockedAt.IsZero() && time.Since(entry.lockedAt) >= s.duration {
		entry.count = 0
		entry.lockedAt = time.Time{}
	}

	entry.count++

	// Lock if threshold reached
	if entry.count >= s.maxAttempts {
		entry.lockedAt = time.Now()
		return true
	}

	return false
}

// RecordSuccess clears failed attempts for an account after successful login.
func (s *LockoutService) RecordSuccess(email string) {
	if s.maxAttempts <= 0 {
		return // Lockout disabled
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.attempts, email)
}

// GetRemainingAttempts returns the number of attempts remaining before lockout.
func (s *LockoutService) GetRemainingAttempts(email string) int {
	if s.maxAttempts <= 0 {
		return -1 // Lockout disabled
	}

	s.mu.RLock()
	entry, exists := s.attempts[email]
	s.mu.RUnlock()

	if !exists {
		return s.maxAttempts
	}

	// If locked but expired, reset
	if !entry.lockedAt.IsZero() && time.Since(entry.lockedAt) >= s.duration {
		return s.maxAttempts
	}

	remaining := s.maxAttempts - entry.count
	if remaining < 0 {
		remaining = 0
	}
	return remaining
}

// GetLockoutRemaining returns the time remaining until the account is unlocked.
// Returns 0 if not locked.
func (s *LockoutService) GetLockoutRemaining(email string) time.Duration {
	if s.maxAttempts <= 0 {
		return 0
	}

	s.mu.RLock()
	entry, exists := s.attempts[email]
	s.mu.RUnlock()

	if !exists || entry.lockedAt.IsZero() {
		return 0
	}

	remaining := s.duration - time.Since(entry.lockedAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

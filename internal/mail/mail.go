// Package mail sends outbound email. The IdP only needs plain-text
// transactional messages (password reset, email verification), so the
// abstraction is deliberately small.
package mail

import (
	"context"
	"log/slog"
	"strings"
	"sync"
)

// Message is a plain-text email.
type Message struct {
	To      string
	Subject string
	Body    string
}

// Mailer delivers messages.
type Mailer interface {
	Send(ctx context.Context, msg Message) error
}

// LogMailer writes each message to the log instead of sending it. It is the
// default for local development: the reset/verification link shows up in the
// server output.
type LogMailer struct {
	logger *slog.Logger
}

// NewLogMailer creates a LogMailer.
func NewLogMailer(logger *slog.Logger) *LogMailer {
	if logger == nil {
		logger = slog.Default()
	}
	return &LogMailer{logger: logger}
}

func (m *LogMailer) Send(_ context.Context, msg Message) error {
	m.logger.Info("outbound email (log mailer)",
		"to", msg.To,
		"subject", msg.Subject,
		"body", strings.TrimSpace(msg.Body),
	)
	return nil
}

// MemoryMailer records messages for tests.
type MemoryMailer struct {
	mu       sync.Mutex
	Messages []Message
}

func (m *MemoryMailer) Send(_ context.Context, msg Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Messages = append(m.Messages, msg)
	return nil
}

// Last returns the most recent message, or nil.
func (m *MemoryMailer) Last() *Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.Messages) == 0 {
		return nil
	}
	msg := m.Messages[len(m.Messages)-1]
	return &msg
}

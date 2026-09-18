package mail

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// SMTPConfig configures the SMTP mailer.
type SMTPConfig struct {
	Host        string
	Port        int
	Username    string // Empty disables authentication
	Password    string
	From        string
	ImplicitTLS bool // Connect with TLS immediately (port 465) instead of STARTTLS
}

// SMTPMailer sends mail through an SMTP relay. STARTTLS is used whenever the
// server offers it; set ImplicitTLS for servers that expect TLS from the
// first byte.
type SMTPMailer struct {
	cfg SMTPConfig
}

// NewSMTPMailer creates an SMTPMailer.
func NewSMTPMailer(cfg SMTPConfig) (*SMTPMailer, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("smtp host is required")
	}
	if cfg.From == "" {
		return nil, fmt.Errorf("smtp from address is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	return &SMTPMailer{cfg: cfg}, nil
}

func (m *SMTPMailer) Send(ctx context.Context, msg Message) error {
	addr := net.JoinHostPort(m.cfg.Host, fmt.Sprint(m.cfg.Port))

	client, err := m.dial(ctx, addr)
	if err != nil {
		return fmt.Errorf("smtp connect: %w", err)
	}
	defer client.Close()

	if !m.cfg.ImplicitTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: m.cfg.Host}); err != nil {
				return fmt.Errorf("smtp starttls: %w", err)
			}
		}
	}

	if m.cfg.Username != "" {
		auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	if err := client.Mail(m.cfg.From); err != nil {
		return fmt.Errorf("smtp from: %w", err)
	}
	if err := client.Rcpt(msg.To); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write([]byte(buildMessage(m.cfg.From, msg))); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close: %w", err)
	}
	return client.Quit()
}

func (m *SMTPMailer) dial(ctx context.Context, addr string) (*smtp.Client, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	var (
		conn net.Conn
		err  error
	)
	if m.cfg.ImplicitTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: m.cfg.Host})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	return smtp.NewClient(conn, m.cfg.Host)
}

// buildMessage renders RFC 5322 headers and body with CRLF line endings.
func buildMessage(from string, msg Message) string {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", msg.To)
	fmt.Fprintf(&b, "Subject: %s\r\n", sanitizeHeader(msg.Subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(msg.Body, "\r\n", "\n"), "\n", "\r\n"))
	return b.String()
}

// sanitizeHeader strips line breaks so a subject cannot inject headers.
func sanitizeHeader(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

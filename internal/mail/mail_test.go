package mail

import (
	"strings"
	"testing"
)

func TestBuildMessage(t *testing.T) {
	out := buildMessage("idp@example.com", Message{
		To:      "user@example.com",
		Subject: "Reset\r\nBcc: attacker@example.com",
		Body:    "line one\nline two",
	})

	if strings.Contains(out, "\r\nBcc:") {
		t.Error("header injection via subject should be neutralized")
	}
	if !strings.Contains(out, "\r\n\r\nline one\r\nline two") {
		t.Errorf("body should follow a blank line with CRLF endings, got %q", out)
	}
	if !strings.HasPrefix(out, "From: idp@example.com\r\nTo: user@example.com\r\n") {
		t.Errorf("unexpected header order: %q", out)
	}
}

func TestNewSMTPMailer_Validation(t *testing.T) {
	if _, err := NewSMTPMailer(SMTPConfig{From: "x@y"}); err == nil {
		t.Error("missing host should error")
	}
	if _, err := NewSMTPMailer(SMTPConfig{Host: "smtp"}); err == nil {
		t.Error("missing from should error")
	}
	m, err := NewSMTPMailer(SMTPConfig{Host: "smtp", From: "x@y"})
	if err != nil || m.cfg.Port != 587 {
		t.Errorf("default port should be 587, got %d (err %v)", m.cfg.Port, err)
	}
}

package audit

import (
	"context"
	"net/http"
	"testing"

	"github.com/tendant/simple-idp/internal/domain"
	"github.com/tendant/simple-idp/internal/store/sqlite"
)

func TestRecorder(t *testing.T) {
	ctx := context.Background()
	s, err := sqlite.NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer s.Close()

	rec := NewRecorder(s.Audit(), nil)
	actor := &domain.User{ID: "u1", Email: "admin@example.com"}
	rec.Record(ctx, Event{Actor: actor, Action: UserCreated, TargetType: "user", TargetID: "u2", Detail: "bob@example.com", IP: "10.0.0.1"})
	rec.Record(ctx, Event{ActorEmail: "nobody@example.com", Action: LoginFailure, TargetType: "user"})

	events, _ := s.Audit().List(ctx, 10)
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	// newest first
	if events[0].Action != LoginFailure || events[0].ActorEmail != "nobody@example.com" || events[0].ActorID != "" {
		t.Errorf("anonymous event wrong: %+v", events[0])
	}
	if events[1].ActorID != "u1" || events[1].ActorEmail != "admin@example.com" || events[1].TargetID != "u2" {
		t.Errorf("actor fields wrong: %+v", events[1])
	}

	// nil recorder is a no-op
	var none *Recorder
	none.Record(ctx, Event{Action: Logout})
}

func TestClientIP(t *testing.T) {
	for in, want := range map[string]string{"1.2.3.4:5678": "1.2.3.4", "[::1]:80": "[::1]", "noport": "noport"} {
		if got := ClientIP(&http.Request{RemoteAddr: in}); got != want {
			t.Errorf("ClientIP(%q) = %q, want %q", in, got, want)
		}
	}
	if ClientIP(nil) != "" {
		t.Error("nil request should yield empty IP")
	}
}

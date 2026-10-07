package metrics

import "testing"

func TestNormalizeMethod(t *testing.T) {
	for in, want := range map[string]string{"GET": "GET", "POST": "POST", "AAAA1": "OTHER", "get": "OTHER", "PROPFIND": "OTHER"} {
		if got := normalizeMethod(in); got != want {
			t.Errorf("normalizeMethod(%q) = %q, want %q", in, got, want)
		}
	}
}

package domain

import "testing"

func TestValidateRedirectURI(t *testing.T) {
	for uri, ok := range map[string]bool{
		"https://app.example.com/cb":      true,
		"http://127.0.0.1:8080/callback":  true,
		"com.example.app:/oauth2redirect": true, // native app, RFC 8252 §7.1
		"urn:ietf:wg:oauth:2.0:oob":       true,
		"https://app.example.com/cb#frag": false,
		"https://app.example.com/cb#":     false,
		"javascript://x/%0aalert(1)":      false,
		"JavaScript:alert(1)":             false,
		"data:text/html,<script>":         false,
		"file:///etc/passwd":              false,
		"/relative/path":                  false,
		"https:///no-host":                false,
		"":                                false,
	} {
		if err := ValidateRedirectURI(uri); (err == nil) != ok {
			t.Errorf("ValidateRedirectURI(%q) = %v, want ok=%v", uri, err, ok)
		}
	}
}

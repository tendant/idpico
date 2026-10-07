package auth

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B, SHA-1 column: the secret is the ASCII string
// "12345678901234567890"; the 8-digit values there end in the 6-digit ones.
func TestTOTPCode_RFC6238Vectors(t *testing.T) {
	key := []byte("12345678901234567890")
	for _, tc := range []struct {
		unix int64
		want string
	}{
		{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"},
		{1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"},
	} {
		if got := totpCode(key, totpStep(time.Unix(tc.unix, 0))); got != tc.want {
			t.Errorf("T=%d: got %s, want %s", tc.unix, got, tc.want)
		}
	}
}

func TestVerifyTOTP(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := b32.DecodeString(secret)
	now := time.Unix(1_800_000_000, 0)
	code := func(offset int64) string { return totpCode(key, totpStep(now)+offset) }

	step, ok := VerifyTOTP(secret, code(0), now, 0)
	if !ok || step != totpStep(now) {
		t.Fatalf("current code refused")
	}
	if _, ok := VerifyTOTP(secret, code(0), now, step); ok {
		t.Error("the same code was accepted twice")
	}
	if _, ok := VerifyTOTP(secret, code(-1), now, 0); !ok {
		t.Error("previous step refused (clock drift allowance)")
	}
	if _, ok := VerifyTOTP(secret, code(1), now, 0); !ok {
		t.Error("next step refused (clock drift allowance)")
	}
	if _, ok := VerifyTOTP(secret, code(-2), now, 0); ok {
		t.Error("a code two steps old was accepted")
	}
	if _, ok := VerifyTOTP(secret, code(-1), now, step); ok {
		t.Error("an older step was accepted after a newer one was used")
	}
	if _, ok := VerifyTOTP(secret, " "+code(0)[:3]+" "+code(0)[3:], now, 0); !ok {
		t.Error("spaces in the code should be ignored")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := VerifyTOTP(secret, bad, now, 0); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, hashes, err := NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != RecoveryCodeCount || len(hashes) != RecoveryCodeCount {
		t.Fatalf("got %d codes, %d hashes", len(codes), len(hashes))
	}
	for _, h := range hashes {
		for _, c := range codes {
			if strings.Contains(h, normalizeRecoveryCode(c)) {
				t.Fatal("a stored hash contains its code")
			}
		}
	}
	rest, ok := UseRecoveryCode(hashes, strings.ToUpper(strings.ReplaceAll(codes[3], "-", "")))
	if !ok || len(rest) != RecoveryCodeCount-1 {
		t.Fatalf("valid code refused (ok=%v, left %d)", ok, len(rest))
	}
	if _, ok := UseRecoveryCode(rest, codes[3]); ok {
		t.Error("a recovery code worked twice")
	}
	if _, ok := UseRecoveryCode(rest, "aaaaa-aaaaa"); ok {
		t.Error("an unknown code was accepted")
	}
}

func TestTOTPURI(t *testing.T) {
	got := TOTPURI("IDPico", "alice@example.com", "ABC")
	if !strings.HasPrefix(got, "otpauth://totp/IDPico:alice@example.com?") || !strings.Contains(got, "secret=ABC") || !strings.Contains(got, "issuer=IDPico") {
		t.Errorf("URI = %s", got)
	}
}

package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP (RFC 6238) with the parameters every authenticator app supports:
// HMAC-SHA1, 6 digits, 30-second steps. A code is accepted for the current
// step and one step either side, to absorb clock drift and typing time.
const (
	totpDigits = 6
	totpPeriod = 30 * time.Second
	totpSkew   = 1

	// RecoveryCodeCount is how many one-time recovery codes enrollment issues.
	RecoveryCodeCount = 10
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit secret, base32 without padding, as
// authenticator apps expect it.
func NewTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// TOTPURI is the otpauth:// URI an authenticator app scans (Key Uri Format).
func TOTPURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// totpCode computes the code for a time step (RFC 4226 §5.3).
func totpCode(key []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, bin%1_000_000)
}

// GenerateTOTP returns the code an authenticator app shows for secret at t.
func GenerateTOTP(secret string, t time.Time) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	return totpCode(key, totpStep(t)), nil
}

func totpStep(t time.Time) int64 { return t.Unix() / int64(totpPeriod/time.Second) }

// VerifyTOTP checks code against secret at now. It returns the matched time
// step, which the caller stores: a step at or before lastStep is refused, so
// a code is never accepted twice (RFC 6238 §5.2).
func VerifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return 0, false
	}
	current := totpStep(now)
	for step := current - totpSkew; step <= current+totpSkew; step++ {
		if step <= lastStep {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(totpCode(key, step)), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// NewRecoveryCodes returns RecoveryCodeCount one-time codes to show the user
// once, and their hashes to store. Each has 50 bits of entropy (10 base32
// characters, shown as xxxxx-xxxxx), so a fast hash is enough.
func NewRecoveryCodes() (codes, hashes []string, err error) {
	for i := 0; i < RecoveryCodeCount; i++ {
		b := make([]byte, 7)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		raw := strings.ToLower(b32.EncodeToString(b))[:10]
		codes = append(codes, raw[:5]+"-"+raw[5:])
		hashes = append(hashes, hashRecoveryCode(raw))
	}
	return codes, hashes, nil
}

// normalizeRecoveryCode accepts a code typed with or without the dash, in
// any case.
func normalizeRecoveryCode(code string) string {
	return strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
}

func hashRecoveryCode(normalized string) string {
	sum := sha256.Sum256([]byte("idpico-recovery:" + normalized))
	return hex.EncodeToString(sum[:])
}

// UseRecoveryCode reports whether code matches one of hashes, and returns
// hashes without it (each code works once).
func UseRecoveryCode(hashes []string, code string) ([]string, bool) {
	n := normalizeRecoveryCode(code)
	if len(n) != 10 {
		return hashes, false
	}
	h := hashRecoveryCode(n)
	for i, stored := range hashes {
		if subtle.ConstantTimeCompare([]byte(stored), []byte(h)) == 1 {
			rest := append(append([]string(nil), hashes[:i]...), hashes[i+1:]...)
			return rest, true
		}
	}
	return hashes, false
}

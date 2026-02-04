package auth

import (
	"strings"
	"testing"
)

func TestHashPassword(t *testing.T) {
	password := "testpassword123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	// Verify hash format
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("Hash should start with $argon2id$, got: %s", hash)
	}

	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Errorf("Hash should have 6 parts, got %d", len(parts))
	}
}

func TestHashPasswordUniqueSalts(t *testing.T) {
	password := "testpassword123"

	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	// Same password should produce different hashes (different salts)
	if hash1 == hash2 {
		t.Error("Same password should produce different hashes due to random salt")
	}
}

func TestVerifyPassword(t *testing.T) {
	password := "testpassword123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	// Correct password should verify
	valid, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !valid {
		t.Error("Correct password should verify")
	}

	// Wrong password should not verify
	valid, err = VerifyPassword("wrongpassword", hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if valid {
		t.Error("Wrong password should not verify")
	}
}

func TestVerifyPasswordInvalidHash(t *testing.T) {
	tests := []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"wrong format", "not-a-valid-hash"},
		{"wrong algorithm", "$bcrypt$v=19$m=65536,t=1,p=4$salt$hash"},
		{"missing parts", "$argon2id$v=19$m=65536"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyPassword("password", tt.hash)
			if err == nil {
				t.Error("Expected error for invalid hash")
			}
		})
	}
}

func TestVerifyPasswordEmptyPassword(t *testing.T) {
	// Empty password should still be hashable and verifiable
	hash, err := HashPassword("")
	if err != nil {
		t.Fatalf("HashPassword failed for empty password: %v", err)
	}

	valid, err := VerifyPassword("", hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !valid {
		t.Error("Empty password should verify against its hash")
	}

	valid, err = VerifyPassword("notempty", hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if valid {
		t.Error("Non-empty password should not verify against empty password hash")
	}
}

func BenchmarkHashPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = HashPassword("benchmarkpassword")
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	hash, _ := HashPassword("benchmarkpassword")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = VerifyPassword("benchmarkpassword", hash)
	}
}

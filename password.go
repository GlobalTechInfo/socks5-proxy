package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
)

// ─── Password hashing ──────────────────────────────────────────────────────
//
// The users table used to hold passwords verbatim, which turns any copy of the
// database -- a stolen backup, a stray file, a support ticket attachment -- into
// a list of working credentials, for every deployment that shares one. Those
// are also the passwords operators reuse elsewhere.
//
// PBKDF2-HMAC-SHA256 at 600k iterations, which is the OWASP figure for that
// combination, from the standard library: no new dependency for the one thing
// in a proxy that must not be improvised. It costs about 0.3s per login here,
// which is a feature on an endpoint that accepts password guesses.
//
// The parameters are recorded in every stored hash rather than assumed at
// verify time, so they can be raised later without invalidating what is
// already on disk: each hash keeps verifying at its own cost, and a successful
// login can rewrite it at the new one.
const (
	pbkdf2Iterations = 600_000
	pbkdf2SaltLen    = 16
	pbkdf2KeyLen     = 32

	// passwordScheme tags the stored value, so a future scheme is
	// distinguishable from this one rather than being guessed at.
	passwordScheme = "pbkdf2-sha256"
)

// HashPassword returns a self-describing PBKDF2 hash. The password itself is
// not retained anywhere.
func HashPassword(plain string) (string, error) {
	if plain == "" {
		return "", fmt.Errorf("refusing to hash an empty password")
	}
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, plain, salt, pbkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return fmt.Sprintf("%s$iter=%d$%s$%s",
		passwordScheme, pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword reports whether plain matches the stored value.
//
// legacy is true when the stored value predates hashing, meaning it matched
// because it was the password in the clear. The caller uses that to rewrite the
// row, so an install upgrades one account per login instead of needing a
// migration that has to touch every credential at once.
func VerifyPassword(stored, plain string) (ok bool, legacy bool) {
	if stored == "" || plain == "" {
		return false, false
	}
	if !strings.HasPrefix(stored, passwordScheme+"$") {
		// Pre-hashing value: the stored text was the password itself.
		return subtle.ConstantTimeCompare([]byte(stored), []byte(plain)) == 1, true
	}
	iter, salt, key, ok := parseHashedPassword(stored)
	if !ok {
		return false, false
	}
	got, err := pbkdf2.Key(sha256.New, plain, salt, iter, len(key))
	if err != nil {
		return false, false
	}
	return subtle.ConstantTimeCompare(got, key) == 1, false
}

func parseHashedPassword(stored string) (iter int, salt, key []byte, ok bool) {
	// scheme$iter=..$salt$key
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != passwordScheme {
		return 0, nil, nil, false
	}
	if _, err := fmt.Sscanf(parts[1], "iter=%d", &iter); err != nil {
		return 0, nil, nil, false
	}
	// The stored value chooses the cost, so a corrupt or hostile record must
	// not be able to turn one login into a denial of service.
	if iter < 1 || iter > 10_000_000 {
		return 0, nil, nil, false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) < 8 {
		return 0, nil, nil, false
	}
	key, err = base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(key) < 16 {
		return 0, nil, nil, false
	}
	return iter, salt, key, true
}

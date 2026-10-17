package main

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestHashPasswordRoundTrip(t *testing.T) {
	const secret = "correct horse battery staple"

	hash, err := HashPassword(secret)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if strings.Contains(hash, secret) {
		t.Fatal("the hash contains the password")
	}
	if !strings.HasPrefix(hash, passwordScheme+"$") {
		t.Errorf("hash %q does not name its scheme and parameters", hash)
	}
	if !strings.Contains(hash, "iter=600000") {
		t.Errorf("hash %q does not record its cost", hash)
	}

	if ok, legacy := VerifyPassword(hash, secret); !ok || legacy {
		t.Errorf("verify(correct) = %v, legacy=%v; want true, false", ok, legacy)
	}
	if ok, _ := VerifyPassword(hash, "wrong password"); ok {
		t.Error("a wrong password verified")
	}
	if ok, _ := VerifyPassword(hash, ""); ok {
		t.Error("an empty password verified")
	}

	// Two hashes of the same password must differ, or the salt is not doing
	// its job and one rainbow table would open every account.
	other, err := HashPassword(secret)
	if err != nil {
		t.Fatalf("hash again: %v", err)
	}
	if other == hash {
		t.Error("hashing is deterministic; the salt is not being applied")
	}
	if ok, _ := VerifyPassword(other, secret); !ok {
		t.Error("a hash made with a different salt did not verify")
	}

	if _, err := HashPassword(""); err == nil {
		t.Error("an empty password was hashed")
	}
}

// A password stored before hashing existed must keep working, and must be
// reported as legacy so the caller can upgrade it.
func TestVerifyPasswordAcceptsLegacyPlaintext(t *testing.T) {
	if ok, legacy := VerifyPassword("oldpassword", "oldpassword"); !ok || !legacy {
		t.Errorf("legacy verify = %v, legacy=%v; want true, true", ok, legacy)
	}
	if ok, legacy := VerifyPassword("oldpassword", "guess"); ok || !legacy {
		t.Errorf("wrong password against a legacy row = %v, legacy=%v; want false, true", ok, legacy)
	}
	// An empty stored value must never verify, whatever is offered.
	if ok, _ := VerifyPassword("", ""); ok {
		t.Error("an empty stored password verified against an empty offer")
	}
}

// A corrupt or hostile record must be refused rather than believed. The stored
// value chooses the iteration count, so an absurd one would turn a login into a
// denial of service.
func TestVerifyPasswordRejectsCorruptHashes(t *testing.T) {
	good, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	parts := strings.Split(good, "$")

	for _, bad := range []string{
		"",
		"pbkdf2-sha256",
		"pbkdf2-sha256$",
		"pbkdf2-sha256$iter=0$" + parts[2] + "$" + parts[3],
		"pbkdf2-sha256$iter=99999999$" + parts[2] + "$" + parts[3],
		"pbkdf2-sha256$iter=" + parts[2] + "$" + parts[3],
		"pbkdf2-sha256$iter=600000$!!!$" + parts[3],
		"pbkdf2-sha256$iter=600000$" + parts[2] + "$",
		"pbkdf2-sha512$iter=600000$" + parts[2] + "$" + parts[3],
		"scrypt$N=32768,r=8,p=1$" + parts[2] + "$" + parts[3],
		parts[0] + "$iter=600000$" + parts[2] + "$" + parts[3] + "$extra",
	} {
		if ok, legacy := VerifyPassword(bad, "secret"); ok {
			t.Errorf("corrupt hash %q verified (legacy=%v)", bad, legacy)
		}
	}
}

// The point of the whole change: what lands in the database is not the password.
func TestStoredPasswordIsNotThePassword(t *testing.T) {
	store := newTestStore(t)

	user, err := store.CreateUser("alice", "swordfish-123", "pro")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	stored, err := store.GetUser(user.Username)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if strings.Contains(stored.PasswordHash, "swordfish-123") {
		t.Fatal("the password is stored in the clear")
	}
	if ok, legacy := VerifyPassword(stored.PasswordHash, "swordfish-123"); !ok || legacy {
		t.Errorf("the stored hash does not verify: ok=%v legacy=%v", ok, legacy)
	}

	// Changing a password through the admin path must hash as well.
	newPass := "a different one"
	if err := store.UpdateUser(user.ID, nil, &newPass, nil); err != nil {
		t.Fatalf("update password: %v", err)
	}
	stored, _ = store.GetUser(user.Username)
	if strings.Contains(stored.PasswordHash, newPass) {
		t.Fatal("the new password is stored in the clear")
	}
	if ok, _ := VerifyPassword(stored.PasswordHash, newPass); !ok {
		t.Error("the new password does not verify against its stored hash")
	}
	if ok, _ := VerifyPassword(stored.PasswordHash, "swordfish-123"); ok {
		t.Error("the old password still verifies after a change")
	}
}

// A row written before hashing existed authenticates, and is rewritten on the
// way through -- which is how an existing install cleans itself up without a
// migration that has to touch every credential at once.
func TestLoginUpgradesLegacyPasswordRow(t *testing.T) {
	store := newTestStore(t)

	user, err := store.CreateUser("legacy", "still-works", "basic")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	// Put the row back the way an older release would have left it.
	store.mu.Lock()
	_, err = store.db.Exec("UPDATE users SET password_hash=? WHERE id=?", "still-works", user.ID)
	store.mu.Unlock()
	if err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}

	cfg := DefaultConfig()
	cfg.AuthEnabled = true
	cfg.AdminEnabled = false
	cfg.SecurityHeadersEnabled = false
	cfg.RateLimitEnabled = false
	cfg.ProxyPort = freePort(t)
	// Credentials that are not the user's, so success can only come from the
	// database path.
	cfg.Username = "nobody"
	cfg.Password = "nothing"

	s := NewProxyServer(cfg)
	s.store = store

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.ProxyPort))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go s.handleClient(conn, "")
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	if err := socks5ConnectAndAuth(t, conn, "legacy", "still-works", "example.com", 80); err != nil {
		t.Fatalf("a pre-hashing password no longer authenticates: %v", err)
	}

	stored, err := store.GetUser("legacy")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if stored.PasswordHash == "still-works" {
		t.Fatal("the row still holds the password in the clear after a successful login")
	}
	if ok, legacy := VerifyPassword(stored.PasswordHash, "still-works"); !ok || legacy {
		t.Errorf("upgraded row does not verify: ok=%v legacy=%v", ok, legacy)
	}

	// And the upgraded row still authenticates on the next connection.
	conn2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial again: %v", err)
	}
	defer conn2.Close()
	conn2.SetDeadline(time.Now().Add(30 * time.Second))
	if err := socks5ConnectAndAuth(t, conn2, "legacy", "still-works", "example.com", 80); err != nil {
		t.Fatalf("the upgraded row no longer authenticates: %v", err)
	}
}

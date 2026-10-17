package main

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// ─── Per-client rate limiting ───────────────────────────────────────────────

// The documented behaviour is per client. Under the single shared bucket this
// used to be, one address could spend everyone's budget.
func TestRateLimiterSetIsolatesClients(t *testing.T) {
	set := newRateLimiterSet(5)

	for range 5 {
		if !set.allow("10.0.0.1") {
			t.Fatal("first client's fifth request was refused")
		}
	}
	if set.allow("10.0.0.1") {
		t.Error("sixth request for the same client should be refused at 5 rps")
	}

	// The whole point: a different client is unaffected by the first one's burst.
	for i := range 5 {
		if !set.allow("10.0.0.2") {
			t.Fatalf("second client refused on request %d while another client was flooding", i+1)
		}
	}
}

func TestRateLimiterSetRefillsOverTime(t *testing.T) {
	set := newRateLimiterSet(5)
	for range 5 {
		set.allow("10.0.0.1")
	}
	if set.allow("10.0.0.1") {
		t.Fatal("bucket should be empty")
	}
	// Refill is time-based, not reset-on-use: nudge the clock rather than sleep.
	set.mu.Lock()
	set.buckets["10.0.0.1"].last = time.Now().Add(-time.Second)
	set.mu.Unlock()

	if !set.allow("10.0.0.1") {
		t.Error("bucket did not refill after a second")
	}
}

// Buckets must not accumulate for every address the proxy has ever seen.
func TestRateLimiterSetSweepsIdleBuckets(t *testing.T) {
	set := newRateLimiterSet(5)
	for i := range 10 {
		set.allow(strconv.Itoa(i))
	}
	if len(set.buckets) != 10 {
		t.Fatalf("got %d buckets, want 10", len(set.buckets))
	}

	set.mu.Lock()
	// Pretend the last sweep was long ago and nobody has been back since.
	set.lastSweep = time.Now().Add(-time.Hour)
	for _, b := range set.buckets {
		b.lastSeen = time.Now().Add(-rateLimiterIdle - time.Minute)
	}
	set.mu.Unlock()

	// The sweep happens inside allow(). The returning client gets a fresh,
	// full bucket, which is the point of sweeping rather than deleting on use.
	if !set.allow("10.0.0.9") {
		t.Fatal("a client returning after a sweep should start with a full budget")
	}
	if got := len(set.buckets); got != 1 {
		t.Errorf("got %d buckets after a sweep, want only the client that just came back", got)
	}
}

// A change in the dashboard must reach the limiter without a restart.
func TestRateLimiterSetRPSChangeApplies(t *testing.T) {
	set := newRateLimiterSet(2)
	for range 2 {
		set.allow("10.0.0.1")
	}
	if set.allow("10.0.0.1") {
		t.Fatal("third request should be refused at 2 rps")
	}

	// The drained client keeps its debt: a higher limit is not a free refill.
	if set.allow("10.0.0.1") {
		t.Error("raising the limit should not hand the drained client free tokens")
	}

	// A client that has not spent anything now gets the new rate.
	set.setRPS(10)
	allowed := 0
	for range 10 {
		if set.allow("10.0.0.3") {
			allowed++
		}
	}
	if allowed != 10 {
		t.Errorf("new client got %d of 10 immediate requests after setRPS(10)", allowed)
	}
}

// ─── Configuration precedence ───────────────────────────────────────────────

// Editing .env and restarting used to change nothing whenever the dashboard had
// ever saved that setting.
func TestApplyDBOverridesEnvironmentWins(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Username = "env-user"
	cfg.Password = "env-pass"
	cfg.envSet = map[string]bool{"proxy_user": true, "proxy_pass": true}

	dbCfg := map[string]string{
		"proxy_user":      "db-user",
		"proxy_pass":      "db-pass",
		"admin_username":  "db-admin",
		"max_connections": "500",
	}

	applied := applyDBOverrides(&cfg, dbCfg)

	if cfg.Username != "env-user" || cfg.Password != "env-pass" {
		t.Errorf("environment was overwritten by the database: %s/%s", cfg.Username, cfg.Password)
	}
	// Keys the environment did not mention still come from the database.
	if cfg.AdminUser != "db-admin" {
		t.Errorf("admin_username = %q, want the stored value", cfg.AdminUser)
	}
	if cfg.MaxConns != 500 {
		t.Errorf("max_connections = %d, want the stored 500", cfg.MaxConns)
	}
	for _, key := range []string{"proxy_user", "proxy_pass"} {
		if contains(applied, key) {
			t.Errorf("%s was reported as applied from the database, but the environment set it", key)
		}
	}
	if !contains(applied, "admin_username") || !contains(applied, "max_connections") {
		t.Errorf("applied = %v, want the keys that were not set in the environment", applied)
	}
}

func TestApplyDBOverridesDatabaseWinsWhenEnvUnset(t *testing.T) {
	cfg := DefaultConfig()
	dbCfg := map[string]string{"proxy_pass": "db-pass", "auth_enabled": "false", "rate_limit_rps": "99"}

	applyDBOverrides(&cfg, dbCfg)

	if cfg.Password != "db-pass" {
		t.Errorf("password = %q, want the stored value when the environment is silent", cfg.Password)
	}
	if cfg.AuthEnabled {
		t.Error("auth_enabled = true, want the stored false")
	}
	if cfg.RateLimitRPS != 99 {
		t.Errorf("rate_limit_rps = %d, want the stored 99", cfg.RateLimitRPS)
	}
}

// Every documented setting must be tracked, or the precedence rule has a hole.
func TestEveryDatabaseOverridableKeyIsTrackedFromEnv(t *testing.T) {
	envFor := map[string]string{
		"max_connections":          "MAX_CONNECTIONS",
		"proxy_user":               "PROXY_USER",
		"proxy_pass":               "PROXY_PASS",
		"auth_enabled":             "AUTH_ENABLED",
		"admin_auth_enabled":       "ADMIN_AUTH_ENABLED",
		"admin_username":           "ADMIN_USER",
		"admin_pass":               "ADMIN_PASS",
		"security_headers_enabled": "SECURITY_HEADERS_ENABLED",
		"rate_limit_enabled":       "RATE_LIMIT_ENABLED",
		"rate_limit_rps":           "RATE_LIMIT_RPS",
	}
	for _, env := range envFor {
		t.Setenv(env, "1")
	}
	cfgFile := writeTempConfig(t, `{}`)
	cfg, err := LoadConfig(cfgFile)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	for key := range envFor {
		if !cfg.envSet[key] {
			t.Errorf("%s is overridable from the database but its environment variable was not recorded", key)
		}
	}
}

// ─── Bandwidth pacing ───────────────────────────────────────────────────────

func TestPacerCapsThroughput(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 256<<10) // 256 KiB
	var sink bytes.Buffer

	start := time.Now()
	n, err := copyPaced(&sink, bytes.NewReader(payload), newPacer(1))
	if err != nil {
		t.Fatalf("copyPaced: %v", err)
	}
	elapsed := time.Since(start)

	if n != int64(len(payload)) {
		t.Fatalf("copied %d bytes, want %d", n, len(payload))
	}
	if !bytes.Equal(sink.Bytes(), payload) {
		t.Fatal("pacing changed the byte stream, which must stay transparent")
	}

	// 256 KiB at 1 Mbps is 2.05s of transfer time. The first second comes from
	// the burst allowance, so the floor is a little under that.
	floor := 900 * time.Millisecond
	if elapsed < floor {
		t.Errorf("256 KiB through a 1 Mbps pacer took %s, want at least %s: the limit is not being applied", elapsed, floor)
	}
}

func TestPacerNilMeansUnlimited(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 512<<10)
	var sink bytes.Buffer

	start := time.Now()
	if _, err := copyPaced(&sink, bytes.NewReader(payload), newPacer(-1)); err != nil {
		t.Fatalf("copyPaced: %v", err)
	}
	// The Unlimited tier must not pay for a limit that does not exist. Half a
	// megabyte at 1 Mbps would be four seconds; allow a very generous margin and
	// still catch an accidentally applied pacer.
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("unlimited transfer took %s, want well under 500ms: a pacer is active", elapsed)
	}
	if sink.Len() != len(payload) {
		t.Errorf("copied %d bytes, want %d", sink.Len(), len(payload))
	}
}

// The tier table advertises bandwidth; this proves a Free-tier session is
// actually held to it, through the real SOCKS5 path.
func TestFreeTierSessionIsPaced(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "pace.db"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	user, err := store.CreateUser("pu", "pp", "free")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.BandwidthMbps != 1 {
		t.Fatalf("free tier bandwidth = %d, want 1", user.BandwidthMbps)
	}

	// Origin: hands out a fixed payload and nothing else.
	payload := bytes.Repeat([]byte("y"), 256<<10)
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	defer origin.Close()
	go func() {
		for {
			conn, aerr := origin.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, len(payload))
				if _, rerr := io.ReadFull(c, buf); rerr != nil {
					return
				}
				c.Write(payload)
			}(conn)
		}
	}()

	cfg := DefaultConfig()
	cfg.AuthEnabled = true
	cfg.Username = "pu"
	cfg.Password = "pp"
	cfg.AdminEnabled = false
	cfg.SecurityHeadersEnabled = false
	cfg.RateLimitEnabled = false

	proxy := NewProxyServer(cfg)
	proxy.store = store

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go proxy.handleClient(conn, "")
		}
	}()

	host, portStr, _ := net.SplitHostPort(origin.Addr().String())
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("origin port %q: %v", portStr, err)
	}
	port := uint16(port64)

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	if err := socks5ConnectAndAuth(t, client, "pu", "pp", host, port); err != nil {
		t.Fatalf("socks5 handshake: %v", err)
	}
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	got := make([]byte, len(payload))
	start := time.Now()
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("read through proxy: %v", err)
	}
	elapsed := time.Since(start)

	if !bytes.Equal(got, payload) {
		t.Fatal("payload changed in transit")
	}
	if elapsed < 900*time.Millisecond {
		t.Errorf("free tier moved 256 KiB in %s: BandwidthMbps is still not enforced", elapsed)
	}
}

// socks5ConnectAndAuth performs greeting, username/password auth and CONNECT.
// Written out rather than reusing the e2e helper because that one assumes
// no-auth and lives in a different test file's style.
func socks5ConnectAndAuth(t *testing.T, conn net.Conn, user, pass, host string, port uint16) error {
	t.Helper()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return err
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		return err
	}
	if sel[1] != 0x02 {
		return errAuthNotOffered
	}
	if _, err := conn.Write([]byte{0x01, byte(len(user))}); err != nil {
		return err
	}
	if _, err := conn.Write([]byte(user)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{byte(len(pass))}); err != nil {
		return err
	}
	if _, err := conn.Write([]byte(pass)); err != nil {
		return err
	}
	status := make([]byte, 2)
	if _, err := io.ReadFull(conn, status); err != nil {
		return err
	}
	if status[1] != 0x00 {
		return errAuthRejected
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[1] != 0x00 {
		return errConnectRefused
	}
	switch head[3] {
	case 0x01:
		_, err := io.ReadFull(conn, make([]byte, 6))
		return err
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return err
		}
		_, err := io.ReadFull(conn, make([]byte, int(l[0])+2))
		return err
	case 0x04:
		_, err := io.ReadFull(conn, make([]byte, 18))
		return err
	default:
		return errBadAddrType
	}
}

var (
	errAuthNotOffered = errorString("server did not offer username/password auth")
	errAuthRejected   = errorString("server rejected the credentials")
	errConnectRefused = errorString("server refused the CONNECT")
	errBadAddrType    = errorString("server replied with an unknown bound address type")
)

type errorString string

func (e errorString) Error() string { return string(e) }

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func TestPacerHonoursSmallerLimits(t *testing.T) {
	// 4 Mbps over 512 KiB is ~1s, against a burst of 512 KiB, so the floor sits
	// just under the non-burst transfer time. This catches a pacer that only
	// ever applies its ceiling once.
	p := newPacer(4)
	if p == nil {
		t.Fatal("newPacer(4) returned nil, want a pacer")
	}
	if p.bytesPerSec != 512*1024 {
		t.Errorf("bytesPerSec = %v, want 512KiB/s for 4 Mbps", p.bytesPerSec)
	}

	start := time.Now()
	payload := bytes.Repeat([]byte("z"), 1<<20) // 1 MiB
	var sink bytes.Buffer
	if _, err := copyPaced(&sink, bytes.NewReader(payload), p); err != nil {
		t.Fatalf("copyPaced: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 900*time.Millisecond {
		t.Errorf("1 MiB at 4 Mbps took %s, want at least ~900ms", elapsed)
	}
}

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ─── Key parsing ────────────────────────────────────────────────────────────

// The x25519 output is parsed by key name because the label has changed across
// xray releases. Both real spellings are pinned here so an upgrade cannot
// silently swap the server's public key for its private one.
func TestParseX25519LabelSpellings(t *testing.T) {
	tests := []struct {
		name     string
		out      string
		wantPriv string
		wantPub  string
	}{
		{
			name:     "current release",
			out:      "PrivateKey: eEkaDs1WCDOzuM6CU1GCA0ibZ779qdhSQDxJx2q2gWo\nPassword (PublicKey): lyrTBHs2LI5b20khZJhfxrsBfxwBKU0guoAW0vrQ62s\nHash32: 6DGNmVdKFxVnlSCNuWy_Le29fbKe-3LO0KZnQPrXkQI\n",
			wantPriv: "eEkaDs1WCDOzuM6CU1GCA0ibZ779qdhSQDxJx2q2gWo",
			wantPub:  "lyrTBHs2LI5b20khZJhfxrsBfxwBKU0guoAW0vrQ62s",
		},
		{
			name:     "older release",
			out:      "Private key: abc\nPublic key: def\n",
			wantPriv: "abc",
			wantPub:  "def",
		},
		{
			name:     "missing public key",
			out:      "PrivateKey: abc\n",
			wantPriv: "abc",
			wantPub:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv, pub := parseX25519(tt.out)
			if priv != tt.wantPriv {
				t.Errorf("private key = %q, want %q", priv, tt.wantPriv)
			}
			if pub != tt.wantPub {
				t.Errorf("public key = %q, want %q", pub, tt.wantPub)
			}
		})
	}
}

// ─── Rendered configs ───────────────────────────────────────────────────────

func testRealityConfig() (Config, realityKeys) {
	cfg := DefaultConfig()
	cfg.ProxyPort = 1080
	cfg.Username = "pu"
	cfg.Password = "pp"
	cfg.RealityBind = "0.0.0.0:443"
	cfg.RealityDest = "www.example-camouflage.test:443"
	cfg.RealityServerNames = []string{"www.example-camouflage.test"}

	keys := realityKeys{
		PrivateKey: "test-private-key",
		PublicKey:  "test-public-key",
		ShortID:    "0123456789abcdef",
		ClientIDs:  []string{"0cd94710-7290-40da-857d-5f5a7670cd62"},
		ServerName: "www.example-camouflage.test",
	}
	return cfg, keys
}

// TestRenderRealityServerConfig pins the whole point of the feature: xray
// accepts the handshake and hands the session to this proxy's SOCKS5 port, so
// users, tiers and rate limits still apply behind REALITY.
func TestRenderRealityServerConfig(t *testing.T) {
	cfg, keys := testRealityConfig()

	data, err := renderRealityServerConfig(cfg, keys)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	var out realityServerConfig
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(out.Inbounds) != 1 {
		t.Fatalf("got %d inbounds, want 1", len(out.Inbounds))
	}
	in := out.Inbounds[0]
	if in.Protocol != "vless" {
		t.Errorf("protocol = %q, want vless", in.Protocol)
	}
	if in.Settings.Decryption != "none" {
		t.Errorf("decryption = %q, want none: REALITY provides the transport security", in.Settings.Decryption)
	}
	if len(in.Settings.Clients) != 1 || in.Settings.Clients[0].ID != keys.ClientIDs[0] {
		t.Errorf("clients = %+v, want the configured VLESS id", in.Settings.Clients)
	}
	if in.StreamSettings.Network != "raw" {
		t.Errorf("network = %q, want raw", in.StreamSettings.Network)
	}
	if in.StreamSettings.Security != "reality" {
		t.Errorf("security = %q, want reality", in.StreamSettings.Security)
	}
	if in.StreamSettings.RealitySettings.PrivateKey != keys.PrivateKey {
		t.Error("private key missing from realitySettings")
	}
	if len(in.StreamSettings.RealitySettings.ShortIds) != 1 || in.StreamSettings.RealitySettings.ShortIds[0] != keys.ShortID {
		t.Errorf("shortIds = %v, want %v", in.StreamSettings.RealitySettings.ShortIds, keys.ShortID)
	}
	if in.StreamSettings.RealitySettings.Dest != cfg.RealityDest {
		t.Errorf("dest = %q, want %q", in.StreamSettings.RealitySettings.Dest, cfg.RealityDest)
	}

	var socksOut *realityOutbound
	for i := range out.Outbounds {
		if out.Outbounds[i].Tag == realitySocksTag {
			socksOut = &out.Outbounds[i]
		}
	}
	if socksOut == nil || socksOut.Settings == nil || len(socksOut.Settings.Servers) != 1 {
		t.Fatalf("no socks outbound pointing back at this proxy: %+v", out.Outbounds)
	}
	srv := socksOut.Settings.Servers[0]
	if srv.Address != "127.0.0.1" || srv.Port != cfg.ProxyPort {
		t.Errorf("socks outbound = %s:%d, want 127.0.0.1:%d", srv.Address, srv.Port, cfg.ProxyPort)
	}
	if len(srv.Users) != 1 || srv.Users[0].User != cfg.Username || srv.Users[0].Pass != cfg.Password {
		t.Errorf("socks outbound credentials = %+v, want the proxy credentials", srv.Users)
	}

	if len(out.Routing.Rules) != 1 {
		t.Fatalf("got %d routing rules, want 1", len(out.Routing.Rules))
	}
	rule := out.Routing.Rules[0]
	if rule.OutboundTag != realitySocksTag || len(rule.InboundTag) != 1 || rule.InboundTag[0] != realityInboundTag {
		t.Errorf("routing rule = %+v, want %s -> %s", rule, realityInboundTag, realitySocksTag)
	}
}

// An unauthenticated proxy means no users block, and xray is the only local
// client, so the socks outbound must stay usable rather than break startup.
func TestRenderRealityServerConfigWithoutProxyAuth(t *testing.T) {
	cfg, keys := testRealityConfig()
	cfg.AuthEnabled = false
	cfg.Username = ""
	cfg.Password = ""

	data, err := renderRealityServerConfig(cfg, keys)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(string(data), `"users"`) {
		t.Errorf("config carries proxy credentials although auth is off:\n%s", data)
	}
}

// The camouflage host is what a prober sees, so serverNames must cover it even
// when the operator configured no SNI list at all.
func TestRenderRealityServerNamesDefaultToDest(t *testing.T) {
	cfg, keys := testRealityConfig()
	cfg.RealityServerNames = nil
	keys.ServerName = ""

	data, err := renderRealityServerConfig(cfg, keys)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var out realityServerConfig
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	names := out.Inbounds[0].StreamSettings.RealitySettings.ServerNames
	if len(names) != 1 || names[0] != "www.example-camouflage.test" {
		t.Errorf("serverNames = %v, want the dest host", names)
	}
}

func TestRenderRealityClientConfig(t *testing.T) {
	_, keys := testRealityConfig()

	data, err := renderRealityClientConfig("203.0.113.7", 443, "127.0.0.1", 1081, keys)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	var out realityClientConfig
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(out.Inbounds) != 1 || out.Inbounds[0].Protocol != "socks" {
		t.Fatalf("client config needs a local socks inbound, got %+v", out.Inbounds)
	}
	if out.Inbounds[0].Listen != "127.0.0.1" || out.Inbounds[0].Port != 1081 {
		t.Errorf("socks inbound = %s:%d, want 127.0.0.1:1081", out.Inbounds[0].Listen, out.Inbounds[0].Port)
	}
	// UDP is the whole point for Telegram and QUIC. A generated config that
	// leaves it off silently degrades the client to TCP-only.
	if !out.Inbounds[0].Settings.UDP {
		t.Error("generated socks inbound must accept UDP")
	}

	if len(out.Outbounds) != 1 || out.Outbounds[0].Protocol != "vless" {
		t.Fatalf("client config needs a vless outbound, got %+v", out.Outbounds)
	}
	vnext := out.Outbounds[0].Settings.Vnext
	if len(vnext) != 1 || vnext[0].Address != "203.0.113.7" || vnext[0].Port != 443 {
		t.Fatalf("vnext = %+v, want 203.0.113.7:443", vnext)
	}
	if len(vnext[0].Users) != 1 || vnext[0].Users[0].ID != keys.ClientIDs[0] {
		t.Errorf("vless user = %+v, want the generated id", vnext[0].Users)
	}
	if vnext[0].Users[0].Encryption != "none" {
		t.Errorf("encryption = %q, want none", vnext[0].Users[0].Encryption)
	}

	rs := out.Outbounds[0].StreamSettings.RealitySettings
	if rs.PublicKey != keys.PublicKey {
		t.Error("client realitySettings must carry the public key, not the private one")
	}
	if rs.ShortId != keys.ShortID {
		t.Errorf("shortId = %q, want %q", rs.ShortId, keys.ShortID)
	}
	if rs.ServerName != keys.ServerName {
		t.Errorf("serverName = %q, want %q", rs.ServerName, keys.ServerName)
	}
	if rs.Fingerprint != "chrome" {
		t.Errorf("fingerprint = %q, want chrome", rs.Fingerprint)
	}

	// A client config with no id cannot authenticate, so it must fail loudly
	// rather than produce a file that connects and drops.
	if _, err := renderRealityClientConfig("203.0.113.7", 443, "127.0.0.1", 1081, realityKeys{}); err == nil {
		t.Error("rendering a client config without a VLESS id should fail")
	}
}

func TestSplitHostPortRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "443", "0.0.0.0", "0.0.0.0:notaport", "0.0.0.0:0", "0.0.0.0:70000"} {
		if _, _, err := splitHostPort(bad); err == nil {
			t.Errorf("splitHostPort(%q) accepted a value that is not host:port", bad)
		}
	}
	host, port, err := splitHostPort("127.0.0.1:8443")
	if err != nil || host != "127.0.0.1" || port != 8443 {
		t.Errorf("splitHostPort = %q, %d, %v; want 127.0.0.1, 8443, nil", host, port, err)
	}
}

// ─── Key resolution ─────────────────────────────────────────────────────────

// fakeXray is a stand-in for the real binary, so key resolution is testable on
// a machine that has no xray installed.
func fakeXray(t *testing.T, privKey, pubKey string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xray")
	script := fmt.Sprintf(`#!/bin/sh
case "$1" in
x25519)
  echo "PrivateKey: %s"
  echo "Password (PublicKey): %s"
  ;;
uuid)
  echo "0cd94710-7290-40da-857d-5f5a7670cd62"
  ;;
*)
  echo "unsupported" >&2; exit 1
  ;;
esac
`, privKey, pubKey)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake xray: %v", err)
	}
	return path
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "reality.db"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// Generated material must be persisted, because a key that changes on restart
// silently breaks every client profile the operator has already imported.
func TestResolveRealityKeysPersistsGeneratedValues(t *testing.T) {
	bin := fakeXray(t, "generated-private", "generated-public")
	store := newTestStore(t)

	cfg := DefaultConfig()
	cfg.RealityXrayBin = bin
	cfg.Username = "pu"
	cfg.Password = "pp"

	keys, err := resolveRealityKeys(cfg, nil, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if keys.PrivateKey != "generated-private" || keys.PublicKey != "generated-public" {
		t.Errorf("keypair = %q/%q, want the generated pair", keys.PrivateKey, keys.PublicKey)
	}
	if len(keys.ClientIDs) != 1 || keys.ClientIDs[0] != "0cd94710-7290-40da-857d-5f5a7670cd62" {
		t.Errorf("client ids = %v, want the uuid xray generated", keys.ClientIDs)
	}
	if keys.ShortID == "" {
		t.Error("short id was not generated")
	}
	if keys.ServerName != "www.lovelive-anime.jp" {
		t.Errorf("server name = %q, want the dest host", keys.ServerName)
	}

	saved := store.LoadConfig()
	if saved[dbRealityPrivateKey] != keys.PrivateKey {
		t.Errorf("private key not persisted: %v", saved)
	}
	if saved[dbRealityShortID] != keys.ShortID {
		t.Errorf("short id not persisted: %v", saved)
	}
	if saved[dbRealityClientIDs] != strings.Join(keys.ClientIDs, ",") {
		t.Errorf("client ids not persisted: %v", saved)
	}

	// A restart must reuse the persisted pair rather than rotate it.
	again, err := resolveRealityKeys(cfg, saved, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("resolve again: %v", err)
	}
	if again.PrivateKey != keys.PrivateKey || again.ShortID != keys.ShortID {
		t.Errorf("restart rotated the key material: %q/%q", again.PrivateKey, again.ShortID)
	}
}

func TestResolveRealityKeysPrefersOperatorValues(t *testing.T) {
	bin := fakeXray(t, "generated-private", "derived-public")
	cfg := DefaultConfig()
	cfg.RealityXrayBin = bin
	cfg.RealityPrivateKey = "operator-private"
	cfg.RealityShortIDs = []string{"deadbeef", "cafebabe"}
	cfg.RealityClientIDs = []string{"11111111-2222-3333-4444-555555555555"}

	keys, err := resolveRealityKeys(cfg, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if keys.PrivateKey != "operator-private" {
		t.Errorf("private key = %q, want the operator's", keys.PrivateKey)
	}
	if keys.PublicKey != "derived-public" {
		t.Errorf("public key = %q, want the value derived from the private key", keys.PublicKey)
	}
	if keys.ShortID != "deadbeef" {
		t.Errorf("short id = %q, want the first configured one", keys.ShortID)
	}
	if len(keys.ClientIDs) != 1 || keys.ClientIDs[0] != cfg.RealityClientIDs[0] {
		t.Errorf("client ids = %v, want the configured ones", keys.ClientIDs)
	}
}

// Enabling REALITY without xray installed must fail the way the tunnel refuses
// to start without a token: loudly, at startup.
func TestRealityRefusesWithoutXrayBinary(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RealityEnabled = true
	cfg.RealityXrayBin = filepath.Join(t.TempDir(), "definitely-not-here")

	_, err := startRealityForServer(cfg, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("starting REALITY without the xray binary should fail")
	}
	if !strings.Contains(err.Error(), "xray") {
		t.Errorf("error %q should name the missing binary", err)
	}
}

// A config xray rejects must not leave a process running that looks healthy.
func TestStartRealityRejectsInvalidConfig(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "xray")
	script := "#!/bin/sh\nif [ \"$4\" = \"--test\" ]; then echo \"bad reality key\" >&2; exit 1; fi\nsleep 60\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake xray: %v", err)
	}

	cfg, keys := testRealityConfig()
	cfg.RealityXrayBin = bin

	if _, err := startReality(cfg, keys, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("startReality accepted a config its own binary rejects")
	}
}

// ─── End to end, against the real xray ──────────────────────────────────────

// freePort reserves and releases an ephemeral port. Xray binds a configured
// port, so the test has to know it before the config is written.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func requireXray(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("xray")
	if err != nil {
		t.Skip("xray is not installed; skipping the REALITY end-to-end test")
	}
	return bin
}

// TestRealityEndToEnd runs the whole chain: this proxy's SOCKS5 port, xray
// terminating REALITY in front of it, and a second xray acting as the client.
// Anything that matters about the feature -- that REALITY sessions still hit
// the SOCKS5 pipeline and are accounted for -- fails here.
//
// REALITY relays the handshake to a real TLS 1.3 site to borrow its
// certificate, so this needs network access as well as the binary.
func TestRealityEndToEnd(t *testing.T) {
	bin := requireXray(t)

	destHost, destPort, err := splitHostPort(defaultRealityDest)
	if err != nil {
		t.Fatalf("split dest: %v", err)
	}
	if conn, derr := tls.Dial("tcp", net.JoinHostPort(destHost, fmt.Sprint(destPort)), &tls.Config{
		ServerName: destHost,
	}); derr != nil {
		t.Skipf("camouflage site %s is unreachable: %v", defaultRealityDest, derr)
	} else {
		conn.Close()
	}

	// The origin the client ultimately reaches.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "reality-e2e-ok")
	}))
	defer origin.Close()

	// This proxy, on its own SOCKS5 port, exactly as a VPS would run it.
	proxyCfg := DefaultConfig()
	proxyCfg.AuthEnabled = true
	proxyCfg.Username = "pu"
	proxyCfg.Password = "pp"
	proxyCfg.AdminEnabled = false
	proxyCfg.SecurityHeadersEnabled = false
	proxyCfg.RateLimitEnabled = false
	proxyCfg.ProxyPort = freePort(t)
	proxyCfg.AdminPort = freePort(t)
	proxyCfg.MetricsPort = freePort(t)

	server := NewProxyServer(proxyCfg)
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", proxyCfg.ProxyPort))
	if err != nil {
		t.Fatalf("listen socks: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go server.handleClient(conn, "")
		}
	}()

	realityPort := freePort(t)
	clientPort := freePort(t)

	cfg := proxyCfg
	cfg.RealityXrayBin = bin
	cfg.RealityEnabled = true
	cfg.RealityBind = fmt.Sprintf("127.0.0.1:%d", realityPort)
	cfg.RealityDest = defaultRealityDest
	cfg.RealityPublicHost = "127.0.0.1"

	keys, err := resolveRealityKeys(cfg, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("resolve keys: %v", err)
	}

	runner, err := startReality(cfg, keys, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("start reality: %v", err)
	}
	defer runner.Stop()

	clientData, err := renderRealityClientConfig("127.0.0.1", realityPort, "127.0.0.1", clientPort, keys)
	if err != nil {
		t.Fatalf("render client: %v", err)
	}
	clientFile := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(clientFile, clientData, 0o600); err != nil {
		t.Fatalf("write client config: %v", err)
	}

	clientCmd := exec.Command(bin, "run", "-c", clientFile)
	clientCmd.Stdout, clientCmd.Stderr = io.Discard, io.Discard
	if err := clientCmd.Start(); err != nil {
		t.Fatalf("start client: %v", err)
	}
	defer func() {
		clientCmd.Process.Kill()
		clientCmd.Wait()
	}()

	// Wait for the client's socks port before sending anything at it.
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, derr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort), 200*time.Millisecond)
		if derr == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("client socks port never opened: %v", derr)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// The request leaves as ordinary HTTP, so socks5:// in the transport is all
	// the client-side plumbing this test needs.
	proxyURL, err := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", clientPort))
	if err != nil {
		t.Fatalf("parse socks url: %v", err)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   20 * time.Second,
	}

	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("request through REALITY: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "reality-e2e-ok" {
		t.Fatalf("body = %q, want the origin's response", body)
	}

	// The session went through handleClient, so the counters must have moved.
	if server.totalConns.Load() == 0 {
		t.Error("the REALITY session never reached the SOCKS5 pipeline")
	}
}

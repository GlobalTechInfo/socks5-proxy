package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"context"

	"github.com/coder/websocket"
)

// ─── Helpers ───────────────────────────────────────────────────────────────

// startTestServer boots a single-port mux on an ephemeral port and returns its
// address. The store is left nil: the SOCKS5 path tolerates it (database-backed
// features are skipped) and it keeps the test hermetic.
func startTestServer(t *testing.T, mutate func(*Config)) string {
	t.Helper()

	cfg := DefaultConfig()
	cfg.SinglePort = 0 // set below from the listener we hand out
	cfg.AuthEnabled = false
	cfg.AdminEnabled = false
	cfg.SecurityHeadersEnabled = false
	cfg.RateLimitEnabled = false
	cfg.TunnelEnabled = true
	cfg.TunnelToken = "test-token"
	cfg.TunnelPadding = 0
	if mutate != nil {
		mutate(&cfg)
	}

	// Bind :0 ourselves so the test knows the port before serving starts.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close reserved listener: %v", err)
	}

	srv := NewProxyServer(cfg)
	// serveMultiplex binds its own listener on addr.
	if err := srv.serveMultiplex(addr); err != nil {
		t.Fatalf("serveMultiplex: %v", err)
	}
	t.Cleanup(func() { close(srv.shutdownCh) })

	// Wait for the listener to accept.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server never became reachable on %s", addr)
	return ""
}

// ─── Test 1: SOCKS5 and HTTP share one port ────────────────────────────────

// TestMuxSOCKS5AndHTTPOnSamePort is the core assertion of the whole feature:
// one TCP port serves both a raw SOCKS5 greeting and an HTTP request.
func TestMuxSOCKS5AndHTTPOnSamePort(t *testing.T) {
	addr := startTestServer(t, nil)

	t.Run("socks5", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))

		// RFC 1928 method negotiation: VER=5, NMETHODS=1, "no auth"
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			t.Fatalf("write greeting: %v", err)
		}
		reply := make([]byte, 2)
		if _, err := io.ReadFull(conn, reply); err != nil {
			t.Fatalf("read method reply: %v", err)
		}
		if reply[0] != 0x05 || reply[1] != 0x00 {
			t.Fatalf("got method reply %v, want [5 0]", reply)
		}
	})

	t.Run("http", func(t *testing.T) {
		resp, err := http.Get("http://" + addr + "/health")
		if err != nil {
			t.Fatalf("GET /health: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /health = %d, want 200", resp.StatusCode)
		}
		var body map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode /health: %v", err)
		}
		if body["status"] != "ok" {
			t.Fatalf("/health status = %q, want \"ok\"", body["status"])
		}
	})
}

// ─── Test 2: metrics path falls through to the metrics mux ─────────────────

// The admin and metrics muxes both register "/" and "/chart.min.js". The merge
// must let metrics-only paths through to the second handler instead of panicking
// on a duplicate pattern.
func TestMuxMetricsPathReachable(t *testing.T) {
	addr := startTestServer(t, nil)

	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics: %v", err)
	}
	if !strings.Contains(string(body), "SOCKS5 Proxy Metrics") {
		t.Fatalf("/metrics did not serve the metrics dashboard")
	}
}

// ─── Test 3: TLS on the same port ─────────────────────────────────────────

// A TLS ClientHello must be recognised, terminated, and then re-sniffed so the
// decrypted stream still dispatches to HTTP.
func TestMuxTLSThenHTTP(t *testing.T) {
	addr := startTestServer(t, nil)

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := fmt.Fprint(conn, "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(newBufReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("TLS GET /health = %d, want 200", resp.StatusCode)
	}
}

func newBufReader(r io.Reader) *bufio.Reader {
	return bufio.NewReaderSize(r, 4096)
}

// ─── Test 4: TLS then SOCKS5 on the same port ─────────────────────────────

// TLS-wrapped SOCKS5 is the "TLS on 1080" case: the decrypted first byte must
// still be recognised as a SOCKS5 greeting.
func TestMuxTLSThenSOCKS5(t *testing.T) {
	addr := startTestServer(t, nil)

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("got %v, want [5 0]", reply)
	}
}

// ─── Test 5: tunnel round-trip ────────────────────────────────────────────

// A real SOCKS5 session established through the WebSocket tunnel, proving the
// tunnel carries traffic and that handleClient works over a non-TCP conn.
func TestTunnelRoundTrip(t *testing.T) {
	addr := startTestServer(t, func(c *Config) {
		c.TunnelPath = defaultTunnelPath
	})
	wsURL := "ws://" + addr + defaultTunnelPath + "?token=test-token"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wsConn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	defer wsConn.CloseNow()

	conn := websocket.NetConn(ctx, wsConn, websocket.MessageBinary)
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("got %v, want [5 0]", reply)
	}
}

// ─── Test 6: tunnel auth ──────────────────────────────────────────────────

func TestTunnelRequiresToken(t *testing.T) {
	addr := startTestServer(t, nil)

	t.Run("missing", func(t *testing.T) {
		resp, err := http.Get("http://" + addr + defaultTunnelPath)
		if err != nil {
			t.Fatalf("GET tunnel: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("no-token GET = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("wrong", func(t *testing.T) {
		resp, err := http.Get("http://" + addr + defaultTunnelPath + "?token=wrong")
		if err != nil {
			t.Fatalf("GET tunnel: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("bad-token GET = %d, want 401", resp.StatusCode)
		}
	})
}

// ─── Test 7: padding conn ─────────────────────────────────────────────────

// Padding must preserve the exact byte stream (a proxy that alters payload is
// broken) while emitting writes at a uniform size.
// Padding must be transparent: whatever goes in comes out byte-identical, while
// every emitted message is rounded up to the pad size.
func TestPadConnRoundTrip(t *testing.T) {
	for _, size := range []int{1, 2, 17, 255, 256, 257, 1024, 70 * 1024} {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i % 251)
			}

			// A real TCP pair rather than net.Pipe: the socket kernel buffers, so
			// the test does not deadlock on net.Pipe's fully synchronous writes
			// while also exercising the real framing path.
			writer, reader := socketPair(t)

			// Both ends wrap, exactly as server and client do in production:
			// padding is applied by each side and stripped by the other.
			pc := newPadConn(reader, 256)
			wc := newPadConn(writer, 256)

			writeErr := make(chan error, 1)
			go func() {
				_, err := wc.Write(payload)
				writeErr <- err
			}()

			got := make([]byte, 0, len(payload))
			buf := make([]byte, 4096)
			reader.SetReadDeadline(time.Now().Add(10 * time.Second))
			for len(got) < len(payload) {
				n, err := pc.Read(buf)
				got = append(got, buf[:n]...)
				if err != nil {
					t.Fatalf("read: %v", err)
				}
			}
			if err := <-writeErr; err != nil {
				t.Fatalf("write: %v", err)
			}

			if len(got) != len(payload) {
				t.Fatalf("read %d bytes, want %d", len(got), len(payload))
			}
			for i := range payload {
				if got[i] != payload[i] {
					t.Fatalf("byte %d = %d, want %d", i, got[i], payload[i])
				}
			}
		})
	}
}

// A small write must be emitted immediately rather than buffered until the pad
// boundary fills: SOCKS5 control replies are 2 bytes and would otherwise stall
// the handshake forever.
func TestPadConnDoesNotBufferSmallWrites(t *testing.T) {
	w, r := socketPair(t)
	pc := newPadConn(w, 256)

	writeErr := make(chan error, 1)
	go func() {
		_, err := pc.Write([]byte{0x05, 0x00})
		writeErr <- err
	}()

	// The peer must see the 2 payload bytes promptly, without waiting for the
	// pad boundary to fill.
	r.SetReadDeadline(time.Now().Add(3 * time.Second))
	frame := make([]byte, 256)
	if _, err := io.ReadFull(r, frame); err != nil {
		t.Fatalf("peer read: %v", err)
	}
	if frame[0] != 0x00 || frame[1] != 0x02 {
		t.Fatalf("frame header = %v, want [0 2]", frame[:2])
	}
	if frame[2] != 0x05 || frame[3] != 0x00 {
		t.Fatalf("frame payload = %v, want [5 0]", frame[2:4])
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write: %v", err)
	}
}

// padding=0 or 1 must pass traffic through completely untouched.
func TestPadConnDisabled(t *testing.T) {
	a, _ := net.Pipe()
	defer a.Close()
	if c := newPadConn(a, 0); c != net.Conn(a) {
		t.Fatal("padding 0 should return the conn unchanged")
	}
	if c := newPadConn(a, 1); c != net.Conn(a) {
		t.Fatal("padding 1 should return the conn unchanged")
	}
}

// ─── Test 8: merge handler picks the right mux ────────────────────────────

func TestMergeHandlersOrder(t *testing.T) {
	notFound := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	found := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	merged := mergeHandlers(notFound, found)

	rec := httptest.NewRecorder()
	merged.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("fallthrough code = %d, want 418", rec.Code)
	}

	// When the first handler matches, it must win and never consult the second.
	first := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	rec = httptest.NewRecorder()
	mergeHandlers(first, notFound).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("first-match code = %d, want 200", rec.Code)
	}
}

// ─── Test 9: remoteIP handles non-TCP conns ──────────────────────────────

// The tunnel produces conns whose RemoteAddr is not a *net.TCPAddr; the old
// type assertion would have panicked here.
func TestRemoteIPNonTCP(t *testing.T) {
	c := &replayConn{Conn: fakeConn{}}
	if got := remoteIP(c); got == "" {
		t.Fatal("remoteIP returned empty string")
	}

	if got := remoteIP(nil); got != "unknown" {
		t.Fatalf("remoteIP(nil) = %q, want \"unknown\"", got)
	}
}

type fakeConn struct{ net.Conn }

func (fakeConn) RemoteAddr() net.Addr { return fakeAddr{} }
func (fakeConn) LocalAddr() net.Addr  { return fakeAddr{} }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "websocket/unknown-addr" }
func (fakeAddr) String() string  { return "websocket:1234" }

// ─── Test 10: TLS cert endpoint ───────────────────────────────────────────

func TestTLSCertEndpoint(t *testing.T) {
	addr := startTestServer(t, nil)

	resp, err := http.Get("http://" + addr + "/tls-cert")
	if err != nil {
		t.Fatalf("GET /tls-cert: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /tls-cert = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(body), "BEGIN CERTIFICATE") {
		t.Fatalf("/tls-cert did not return PEM:\n%s", body)
	}
}

// ─── Test 11: auth layering on the merged port ────────────────────────────

// Regression: adminHandler() wraps its mux in basicAuth, so on the merged port
// a /metrics request hit the 401 before the merge fallback could see a 404.
// Metrics and tunnel paths must stay reachable without admin credentials.
func TestMergedPortPublicPathsNotAuthGated(t *testing.T) {
	addr := startTestServer(t, func(c *Config) {
		c.AdminEnabled = true
		c.AdminUser = "admin"
		c.AdminPass = "adminpw"
		c.RateLimitEnabled = true
		c.RateLimitRPS = 1000
	})

	for _, path := range []string{"/health", "/metrics", "/tls-cert"} {
		resp, err := http.Get("http://" + addr + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			t.Errorf("GET %s = 401, want reachable without admin creds", path)
		}
	}

	// The tunnel path must also skip admin auth. It carries its own token, so
	// assert with a valid token: if admin auth were still gating the path, this
	// would 401 even though the token is correct.
	resp, err := http.Get("http://" + addr + defaultTunnelPath + "?token=test-token")
	if err != nil {
		t.Fatalf("GET tunnel: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Error("tunnel with valid token = 401: admin auth is gating the tunnel path")
	}

	// A tunnel handshake must never be billed against the admin budget, so give
	// the limiter a separate, generous cap via a dedicated probe.
	resp2, err := http.Get("http://" + addr + defaultTunnelPath + "?token=test-token")
	if err != nil {
		t.Fatalf("GET tunnel: %v", err)
	}
	resp2.Body.Close()

	// An admin-only route must still require credentials.
	adminResp, err := http.Get("http://" + addr + "/api/users")
	if err != nil {
		t.Fatalf("GET /api/users: %v", err)
	}
	defer adminResp.Body.Close()
	if adminResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/users = %d, want 401", adminResp.StatusCode)
	}
}

// ─── Test 12: config env routing ──────────────────────────────────────────

// PORT must switch the server into single-port mode (Render/Koyeb/Heroku inject
// it); SINGLE_PORT is the explicit override for Northflank, which does not.
func TestSinglePortEnvDetection(t *testing.T) {
	cfgFile := writeTempConfig(t, `{"proxy_port":1080}`)

	t.Run("PORT", func(t *testing.T) {
		t.Setenv("PORT", "8080")
		t.Setenv("SINGLE_PORT", "")
		cfg, err := LoadConfig(cfgFile)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if cfg.SinglePort != 8080 {
			t.Fatalf("SinglePort = %d, want 8080", cfg.SinglePort)
		}
	})

	t.Run("SINGLE_PORT wins", func(t *testing.T) {
		t.Setenv("PORT", "8080")
		t.Setenv("SINGLE_PORT", "9090")
		cfg, err := LoadConfig(cfgFile)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if cfg.SinglePort != 9090 {
			t.Fatalf("SinglePort = %d, want 9090", cfg.SinglePort)
		}
	})

	t.Run("unset keeps multi-port", func(t *testing.T) {
		t.Setenv("PORT", "")
		t.Setenv("SINGLE_PORT", "")
		cfg, err := LoadConfig(cfgFile)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if cfg.SinglePort != 0 {
			t.Fatalf("SinglePort = %d, want 0 (multi-port)", cfg.SinglePort)
		}
	})
}

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// socketPair returns two connected TCP conns. The kernel buffers, so large
// framed writes do not deadlock against a concurrent reader the way net.Pipe's
// fully synchronous writes do.
func socketPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	t.Cleanup(func() {
		client.Close()
		r.c.Close()
	})
	return client, r.c
}

// listenerPair returns a listener and the address to dial, so a caller can
// exercise the accept loop the way runClient does.
func listenerPair(t *testing.T) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, ln.Addr().String()
}

// ─── Test 13: real client against real server ─────────────────────────────

// Exercises the full path the way a user does: a local SOCKS5 client connects to
// the tunnel client's listener, the tunnel client dials the server over a real
// WebSocket, and a genuine SOCKS5 CONNECT is proxied to a live HTTP server.
// Both ends apply padding, which is where a framing asymmetry would show up.
func TestClientSessionEndToEnd(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello-through-proxy")
	}))
	defer origin.Close()

	addr := startTestServer(t, func(c *Config) {
		c.AuthEnabled = false
		c.TunnelPadding = 256
	})
	wsURL := "ws://" + addr + defaultTunnelPath + "?token=test-token"

	// Stand in for runClient's listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		local, err := ln.Accept()
		if err != nil {
			return
		}
		clientSession(local, wsURL, "test-token", false, keepaliveInterval, 0)
	}()

	app, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial client: %v", err)
	}
	defer app.Close()
	app.SetDeadline(time.Now().Add(20 * time.Second))

	// Full SOCKS5 CONNECT through the tunnel to the origin server.
	conn, err := socks5ConnectApp(t, app, origin.Listener.Addr().String())
	if err != nil {
		t.Fatalf("socks5 connect through tunnel: %v", err)
	}
	defer conn.Close()

	fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n")
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(string(body), "hello-through-proxy") {
		t.Fatalf("response through tunnel = %q, want it to contain the origin body", body)
	}
}

// socks5ConnectApp performs a no-auth SOCKS5 CONNECT over an existing conn.
func socks5ConnectApp(t *testing.T, c net.Conn, target string) (net.Conn, error) {
	t.Helper()
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, fmt.Errorf("write greeting: %w", err)
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c, rep); err != nil {
		return nil, fmt.Errorf("read method reply: %w", err)
	}
	if rep[1] != 0x00 {
		return nil, fmt.Errorf("auth method %v", rep)
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	if len(host) > 255 {
		return nil, fmt.Errorf("hostname too long")
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return nil, fmt.Errorf("write connect req: %w", err)
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return nil, fmt.Errorf("read connect reply: %w", err)
	}
	if hdr[1] != 0x00 {
		return nil, fmt.Errorf("connect reply code %d", hdr[1])
	}
	// The reply is 4 bytes of header plus the bound address, whose form is
	// declared by ATYP. sendReply always emits 0x01/0.0.0.0:0, so IPv4 is the
	// only case this helper needs to decode.
	switch hdr[3] {
	case addrTypeIPv4:
		if _, err := io.ReadFull(c, make([]byte, 6)); err != nil {
			return nil, fmt.Errorf("read ipv4 addr+port: %w", err)
		}
	case addrTypeFQDN:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return nil, fmt.Errorf("read domain len: %w", err)
		}
		if _, err := io.ReadFull(c, make([]byte, int(l[0]))); err != nil {
			return nil, fmt.Errorf("read domain: %w", err)
		}
		if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
			return nil, fmt.Errorf("read domain port: %w", err)
		}
	case addrTypeIPv6:
		if _, err := io.ReadFull(c, make([]byte, 18)); err != nil {
			return nil, fmt.Errorf("read ipv6 addr+port: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown reply address type %d", hdr[3])
	}
	return c, nil
}

// ─── Test 14: remote URL normalisation ────────────────────────────────────

// Users paste the browser URL they were given, so http/https must be accepted
// and mapped to ws/wss, and a bare host must get the default tunnel path.
func TestParseRemoteURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"wss://host.example/api/v1/tunnel", "wss://host.example/api/v1/tunnel"},
		{"https://host.example/api/v1/tunnel", "wss://host.example/api/v1/tunnel"},
		{"ws://host.example/api/v1/tunnel", "ws://host.example/api/v1/tunnel"},
		{"http://host.example/api/v1/tunnel", "ws://host.example/api/v1/tunnel"},
		{"https://host.example", "wss://host.example" + defaultTunnelPath},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			u, err := parseRemoteURL(c.in)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if u.String() != c.want {
				t.Fatalf("got %q, want %q", u, c.want)
			}
		})
	}

	for _, bad := range []string{"ftp://host/x", "://nope", "not a url at all::"} {
		if _, err := parseRemoteURL(bad); err == nil {
			t.Errorf("parseRemoteURL(%q) succeeded, want error", bad)
		}
	}
}

// ─── Test 15: HTTP CONNECT proxying ───────────────────────────────────────

// CONNECT makes the public URL usable with no local client: browsers, curl and
// most HTTP libraries already speak it, so they can point straight at the PaaS
// URL with the SOCKS5 credentials.
func TestConnectProxy(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello-through-connect")
	}))
	defer origin.Close()

	addr := startTestServer(t, func(c *Config) {
		c.AuthEnabled = true
		c.Username = "cuser"
		c.Password = "cpass"
	})

	t.Run("with auth", func(t *testing.T) {
		body := connectThrough(t, addr, origin.Listener.Addr().String(), "cuser", "cpass")
		if !strings.Contains(body, "hello-through-connect") {
			t.Fatalf("body = %q, want origin response", body)
		}
	})

	t.Run("without auth is rejected", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
			origin.Listener.Addr().String(), origin.Listener.Addr().String())
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("status = %d, want 407", resp.StatusCode)
		}
	})

	t.Run("wrong creds are rejected", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n\r\n",
			origin.Listener.Addr().String(), origin.Listener.Addr().String(),
			"Proxy-Authorization: Basic "+basicAuthValue("cuser", "nope"))
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("status = %d, want 407", resp.StatusCode)
		}
	})
}

func basicAuthValue(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

func connectThrough(t *testing.T, addr, target, user, pass string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		target, target, basicAuthValue(user, pass))

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT = %d, want 200", resp.StatusCode)
	}

	// The tunnel is now raw bytes; any buffered leftovers are part of it.
	if _, err := fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	inner, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read inner response: %v", err)
	}
	defer inner.Body.Close()
	body, err := io.ReadAll(inner.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}

// ─── Test 16: forward proxy for plain http:// targets ─────────────────────

// CONNECT covers https://; browsers send absolute-form GET for http://. Both
// halves must work, and neither may fall through to admin auth.
func TestForwardProxyPlainHTTP(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "path=%s", r.URL.Path)
	}))
	defer origin.Close()

	addr := startTestServer(t, func(c *Config) {
		c.AuthEnabled = true
		c.Username = "fuser"
		c.Password = "fpass"
	})
	originURL := "http://" + origin.Listener.Addr().String()

	t.Run("with auth", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))

		fmt.Fprintf(conn, "GET %s/probed HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\nConnection: close\r\n\r\n",
			originURL, origin.Listener.Addr().String(), basicAuthValue("fuser", "fpass"))

		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "path=/probed") {
			t.Fatalf("body = %q, want the origin body", body)
		}
	})

	t.Run("without auth is rejected", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "GET %s/x HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n", originURL)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("status = %d, want 407", resp.StatusCode)
		}
	})
}

// The dashboard must keep working on the same port: relative-path requests must
// not be mistaken for proxy traffic.
func TestDashboardStillWorksOnSharedPort(t *testing.T) {
	addr := startTestServer(t, func(c *Config) {
		c.AuthEnabled = true
		c.Username = "fuser"
		c.Password = "fpass"
	})
	resp, err := http.Get("http://" + addr + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /health = %d, want 200", resp.StatusCode)
	}
}

// ─── Test 17: single-port mode cannot collide with the SOCKS5 port ─────────

// PORT used to be copied into ProxyPort as well as SinglePort, so the mux and
// the raw listener both bound the same value and the process exited. That broke
// every PaaS deploy, where PORT is injected automatically.
func TestPortNoLongerSetsProxyPort(t *testing.T) {
	cfgFile := writeTempConfig(t, `{"proxy_port":1080}`)

	t.Setenv("PORT", "8080")
	t.Setenv("SINGLE_PORT", "")
	t.Setenv("PROXY_PORT", "")
	cfg, err := LoadConfig(cfgFile)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.SinglePort != 8080 {
		t.Fatalf("SinglePort = %d, want 8080", cfg.SinglePort)
	}
	if cfg.ProxyPort != 1080 {
		t.Fatalf("ProxyPort = %d, want 1080: PORT must not move the SOCKS5 port", cfg.ProxyPort)
	}
	if cfg.SinglePort == cfg.ProxyPort {
		t.Fatal("SinglePort and ProxyPort must not collide by default")
	}
}

// PROXY_PORT still works for moving the SOCKS5 port explicitly.
func TestProxyPortStillHonoured(t *testing.T) {
	cfgFile := writeTempConfig(t, `{"proxy_port":1080}`)
	t.Setenv("PORT", "8080")
	t.Setenv("PROXY_PORT", "9999")
	cfg, err := LoadConfig(cfgFile)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ProxyPort != 9999 {
		t.Fatalf("ProxyPort = %d, want 9999", cfg.ProxyPort)
	}
}

// ─── Test 18: TUNNEL_ENABLED=false really disables the tunnel ─────────────

// The handler used to check only for a token, so an operator who set
// TUNNEL_ENABLED=false but left a token behind still had a live tunnel.
func TestTunnelDisabledDespiteToken(t *testing.T) {
	addr := startTestServer(t, func(c *Config) {
		c.TunnelEnabled = false
		c.TunnelToken = "test-token"
	})

	for _, path := range []string{defaultTunnelPath, defaultTunnelPath + "?token=test-token"} {
		resp, err := http.Get("http://" + addr + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusSwitchingProtocols || resp.StatusCode == http.StatusOK {
			t.Errorf("GET %s = %d: tunnel reachable while disabled", path, resp.StatusCode)
		}
	}
}

// ─── Test 19: the HTTP proxy honours the IP allowlist ──────────────────────

// CONNECT and forward-proxy paths skipped isAllowedIP, so a blacklisted client
// could relay through the proxy around the operator's own access control.
func TestProxyPathsEnforceIPAllowlist(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "should not be reachable")
	}))
	defer origin.Close()

	addr := startTestServer(t, func(c *Config) {
		c.AuthEnabled = true
		c.Username = "auser"
		c.Password = "apass"
		c.Blacklist = []string{"127.0.0.1"}
	})

	t.Run("CONNECT blocked", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		target := origin.Listener.Addr().String()
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
			target, target, basicAuthValue("auser", "apass"))
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("CONNECT from blacklisted IP = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("forward proxy blocked", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		originURL := "http://" + origin.Listener.Addr().String() + "/x"
		fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: h\r\nProxy-Authorization: Basic %s\r\nConnection: close\r\n\r\n",
			originURL, basicAuthValue("auser", "apass"))
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("forward proxy from blacklisted IP = %d, want 403", resp.StatusCode)
		}
	})
}

// ─── Test 20: protocol sniffing is bounded ─────────────────────────────────

// A silent peer must not park a goroutine and descriptor forever on the public
// port, so the sniff has to time out.
func TestSniffTimeoutClosesSilentConnection(t *testing.T) {
	addr := startTestServer(t, nil)

	// Connect and send nothing at all.
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	buf := make([]byte, 1)
	// The server must give up first; sniffTimeout is 10s and the test budget 20s,
	// so a read here returning an error (not data) proves the deadline fired.
	if _, err := conn.Read(buf); err != nil {
		if os.IsTimeout(err) {
			t.Fatalf("client read timed out before the server closed: sniff deadline did not fire")
		}
		return // server closed the connection, which is what we want
	}
	t.Fatal("server sent data on a silent connection")
}

// ─── Test 21: bad TUNNEL_PATH values must not panic ────────────────────────

// http.ServeMux panics rather than returning an error, so every value it would
// reject has to be caught before registration. That includes ASCII space and
// tab, which Go 1.22+ splits on to support the "METHOD /path" form.
func TestTunnelPathRejectsServeMuxPanics(t *testing.T) {
	bad := map[string]string{
		"no leading slash": "tunnel",
		"trailing space":   "/tunnel ",
		"trailing tab":     "/tunnel\t",
		"inner space":      "/tun nel",
		"method prefix":    "GET /tunnel",
	}
	for name, path := range bad {
		t.Run(name, func(t *testing.T) {
			srv := NewProxyServer(DefaultConfig())
			srv.tunnelLimiter = newRateLimiter(5)
			srv.cfg.TunnelEnabled = true
			srv.cfg.TunnelPath = path

			err := srv.serveMultiplex("127.0.0.1:0")
			if err == nil {
				t.Fatalf("serveMultiplex accepted %q", path)
			}
			if !strings.Contains(err.Error(), "tunnel_path") {
				t.Fatalf("error %q should name tunnel_path", err)
			}
		})
	}

	// A valid path must still start.
	srv := NewProxyServer(DefaultConfig())
	srv.tunnelLimiter = newRateLimiter(5)
	srv.cfg.TunnelEnabled = true
	srv.cfg.TunnelPath = "/api/v1/tunnel"
	if err := srv.serveMultiplex("127.0.0.1:0"); err != nil {
		t.Fatalf("valid tunnel path rejected: %v", err)
	}
}

// A disabled tunnel registers nothing, so a malformed path is harmless and must
// not block startup. Validating unconditionally broke deployments that set
// TUNNEL_ENABLED=false while leaving a stale TUNNEL_PATH behind.
func TestDisabledTunnelIgnoresPath(t *testing.T) {
	srv := NewProxyServer(DefaultConfig())
	srv.tunnelLimiter = newRateLimiter(5)
	srv.cfg.TunnelEnabled = false
	srv.cfg.TunnelPath = "not-even-a-path"

	if err := srv.serveMultiplex("127.0.0.1:0"); err != nil {
		t.Fatalf("disabled tunnel rejected a path it never registers: %v", err)
	}
}

// Unicode whitespace is not a ServeMux separator and must not be rejected.
func TestRoutePatternAllowsUnicodeWhitespace(t *testing.T) {
	if err := validateRoutePattern("tunnel_path", "/tunnel\u00a0"); err != nil {
		t.Fatalf("unicode whitespace rejected: %v", err)
	}
}

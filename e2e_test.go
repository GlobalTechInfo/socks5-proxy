package main

// End-to-end proof that the proxy works for real clients, not just raw sockets.
//
// The tests in multiplex_test.go hand-write HTTP requests over a raw TCP conn.
// That exercises the parser but never the client stack, so a proxy that breaks
// something a real library depends on -- Proxy-Authorization on a CONNECT,
// keep-alive reuse, or a WebSocket upgrade through the tunnel -- would still
// pass them.
//
// This file closes that gap using real origins and real clients:
//   - a genuine WebSocket echo server (coder/websocket, already a dependency)
//   - a genuine plain-HTTP origin and a genuine TLS origin
//   - net/http's own Client with Transport.Proxy pointed at us
//   - coder/websocket's Dialer with its HTTPProxy hook pointed at us
//   - the bundled tunnel client, the same path a phone would take

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// ─── Helpers ───────────────────────────────────────────────────────────────

// hostPort splits a raw origin URL into the host and port SOCKS5 CONNECT needs.
// Parsing the port matters: the origins bind :0, so assuming 80 would be wrong.
func hostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %s: %v", rawURL, err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("port from %s: %v", rawURL, err)
	}
	return u.Hostname(), port
}

// startWSEchoOrigin serves a real WebSocket endpoint that echoes text frames, so
// a client can prove frames survived the proxy rather than just that a socket opened.
func startWSEchoOrigin(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ws origin listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		ctx := r.Context()
		for {
			typ, msg, err := c.Read(ctx)
			if err != nil {
				return
			}
			if err := c.Write(ctx, typ, msg); err != nil {
				return
			}
		}
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return "ws://" + ln.Addr().String() + "/echo"
}

// startWSEchoOriginTLS is the same echo endpoint behind TLS, giving a real wss://
// origin. wss travels through the proxy as a CONNECT tunnel, a different code
// path from ws:// (which is a forwarded absolute-form GET), so it needs its own
// test rather than being assumed to follow.
func startWSEchoOriginTLS(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("wss origin listen: %v", err)
	}
	cfg := DefaultConfig()
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("build tls config: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		ctx := r.Context()
		for {
			typ, msg, err := c.Read(ctx)
			if err != nil {
				return
			}
			if err := c.Write(ctx, typ, msg); err != nil {
				return
			}
		}
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(tls.NewListener(ln, tlsCfg))
	t.Cleanup(func() { srv.Close() })
	return "wss://" + ln.Addr().String() + "/echo"
}

func startHTTPOrigin(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("http origin listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin-reached path=%s", r.URL.Path)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return "http://" + ln.Addr().String()
}

// startTLSOrigin serves the same over TLS with the server's self-signed cert, to
// prove CONNECT is a genuine byte pipe: if the proxy parsed the stream the
// handshake would fail.
func startTLSOrigin(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tls origin listen: %v", err)
	}
	cfg := DefaultConfig()
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("build tls config: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tls-origin-reached")
	})}
	go srv.Serve(tls.NewListener(ln, tlsCfg))
	t.Cleanup(func() { srv.Close() })
	return "https://" + ln.Addr().String()
}

// proxyTransport builds a transport routed through addr.
//
// Credentials go in the proxy URL's userinfo, not ProxyConnectHeader: Go only
// sends ProxyConnectHeader on CONNECT. Forwarded (absolute-form) requests get no
// auth header from it, so a client authenticating that way gets 407 on every
// request. Userinfo covers both, which is what every real client does.
func proxyTransport(t *testing.T, addr, user, pass string) *http.Transport {
	t.Helper()
	proxyURL := "http://" + addr
	if user != "" {
		proxyURL = "http://" + url.UserPassword(user, pass).String() + "@" + addr
	}
	if _, err := url.Parse(proxyURL); err != nil {
		t.Fatalf("parse proxy url %s: %v", proxyURL, err)
	}
	return &http.Transport{
		Proxy:               http.ProxyURL(mustParse(t, proxyURL)),
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost: 4,
	}
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return u
}

// ─── 1. Plain HTTP through the forward proxy, real client ──────────────────

func TestE2EForwardProxyRealHTTPClient(t *testing.T) {
	origin := startHTTPOrigin(t)
	addr := startTestServer(t, func(c *Config) {
		c.AuthEnabled = true
		c.Username = "eu"
		c.Password = "ep"
	})
	client := &http.Client{Transport: proxyTransport(t, addr, "eu", "ep"), Timeout: 15 * time.Second}

	resp, err := client.Get(origin + "/e2e-http")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "origin-reached path=/e2e-http") {
		t.Fatalf("body = %q, want the origin's response", body)
	}

	// Reuse the same client. A proxy that mishandles keep-alive reuse or leaks
	// per-connection state passes a single request but fails here.
	for i := range 3 {
		r2, err := client.Get(origin + fmt.Sprintf("/reuse-%d", i))
		if err != nil {
			t.Fatalf("reuse %d: %v", i, err)
		}
		b2, _ := io.ReadAll(r2.Body)
		r2.Body.Close()
		if !strings.Contains(string(b2), fmt.Sprintf("path=/reuse-%d", i)) {
			t.Fatalf("reuse %d body = %q, want matching path", i, b2)
		}
	}
}

// TestE2EForwardProxyRejectsBadCredentials proves it is not an open relay.
func TestE2EForwardProxyRejectsBadCredentials(t *testing.T) {
	origin := startHTTPOrigin(t)
	addr := startTestServer(t, func(c *Config) {
		c.AuthEnabled = true
		c.Username = "eu"
		c.Password = "correct"
	})
	client := &http.Client{Transport: proxyTransport(t, addr, "eu", "wrong"), Timeout: 10 * time.Second}
	resp, err := client.Get(origin + "/nope")
	if err != nil {
		return // a dial or handshake failure is an acceptable rejection
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("proxy served an authenticated route with bad credentials")
	}
}

// TestE2ETLSOriginThroughConnect drives https through the proxy using net/http's
// own CONNECT handling, so no hand-written CONNECT code is involved.
func TestE2ETLSOriginThroughConnect(t *testing.T) {
	origin := startTLSOrigin(t)
	addr := startTestServer(t, func(c *Config) {
		c.AuthEnabled = true
		c.Username = "tu"
		c.Password = "tp"
	})
	client := &http.Client{Transport: proxyTransport(t, addr, "tu", "tp"), Timeout: 15 * time.Second}

	resp, err := client.Get(origin + "/tls")
	if err != nil {
		t.Fatalf("https through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "tls-origin-reached") {
		t.Fatalf("body = %q, want tls origin response", body)
	}
}

// ─── 2. WebSocket through CONNECT, real WebSocket client ───────────────────

func TestE2EWebSocketThroughProxy(t *testing.T) {
	wsURL := startWSEchoOrigin(t)
	addr := startTestServer(t, func(c *Config) {
		c.AuthEnabled = true
		c.Username = "eu"
		c.Password = "ep"
	})
	httpClient := &http.Client{
		Transport: proxyTransport(t, addr, "eu", "ep"),
		Timeout:   15 * time.Second,
	}
	// coder/websocket has no HTTPProxy option; it dials with the given
	// http.Client, so a Transport with Proxy set makes net/http issue the
	// CONNECT itself. That is the real client stack, which is the point.
	dialOpts := &websocket.DialOptions{HTTPClient: httpClient}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, dialOpts)
	if err != nil {
		t.Fatalf("ws dial through proxy: %v", err)
	}
	defer c.CloseNow()

	// A payload larger than one frame forces real data through the proxy, so a
	// truncation or framing bug shows up as a mismatch instead of passing.
	msg := strings.Repeat("telegram-ws-frame-", 512)
	if err := c.Write(ctx, websocket.MessageText, []byte(msg)); err != nil {
		t.Fatalf("ws write: %v", err)
	}
	_, got, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("ws read: %v", err)
	}
	if string(got) != msg {
		t.Fatalf("echo mismatch: sent %d bytes, got %d bytes", len(msg), len(got))
	}
}

// ─── 3. Through the bundled tunnel client: the path a phone takes ──────────

// startTunnelClient mirrors runClient: each accepted conn gets a real
// clientSession aimed at the mux's own ws:// tunnel endpoint.
func startTunnelClient(t *testing.T, muxAddr, token string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	remote := "ws://" + muxAddr + "/api/v1/tunnel"
	go func() {
		for {
			local, err := ln.Accept()
			if err != nil {
				return
			}
			go clientSession(local, remote, token, false, 30*time.Second, 0)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// socks5Connect performs a real SOCKS5 CONNECT. No credentials: the tunnel
// already authenticated, so the proxied bytes never carry SOCKS5 auth.
func socks5Connect(t *testing.T, proxyAddr, host string, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	if err := socks5Handshake(conn, host, port); err != nil {
		conn.Close()
		t.Fatalf("socks5 handshake to %s:%d: %v", host, port, err)
	}
	return conn
}

// socks5Handshake writes the greeting and CONNECT, returning an error instead of
// calling t.Fatalf so it is safe to use from goroutines.
func socks5Handshake(conn net.Conn, host string, port int) error {
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		return fmt.Errorf("greeting reply: %w", err)
	}
	if sel[0] != 0x05 || sel[1] != 0x00 {
		return fmt.Errorf("greeting reply = %v, want [5 0]", sel)
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("connect reply: %w", err)
	}
	if head[1] != 0x00 {
		return fmt.Errorf("connect reply code %d, want 0", head[1])
	}
	// Drain the bound address that follows the reply header.
	var err error
	switch head[3] {
	case 0x01:
		_, err = io.ReadFull(conn, make([]byte, 4+2))
	case 0x03:
		var l [1]byte
		if _, err = io.ReadFull(conn, l[:]); err == nil {
			_, err = io.ReadFull(conn, make([]byte, int(l[0])+2))
		}
	case 0x04:
		_, err = io.ReadFull(conn, make([]byte, 16+2))
	default:
		return fmt.Errorf("unknown bound address type %d", head[3])
	}
	return err
}

// TestE2ETunnelClientHTTP drives plain HTTP through SOCKS5 over the tunnel, which
// is exactly what Telegram does when it is handed a SOCKS5 host and port.
func TestE2ETunnelClientHTTP(t *testing.T) {
	origin := startHTTPOrigin(t)
	host, port := hostPort(t, origin)
	addr := startTestServer(t, func(c *Config) {
		c.TunnelEnabled = true
		c.TunnelToken = "e2e-tunnel-token"
		c.TunnelPadding = 64 // exercise real framing, not the disabled path
	})
	tunnelAddr := startTunnelClient(t, addr, "e2e-tunnel-token")

	conn := socks5Connect(t, tunnelAddr, host, port)
	defer conn.Close()
	fmt.Fprintf(conn, "GET /via-tunnel HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	resp, err := http.ReadResponse(newBufReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "path=/via-tunnel") {
		t.Fatalf("body = %q, want origin response", body)
	}
}

// TestE2ETunnelClientWebSocket drives a WebSocket upgrade through SOCKS5 over the
// tunnel, then verifies the 101 and echoes a frame. The upgrade is written by
// hand because no WebSocket library speaks SOCKS5.
func TestE2ETunnelClientWebSocket(t *testing.T) {
	wsURL := startWSEchoOrigin(t)
	host, port := hostPort(t, wsURL)
	addr := startTestServer(t, func(c *Config) {
		c.TunnelEnabled = true
		c.TunnelToken = "e2e-ws-token"
		c.TunnelPadding = 64
	})
	tunnelAddr := startTunnelClient(t, addr, "e2e-ws-token")

	conn := socks5Connect(t, tunnelAddr, host, port)
	defer conn.Close()
	fmt.Fprintf(conn, "GET /echo HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"+
		"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", host)
	resp, err := http.ReadResponse(newBufReader(conn), nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		t.Fatalf("Upgrade = %q, want websocket", resp.Header.Get("Upgrade"))
	}
	if resp.Header.Get("Sec-WebSocket-Accept") == "" {
		t.Fatal("missing Sec-WebSocket-Accept")
	}
}

// ─── 4. Concurrency: 50 simultaneous sessions through one listener ─────────

func TestE2ETunnelConcurrentSessions(t *testing.T) {
	const token = "e2e-concurrency-token"
	addr := startTestServer(t, func(c *Config) {
		c.TunnelEnabled = true
		c.TunnelToken = token
		c.TunnelPadding = 128
		// The token bucket defaults to 5 rps and would reject a 50-wide burst,
		// measuring the limiter instead of concurrency.
		c.TunnelRateRPS = 500
	})
	tunnelAddr := startTunnelClient(t, addr, token)
	origin := startHTTPOrigin(t)
	host, port := hostPort(t, origin)

	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", tunnelAddr, 10*time.Second)
			if err != nil {
				errs <- fmt.Errorf("conn %d dial: %w", i, err)
				return
			}
			defer conn.Close()
			if err := socks5Handshake(conn, host, port); err != nil {
				errs <- fmt.Errorf("conn %d handshake: %w", i, err)
				return
			}
			fmt.Fprintf(conn, "GET /c%d HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", i, host)
			resp, err := http.ReadResponse(newBufReader(conn), nil)
			if err != nil {
				errs <- fmt.Errorf("conn %d read: %w", i, err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errs <- fmt.Errorf("conn %d status %d", i, resp.StatusCode)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	failed := 0
	for err := range errs {
		failed++
		if failed <= 3 {
			t.Errorf("session failed: %v", err)
		}
	}
	if failed > 0 {
		t.Fatalf("%d/%d concurrent tunnel sessions failed", failed, n)
	}
}

// ─── 5. The tunnel rate limiter is real and load-bearing ──────────────────
//
// TunnelRateRPS defaults to 5. A 50-wide burst is therefore throttled by design,
// which is why the concurrency test raises it. This locks that behaviour down so
// a future change cannot silently turn the tunnel into an unmetered relay.

func TestE2ETunnelRateLimitRejectsBurst(t *testing.T) {
	addr := startTestServer(t, func(c *Config) {
		c.TunnelEnabled = true
		c.TunnelToken = "e2e-rate-token"
		c.TunnelRateRPS = 5
	})

	// Hit the real tunnel path: an upgrade carrying the token. The limiter sits in
	// front of it, so a burst wider than the bucket must be refused.
	const path = "/api/v1/tunnel?token=e2e-rate-token"
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted, throttled, other := 0, 0, 0
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"+
				"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"+
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", path, addr)
			resp, err := http.ReadResponse(newBufReader(conn), nil)
			if err != nil {
				mu.Lock()
				other++
				mu.Unlock()
				return
			}
			resp.Body.Close()
			mu.Lock()
			switch resp.StatusCode {
			case http.StatusSwitchingProtocols:
				accepted++
			case http.StatusTooManyRequests:
				throttled++
			default:
				other++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	if accepted == 0 {
		t.Fatalf("limiter refused every request (throttled=%d other=%d); it may be stuck at 0", throttled, other)
	}
	if accepted > 12 {
		t.Fatalf("accepted %d/20 upgrades despite a 5 rps limit; limiter is not throttling", accepted)
	}
	t.Logf("limiter held: %d accepted, %d throttled, %d other (limit 5 rps)", accepted, throttled, other)
}

// ─── 6. wss:// through CONNECT ────────────────────────────────────────────
//
// ws:// rides the forward path as an absolute-form GET; wss:// must go through
// CONNECT and then a TLS handshake to the origin. Those are different code paths,
// so wss is asserted separately rather than assumed to follow from ws.

func TestE2EWSSThroughConnectProxy(t *testing.T) {
	wssURL := startWSEchoOriginTLS(t)
	addr := startTestServer(t, func(c *Config) {
		c.AuthEnabled = true
		c.Username = "wu"
		c.Password = "wp"
	})
	client := &http.Client{
		Transport: proxyTransport(t, addr, "wu", "wp"),
		Timeout:   20 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c, _, err := websocket.Dial(ctx, wssURL, &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		t.Fatalf("wss dial through proxy: %v", err)
	}
	defer c.CloseNow()

	// Multi-frame sized payload: catches truncation and bad fragmentation.
	msg := strings.Repeat("wss-through-connect-", 400)
	if err := c.Write(ctx, websocket.MessageText, []byte(msg)); err != nil {
		t.Fatalf("wss write: %v", err)
	}
	_, got, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("wss read: %v", err)
	}
	if string(got) != msg {
		t.Fatalf("wss echo mismatch: sent %d bytes, got %d bytes", len(msg), len(got))
	}
}

// TestE2ETunnelClientWSS drives a TLS WebSocket through SOCKS5 over the tunnel,
// mirroring what a real client does when handed the tunnel's local listener.
func TestE2ETunnelClientWSS(t *testing.T) {
	wssURL := startWSEchoOriginTLS(t)
	host, port := hostPort(t, wssURL)
	addr := startTestServer(t, func(c *Config) {
		c.TunnelEnabled = true
		c.TunnelToken = "e2e-wss-token"
		c.TunnelPadding = 256
	})
	tunnelAddr := startTunnelClient(t, addr, "e2e-wss-token")

	// SOCKS5 first, then a TLS handshake to the origin, then the upgrade: all
	// three layers must survive the tunnel intact.
	raw := socks5Connect(t, tunnelAddr, host, port)
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: host})
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		t.Fatalf("tls handshake through tunnel: %v", err)
	}

	fmt.Fprintf(conn, "GET /echo HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"+
		"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", host)
	resp, err := http.ReadResponse(newBufReader(conn), nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}

	// Speak WebSocket frames over the raw conn to prove data moves, not just the
	// handshake. Client frames must be masked; a server frame must not be.
	var frame []byte
	payload := "tunnel-wss-payload"
	frame = append(frame, 0x81)                    // FIN + text
	frame = append(frame, 0x80|byte(len(payload))) // MASK set + length
	mask := []byte{0x11, 0x22, 0x33, 0x44}
	frame = append(frame, mask...)
	for i := range len(payload) {
		frame = append(frame, payload[i]^mask[i%4])
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write masked ws frame: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("read ws frame header: %v", err)
	}
	if hdr[0] != 0x81 {
		t.Fatalf("first ws byte = %#x, want 0x81 (FIN+text, unmasked from server)", hdr[0])
	}
	if hdr[1]&0x80 != 0 {
		t.Fatal("server frame must not be masked")
	}
	n := int(hdr[1] & 0x7f)
	got := make([]byte, n)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read ws payload: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

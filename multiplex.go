package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// ─── Protocol Constants ────────────────────────────────────────────────────

const (
	socks5Greeting     = 0x05
	tlsRecordHandshake = 0x16
	defaultTunnelPath  = "/api/v1/tunnel"
	keepaliveInterval  = 30 * time.Second
	// sniffTimeout bounds protocol detection so a silent peer cannot hold a
	// goroutine and descriptor open on the public port.
	sniffTimeout      = 10 * time.Second
	maxHandshakeBytes = 16
)

// ─── Buffered Connection (peek replay) ─────────────────────────────────────

// replayConn wraps a conn with a buffered reader so bytes consumed while
// sniffing are handed back to the handler. Without this the first byte of a
// SOCKS5 greeting or TLS handshake is lost and the protocol stalls.
type replayConn struct {
	net.Conn
	r io.Reader
}

func newReplayConn(c net.Conn, r io.Reader) *replayConn {
	return &replayConn{Conn: c, r: r}
}

func (c *replayConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// oneShotListener hands a single already-accepted connection to http.Server.
// Each multiplexed connection gets its own http.Server so there is no shared
// state or cross-connection interference.
type oneShotListener struct {
	c    net.Conn
	done bool
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.done {
		return nil, io.EOF
	}
	l.done = true
	return l.c, nil
}

func (l *oneShotListener) Close() error   { return nil }
func (l *oneShotListener) Addr() net.Addr { return l.c.LocalAddr() }

// ─── Handler Merging ───────────────────────────────────────────────────────

// bufWriter buffers a response so it can be discarded if the handler turns out
// to be the wrong handler for this path. Discarding is what makes a 404-based
// fallback safe: an http.Error body already written to the socket cannot be
// taken back.
type bufWriter struct {
	header http.Header
	body   bytes.Buffer
	code   int
}

func newBufWriter() *bufWriter {
	return &bufWriter{header: make(http.Header), code: http.StatusOK}
}

func (w *bufWriter) Header() http.Header { return w.header }

func (w *bufWriter) WriteHeader(code int) {
	if w.code == http.StatusOK && code != http.StatusOK {
		w.code = code
	}
}

func (w *bufWriter) Write(p []byte) (int, error) { return w.body.Write(p) }

func (w *bufWriter) flushTo(dst http.ResponseWriter) {
	for k, vs := range w.header {
		for _, v := range vs {
			dst.Header().Add(k, v)
		}
	}
	dst.WriteHeader(w.code)
	_, _ = dst.Write(w.body.Bytes())
}

// mergeHandlers tries each handler in order and uses the first one that does
// not return 404.
//
// This exists because the admin and metrics muxes register the same paths
// (/, /chart.min.js, /api/history/stats, /api/history/destinations,
// /api/history/top-alltime). http.ServeMux panics on duplicate patterns, and
// http.StripPrefix is not an option either because the metrics dashboard
// fetches absolute paths. Order matters: admin first, so / serves the main
// dashboard and the metrics-only paths (/metrics, /prometheus, /api/live) fall
// through to the metrics mux.
func mergeHandlers(handlers ...http.Handler) http.Handler {
	if len(handlers) == 1 {
		return handlers[0]
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range handlers[:len(handlers)-1] {
			bw := newBufWriter()
			h.ServeHTTP(bw, r)
			if bw.code != http.StatusNotFound {
				bw.flushTo(w)
				return
			}
		}
		handlers[len(handlers)-1].ServeHTTP(w, r)
	})
}

// ─── TLS ───────────────────────────────────────────────────────────────────

// buildTLSConfig loads the configured cert/key pair, or generates a self-signed
// one in memory so the TLS path works on every platform without per-deployment
// certificate setup.
//
// ponytail: self-signed certs regenerate on restart and carry a generic issuer,
// which defeats some TLS fingerprinting checks. Add a real ACME client only if a
// deployment needs public-trust certs -- PaaS edges cannot issue them anyway.
func buildTLSConfig(cfg Config) (*tls.Config, error) {
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load tls keypair: %w", err)
		}
		if cert.Leaf == nil && len(cert.Certificate) > 0 {
			if leaf, perr := x509.ParseCertificate(cert.Certificate[0]); perr == nil {
				cert.Leaf = leaf
			}
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}

	host, _ := os.Hostname()
	if host == "" {
		host = "localhost"
	}
	certPEM, keyPEM, err := selfSignedCert(host)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse generated cert: %w", err)
	}
	// Populate Leaf explicitly so /tls-cert can re-encode the cert without
	// depending on X509KeyPair filling it in.
	if cert.Leaf == nil {
		block, _ := pem.Decode(certPEM)
		if block != nil {
			if leaf, perr := x509.ParseCertificate(block.Bytes); perr == nil {
				cert.Leaf = leaf
			}
		}
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

func selfSignedCert(host string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"socks5-proxy"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// ─── TLS Certificate Endpoint ──────────────────────────────────────────────

// tlsCertHandler exposes the active certificate as PEM so a client on a VPS
// (where we terminate TLS rather than a PaaS edge) can install and pin it.
//
// Behind a PaaS edge this endpoint is never reached by clients: the edge
// presents its own certificate and terminates TLS before the request gets here.
func (s *ProxyServer) tlsCertHandler(tlsCfg *tls.Config) http.HandlerFunc {
	var certPEM []byte
	if len(tlsCfg.Certificates) > 0 && tlsCfg.Certificates[0].Leaf != nil {
		certPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: tlsCfg.Certificates[0].Leaf.Raw,
		})
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if len(certPEM) == 0 {
			http.Error(w, "no certificate available", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="socks5-proxy.crt"`)
		_, _ = w.Write(certPEM)
	}
}

// ─── Connection Padding (stealth) ──────────────────────────────────────────

// padConn pads outbound WebSocket messages and strips the padding inbound.
//
// Why a length prefix: padding a byte *stream* is not possible, because the
// receiver cannot know how many of the extra bytes are payload and how many are
// padding. A WebSocket message is self-delimiting, so each Write becomes one
// message of the form:
//
//	[2-byte payload length][payload][random fill to a padTo multiple]
//
// On read the length prefix is authoritative and the fill is discarded. This
// keeps every wire message the same rounded size, so a 2-byte SOCKS5 reply and a
// 64KB data burst no longer differ in shape -- the signal Camoufle-style padding
// exists to remove.
//
// Writes are never buffered across calls: buffering a partial chunk would stall
// small control replies until enough bytes accumulated, which deadlocks the
// SOCKS5 handshake.
type padConn struct {
	net.Conn
	padTo int

	// readMu guards partial and serialises frame reads. It must NOT be held
	// while waiting for peer data: a single mutex shared with Write deadlocks a
	// full-duplex session, because Read blocks holding it while the peer's Write
	// waits for it to release.
	readMu sync.Mutex
	// writeMu serialises frame writes so interleaved frames are not corrupted.
	writeMu sync.Mutex

	// partial holds the not-yet-returned remainder of the current frame's
	// payload. It is consumed from the front and empties when fully read.
	partial []byte
}

const (
	padLenSize  = 2
	padReadSize = 32 << 10
)

func newPadConn(c net.Conn, padTo int) net.Conn {
	if padTo <= 1 {
		return c
	}
	return &padConn{Conn: c, padTo: padTo}
}

// maxFrame is the largest payload a 2-byte length prefix can describe. Larger
// writes are split across frames, each with its own header.
const maxFrame = 0xFFFF

func (p *padConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	origLen := len(b)

	p.writeMu.Lock()

	var frame []byte
	for len(b) > 0 {
		n := len(b)
		if n > maxFrame {
			n = maxFrame
		}
		// A deterministic fill is as good as random here: the goal is uniform
		// frame length, not secret bytes.
		frame = append(frame[:0], byte(n>>8), byte(n))
		frame = append(frame, b[:n]...)
		for len(frame)%p.padTo != 0 {
			frame = append(frame, byte(len(frame)*31))
		}
		if _, err := p.Conn.Write(frame); err != nil {
			p.writeMu.Unlock()
			return 0, err
		}
		b = b[n:]
	}
	p.writeMu.Unlock()
	return origLen, nil
}

func (p *padConn) Read(b []byte) (int, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()

	for len(p.partial) == 0 {
		var hdr [padLenSize]byte
		if _, err := io.ReadFull(p.Conn, hdr[:]); err != nil {
			return 0, err
		}
		n := int(hdr[0])<<8 | int(hdr[1])

		total := padLenSize + n
		if total%p.padTo != 0 {
			total += p.padTo - total%p.padTo
		}
		// The header is already consumed, so only the remainder of the frame is
		// still on the wire. Reading total bytes here would wait forever for the
		// two bytes that were read above.
		rest := make([]byte, total-padLenSize)
		if _, err := io.ReadFull(p.Conn, rest); err != nil {
			return 0, err
		}
		p.partial = rest[:n]
	}

	n := copy(b, p.partial)
	p.partial = p.partial[n:]
	return n, nil
}

func (p *padConn) Close() error { return p.Conn.Close() }

// ─── Tunnel Handler ────────────────────────────────────────────────────────

// tunnelHandler authenticates and upgrades a WebSocket request, then hands the
// resulting conn to the normal SOCKS5 pipeline. Reusing handleClient is what
// keeps user management, tiers, rate limits and metrics identical between the
// raw port and tunneled sessions.
// connectHandler implements HTTP CONNECT, i.e. standard forward-proxy semantics.
//
// This is what makes the single public URL usable with no local client: browsers,
// curl, Telegram Desktop's HTTP-proxy mode and most HTTP libraries already speak
// it, so pointing them at the PaaS URL and the SOCKS5 credentials is enough. The
// WebSocket tunnel remains available for SOCKS5-only clients.
//
// Auth reuses the SOCKS5 credentials so there is one set of secrets, and an
// unconfigured proxy refuses outright rather than becoming an open relay.
func (s *ProxyServer) connectHandler(w http.ResponseWriter, r *http.Request) {
	cfg := s.currentConfig()

	if !cfg.AuthEnabled || cfg.Username == "" || cfg.Password == "" {
		http.Error(w, "proxy auth is not configured", http.StatusForbidden)
		return
	}
	// Same IP access control that handleClient applies on the SOCKS5 path.
	// Checked before the limiter and the credentials so a blacklisted client
	// cannot use the HTTP proxy to route around the operator's own rules.
	if !s.isAllowedIP(requestIP(r)) {
		s.blockedConns.Add(1)
		metricBlockedConns.WithLabelValues(requestIP(r)).Inc()
		s.logger.Warn("blocked IP on http proxy", "client", requestIP(r))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !s.tunnelLimiter.allow() {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	if !validProxyAuth(r, cfg.Username, cfg.Password) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="socks5-proxy"`)
		s.logger.Warn("CONNECT auth failed", "remote", r.RemoteAddr)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}

	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	if host == "" {
		http.Error(w, "CONNECT requires a target host", http.StatusBadRequest)
		return
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		// RFC 9111 allows a bare authority; default to https.
		host = net.JoinHostPort(host, "443")
	}

	// Hijack before dialling so the connection can outlive the handler.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, clientRW, err := hj.Hijack()
	if err != nil {
		s.logger.Debug("CONNECT hijack failed", "error", err)
		return
	}
	defer clientConn.Close()

	targetConn, err := net.DialTimeout("tcp", host, 15*time.Second)
	if err != nil {
		s.logger.Warn("CONNECT dial failed", "target", host, "error", err)
		fmt.Fprintf(clientRW, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		_ = clientRW.Flush()
		return
	}
	defer targetConn.Close()
	tuneConn(targetConn)

	s.recordDestination(host)
	s.totalConns.Add(1)
	metricTotalConns.Inc()
	s.activeConns.Add(1)
	metricActiveConns.Inc()
	defer func() {
		s.activeConns.Add(-1)
		metricActiveConns.Dec()
	}()

	if _, err := clientRW.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := clientRW.Flush(); err != nil {
		return
	}
	// Any buffered client bytes are part of the tunnelled stream.
	var pending []byte
	if n := clientRW.Reader.Buffered(); n > 0 {
		pending = make([]byte, n)
		if _, err := io.ReadFull(clientRW.Reader, pending); err != nil {
			return
		}
	}
	if len(pending) > 0 {
		if _, err := targetConn.Write(pending); err != nil {
			return
		}
	}

	log := s.logger.With("proto", "http-connect", "target", host)
	done := make(chan struct{}, 2)
	go func() {
		_, err := io.Copy(targetConn, clientConn)
		if err != nil && !isClosedConnError(err) {
			log.Debug("client->target copy error", "error", err)
		}
		done <- struct{}{}
	}()
	go func() {
		_, err := io.Copy(clientConn, targetConn)
		if err != nil && !isClosedConnError(err) {
			log.Debug("target->client copy error", "error", err)
		}
		done <- struct{}{}
	}()
	<-done
	log.Info("connect session closed", "target", host)
}

// forwardProxyHandler serves the non-CONNECT half of HTTP forward proxying.
//
// Browsers and most libraries send absolute-form request targets
// ("GET http://example.com/ HTTP/1.1") for plain http:// traffic, and reserve
// CONNECT for https://. Handling only CONNECT would leave the proxy half
// working and returning 401 on ordinary http:// requests, so both are covered.
func (s *ProxyServer) forwardProxyHandler(w http.ResponseWriter, r *http.Request) {
	cfg := s.currentConfig()

	if !cfg.AuthEnabled || cfg.Username == "" || cfg.Password == "" {
		http.Error(w, "proxy auth is not configured", http.StatusProxyAuthRequired)
		return
	}
	// Same IP access control as the SOCKS5 and CONNECT paths.
	if !s.isAllowedIP(requestIP(r)) {
		s.blockedConns.Add(1)
		metricBlockedConns.WithLabelValues(requestIP(r)).Inc()
		s.logger.Warn("blocked IP on forward proxy", "client", requestIP(r))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !s.tunnelLimiter.allow() {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	if !validProxyAuth(r, cfg.Username, cfg.Password) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="socks5-proxy"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	if r.URL.Scheme != "http" || r.URL.Host == "" {
		http.Error(w, "only absolute http:// targets are supported; use CONNECT for https://", http.StatusBadRequest)
		return
	}

	target := r.URL.Host
	s.recordDestination(target)
	s.totalConns.Add(1)
	metricTotalConns.Inc()

	// The proxy's own credentials must not be forwarded upstream.
	r.Header.Del("Proxy-Authorization")
	r.RequestURI = ""
	r.Header.Del("Connection")

	out := &forwardProxy{
		server: s,
		inner:  s.proxyTransport.RoundTrip,
	}
	out.ServeHTTP(w, r)
}

// forwardProxy is a thin ReverseProxy configured for forward-proxy use.
type forwardProxy struct {
	server *ProxyServer
	inner  func(*http.Request) (*http.Response, error)
}

func (f *forwardProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp, err := f.inner(r)
	if err != nil {
		f.server.logger.Debug("forward proxy failed", "error", err)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// validProxyAuth checks Proxy-Authorization: Basic against the SOCKS5 creds.
//
// r.BasicAuth() is deliberately not used: it only reads the "Authorization"
// header, and a forward proxy receives its credentials in "Proxy-Authorization".
// requestIP extracts the peer address for an HTTP request. In single-port mode
// this is always a real TCP peer, so the RemoteAddr is authoritative; the
// bracketed form from SplitHostPort is stripped.
func requestIP(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func validProxyAuth(r *http.Request, wantUser, wantPass string) bool {
	h := r.Header.Get("Proxy-Authorization")
	const prefix = "Basic "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[len(prefix):]))
	if err != nil {
		return false
	}
	user, pass, found := strings.Cut(string(raw), ":")
	if !found {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(wantUser)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(wantPass)) == 1
	return userOK && passOK
}

func (s *ProxyServer) tunnelHandler(w http.ResponseWriter, r *http.Request) {
	cfg := s.currentConfig()

	// Check the documented switch as well as the token. An operator who sets
	// TUNNEL_ENABLED=false but leaves a token behind must actually get no tunnel.
	if !cfg.TunnelEnabled {
		http.Error(w, "tunnel disabled", http.StatusForbidden)
		return
	}
	if cfg.TunnelToken == "" {
		http.Error(w, "tunnel disabled", http.StatusForbidden)
		return
	}
	if !s.tunnelLimiter.allow() {
		http.Error(w, "too many tunnel attempts", http.StatusTooManyRequests)
		return
	}
	if !validTunnelToken(r, cfg.TunnelToken) {
		s.logger.Warn("tunnel auth failed", "remote", r.RemoteAddr)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Advertise the padding size in the upgrade response so the client mirrors
	// it. Padding must be applied by both ends or the stream is corrupt.
	w.Header().Set("X-Tunnel-Padding", strconv.Itoa(cfg.TunnelPadding))

	wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Payloads are already TLS-framed and incompressible; deflate would
		// burn CPU to save nothing and adds a nonstandard negotiation.
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		s.logger.Debug("tunnel upgrade failed", "error", err)
		return
	}

	// NetConn yields a real net.Conn, so handleClient works unchanged.
	//
	// The context must be detached from the request: when ServeHTTP returns,
	// Go cancels r.Context(), and NetConn reads/writes are bound to it, so
	// tying the tunnel's lifetime to the request would kill every session the
	// moment the handler goroutine unwinds. The conn is instead closed
	// explicitly by handleClient when the SOCKS5 session ends.
	ctx, cancel := context.WithCancel(context.Background())

	var conn net.Conn = &cancelConn{
		Conn:   websocket.NetConn(ctx, wsConn, websocket.MessageBinary),
		cancel: cancel,
	}

	if cfg.TunnelPadding > 1 {
		conn = newPadConn(conn, cfg.TunnelPadding)
	}

	s.logger.Info("tunnel session opened", "remote", r.RemoteAddr, "padding", cfg.TunnelPadding)
	s.handleClient(conn)
}

// cancelConn ties a context cancel to Close, so tearing down the SOCKS5 session
// also releases the WebSocket's internal goroutines.
type cancelConn struct {
	net.Conn
	cancel context.CancelFunc
	once   sync.Once
}

func (c *cancelConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.cancel)
	return err
}

func validTunnelToken(r *http.Request, want string) bool {
	got := r.URL.Query().Get("token")
	if got == "" {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			got = strings.TrimPrefix(h, "Bearer ")
		}
	}
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (s *ProxyServer) currentConfig() Config {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return s.cfg
}

// ─── Single-Port Multiplexer ───────────────────────────────────────────────

// serveMultiplex runs the SOCKS5 proxy, the TLS terminator and the HTTP
// dashboards on a single port by sniffing the first byte of each connection.
//
// This is what makes the app deployable on PaaS platforms that expose exactly
// one HTTP endpoint: their edge terminates TLS and forwards HTTP only, so raw
// SOCKS5 can never reach the container unless it is encoded inside an HTTP
// request.
//
//	0x05           -> SOCKS5
//	0x16           -> TLS ClientHello, then re-sniff the decrypted byte
//	A-Z, "PRI"     -> HTTP request (PRI * = HTTP/2 cleartext preface)
//
// validateRoutePattern rejects a value that http.ServeMux cannot register.
//
// ServeMux panics rather than returning an error, so any pattern it rejects
// would otherwise take the process down at startup:
//
//   - a pattern not starting with "/" panics with "host/path missing /"
//   - ASCII space or tab panics with "invalid method", because Go 1.22+ splits
//     patterns on whitespace to support the "METHOD /path" form
//
// Only ASCII space (0x20) and tab (0x09) are rejected. Unicode whitespace is
// not a separator to ServeMux and is left alone, and the value is not trimmed:
// a silently altered path would be harder to diagnose than a rejected one.
func validateRoutePattern(name, pattern string) error {
	if !strings.HasPrefix(pattern, "/") {
		return fmt.Errorf("%s must start with %q, got %q", name, "/", pattern)
	}
	if strings.ContainsAny(pattern, " \t") {
		return fmt.Errorf("%s must not contain spaces or tabs, got %q", name, pattern)
	}
	return nil
}

func (s *ProxyServer) serveMultiplex(addr string) error {
	cfg := s.currentConfig()

	var tlsCfg *tls.Config
	if err := func() error {
		var err error
		tlsCfg, err = buildTLSConfig(cfg)
		return err
	}(); err != nil {
		return err
	}

	s.tunnelLimiter = newRateLimiter(cfg.TunnelRateRPS)

	tunnelPath := cfg.TunnelPath
	if tunnelPath == "" {
		tunnelPath = defaultTunnelPath
	}
	// Tell the auth layer which path to skip (basicAuth reads this).
	tunnelPublicPath = tunnelPath

	// Upstream client for absolute-URI forward-proxy requests. Proxy is nil so
	// nested proxying cannot loop, and the dial is tuned like any other.
	s.proxyTransport = &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          256,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
	}

	tunnelMux := http.NewServeMux()
	// Only advertise the tunnel when it is actually enabled, so a disabled
	// tunnel does not answer 403 on a live path and looks absent to a prober.
	// The route pattern is validated here rather than above, because a disabled
	// tunnel registers nothing and so cannot be harmed by a malformed value.
	if cfg.TunnelEnabled {
		if err := validateRoutePattern("tunnel_path", tunnelPath); err != nil {
			return err
		}
		tunnelMux.HandleFunc(tunnelPath, s.tunnelHandler)
	}
	tunnelMux.HandleFunc("/tls-cert", s.tlsCertHandler(tlsCfg))

	// admin first: its / serves the dashboard, and metrics-only paths fall through
	merged := mergeHandlers(s.adminHandler(), s.metricsHandler(), tunnelMux)

	// CONNECT is intercepted before the merge: an admin-auth failure or a 404
	// fallback must never be allowed to answer a tunnel request. It is also
	// excluded from securityHeaders, whose 200 response would otherwise be
	// written ahead of the hijacked upgrade.
	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodConnect:
			s.connectHandler(w, r)
			return
		case r.URL.IsAbs():
			// Absolute-form target: this is a forward-proxy request, not a
			// dashboard request. Relative paths (the dashboard) never look like
			// this, so there is no ambiguity.
			s.forwardProxyHandler(w, r)
			return
		}
		merged.ServeHTTP(w, r)
	})
	if cfg.SecurityHeadersEnabled {
		handler = securityHeaders(handler)
	}

	// WriteTimeout must be zero: the existing per-port servers set 5s, which
	// would sever every tunnel after 5 seconds.
	httpSrv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 3 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    8192,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	// The listener must outlive this function: serveMultiplex returns as soon as
	// the accept loop is running. Closing it here would kill the server instantly.
	go func() {
		<-s.shutdownCh
		_ = ln.Close()
	}()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-s.shutdownCh:
					return
				default:
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				s.logger.Error("accept error", "error", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			tuneConn(conn)

			// Enforce the same connection ceiling as the raw-port accept loop.
			// Without this the public single port is a cheaper way to exhaust
			// resources than the dedicated SOCKS5 port.
			s.configMu.RLock()
			maxConns := s.cfg.MaxConns
			s.configMu.RUnlock()
			if s.activeConns.Load() >= int64(maxConns) {
				s.logger.Warn("max connections reached, rejecting", "client", conn.RemoteAddr())
				_ = conn.Close()
				continue
			}

			go s.dispatchMultiplex(conn, tlsCfg, httpSrv)
		}
	}()

	s.logger.Info("single-port mux started", "addr", addr, "tunnel_path", tunnelPath, "tunnel", cfg.TunnelEnabled)
	return nil
}

func (s *ProxyServer) dispatchMultiplex(conn net.Conn, tlsCfg *tls.Config, httpSrv *http.Server) {
	// conn is closed on every path that does not hand it to a handler.
	// handleClient closes it via untrackConn; http.Server closes it after the
	// handler returns. Anything else is a leak, so each early return below
	// defers a close.
	//
	// Without the sniff deadline, a client that connects and sends nothing
	// parks this goroutine and its file descriptor indefinitely, which on a
	// single public port is a cheap way to exhaust descriptors.
	_ = conn.SetReadDeadline(time.Now().Add(sniffTimeout))
	_ = conn.SetWriteDeadline(time.Now().Add(sniffTimeout))

	br := newPeekReader(conn)

	first, err := br.peekByte()
	if err != nil {
		_ = conn.Close()
		return
	}

	switch {
	case first == socks5Greeting:
		clearSniffDeadlines(conn)
		s.handleClient(newReplayConn(conn, br))

	case first == tlsRecordHandshake:
		tlsConn := tls.Server(newReplayConn(conn, br), tlsCfg)
		if err := tlsConn.HandshakeContext(context.Background()); err != nil {
			_ = conn.Close()
			return
		}
		// The handshake is done, so the inner sniff gets a fresh deadline.
		_ = tlsConn.SetReadDeadline(time.Now().Add(sniffTimeout))
		inner := newPeekReader(tlsConn)
		firstDecrypted, err := inner.peekByte()
		if err != nil {
			_ = conn.Close()
			return
		}
		clearSniffDeadlines(tlsConn)
		wrapped := newReplayConn(tlsConn, inner)
		switch {
		case firstDecrypted == socks5Greeting:
			s.handleClient(wrapped)
		case isHTTPFirstByte(firstDecrypted):
			s.serveSingleHTTP(wrapped, httpSrv)
		default:
			_ = wrapped.Close()
		}

	case isHTTPFirstByte(first):
		clearSniffDeadlines(conn)
		s.serveSingleHTTP(newReplayConn(conn, br), httpSrv)

	default:
		_ = conn.Close()
	}
}

// clearSniffDeadlines removes the sniff deadline so the handler can impose its
// own timeouts instead of inheriting this one.
func clearSniffDeadlines(c net.Conn) {
	_ = c.SetReadDeadline(time.Time{})
	_ = c.SetWriteDeadline(time.Time{})
}

func isHTTPFirstByte(b byte) bool {
	// HTTP methods start with an uppercase letter. "PRI" is the HTTP/2
	// cleartext preface, which Go answers with 505.
	return (b >= 'A' && b <= 'Z') || b == 'P'
}

// serveSingleHTTP hands one accepted connection to http.Server.
//
// The conn must NOT be closed here. Serve returns as soon as Accept yields
// io.EOF, which happens the moment the single conn is dispatched -- while the
// handler is still running in its own goroutine. Closing on return severs the
// response mid-flight. http.Server owns the conn and closes it when the handler
// finishes.
func (s *ProxyServer) serveSingleHTTP(conn net.Conn, srv *http.Server) {
	one := &oneShotListener{c: conn}
	if err := srv.Serve(one); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, io.EOF) {
		s.logger.Debug("http serve ended", "error", err)
	}
}

// ─── Peek Reader ───────────────────────────────────────────────────────────

// peekReader reads from a conn but holds the first byte until asked, so the
// dispatcher can make a decision and then replay the full stream to the handler.
type peekReader struct {
	src  io.Reader
	buf  []byte
	read bool
}

func newPeekReader(src io.Reader) *peekReader {
	return &peekReader{src: src}
}

func (p *peekReader) peekByte() (byte, error) {
	if !p.read {
		var b [1]byte
		n, err := p.src.Read(b[:])
		if n > 0 {
			p.buf = append(p.buf, b[0])
			p.read = true
		}
		if err != nil && len(p.buf) == 0 {
			return 0, err
		}
	}
	if len(p.buf) == 0 {
		return 0, io.EOF
	}
	return p.buf[0], nil
}

func (p *peekReader) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return p.src.Read(b)
}

// ─── Client Subcommand ─────────────────────────────────────────────────────

// runClient exposes a local SOCKS5 listener whose sessions are tunnelled to the
// remote server over WebSocket. It performs no SOCKS5 parsing of its own: the
// local client's handshake travels inside the tunnel, making this a transparent
// byte pipe, the same shape as "ssh -D".
func runClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	remoteURL := fs.String("url", "", "remote tunnel URL, e.g. wss://proxy.example.com/api/v1/tunnel")
	token := fs.String("token", "", "tunnel token (or set TUNNEL_TOKEN)")
	listen := fs.String("listen", "127.0.0.1:1080", "local SOCKS5 listen address")
	insecure := fs.Bool("insecure", false, "skip TLS verification (VPS with self-signed cert only)")
	keepalive := fs.Duration("keepalive", keepaliveInterval, "ping interval; must stay under the edge idle timeout")
	padding := fs.Int("padding", 0, "message padding size; use the value from the server (0 = server decides)")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *remoteURL == "" {
		return errors.New("-url is required")
	}
	u, err := parseRemoteURL(*remoteURL)
	if err != nil {
		return fmt.Errorf("invalid -url: %w", err)
	}
	*remoteURL = u.String()
	tok := *token
	if tok == "" {
		tok = os.Getenv("TUNNEL_TOKEN")
	}
	if tok == "" {
		return errors.New("-token or TUNNEL_TOKEN is required")
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", *listen, err)
	}
	defer ln.Close()

	slog.Info("tunnel client started", "remote", *remoteURL, "listen", ln.Addr())

	for {
		local, err := ln.Accept()
		if err != nil {
			return err
		}
		// Each session owns its own dial+retry, so a session waiting out a
		// server cold start never blocks the next connection.
		go clientSession(local, *remoteURL, tok, *insecure, *keepalive, *padding)
	}
}

func clientSession(local net.Conn, remoteURL, token string, insecure bool, keepalive time.Duration, padding int) {
	_ = padding // dialTunnel negotiates the real value from the server response
	defer local.Close()
	tuneConn(local)

	remote, wsConn, cancel, err := dialTunnel(remoteURL, token, insecure, padding)
	if err != nil {
		slog.Error("tunnel dial failed", "error", err)
		return
	}
	defer cancel()
	defer remote.Close()

	// Padding is applied inside dialTunnel, which reads the size the server
	// advertised in its upgrade response. Wrapping again here would double-frame
	// the stream and corrupt it.

	done := make(chan struct{}, 2)
	go func() {
		_, err := io.Copy(remote, local)
		if err != nil && !isClosedConnError(err) {
			slog.Debug("client->server copy error", "error", err)
		}
		done <- struct{}{}
	}()
	go func() {
		_, err := io.Copy(local, remote)
		if err != nil && !isClosedConnError(err) {
			slog.Debug("server->client copy error", "error", err)
		}
		done <- struct{}{}
	}()

	// Keepalive: edges such as Cloudflare close idle WebSockets after 100s and
	// that timeout is not configurable below Enterprise. A ping resets it.
	stop := make(chan struct{})
	defer close(stop)
	go clientKeepalive(wsConn, keepalive, stop)

	<-done
	// Tear the whole session down once either direction ends, so the surviving
	// copy goroutine is not left blocked on a half-open socket.
	local.Close()
	remote.Close()
}

// dialTunnel opens one tunnel session, retrying with capped exponential backoff
// so a server in cold start is not hammered but a brief blip does not stall the
// session.
//
// The returned context must stay alive for the life of the conn: NetConn derives
// its read/write cancellation from it, so cancelling would sever the session.
// Callers own cancelling it once the session ends.
func dialTunnel(rawURL, token string, insecure bool, padding int) (net.Conn, *websocket.Conn, context.CancelFunc, error) {
	const (
		dialTimeout  = 15 * time.Second
		maxAttempts  = 5
		retryBase    = 500 * time.Millisecond
		maxRetryWait = 8 * time.Second
	)

	// Session lifetime context, deliberately not the per-dial one.
	sessionCtx, sessionCancel := context.WithCancel(context.Background())

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		ctx, dialCancel := context.WithTimeout(sessionCtx, dialTimeout)
		opts := &websocket.DialOptions{
			HTTPHeader:      authHeader(token),
			HTTPClient:      &http.Client{Transport: tlsTransport(insecure)},
			CompressionMode: websocket.CompressionDisabled,
		}
		wsConn, resp, err := websocket.Dial(ctx, rawURL, opts)
		if err != nil && resp != nil {
			slog.Error("tunnel handshake rejected", "status", resp.Status,
				"server", resp.Header.Get("Server"), "cf_ray", resp.Header.Get("CF-Ray"))
		}
		if err == nil {
			// Mirror the server's padding. Padding is applied by both ends or
			// the stream is corrupt, so the value is taken from the server's
			// upgrade response and sanity-checked rather than assumed.
			padding := 0
			if resp != nil {
				if v, perr := strconv.Atoi(resp.Header.Get("X-Tunnel-Padding")); perr == nil && v > 1 {
					padding = v
				}
			}
			conn := websocket.NetConn(sessionCtx, wsConn, websocket.MessageBinary)
			if padding > 1 {
				conn = newPadConn(conn, padding)
			}
			// NetConn derives its lifetime from sessionCtx, not the dial ctx, so
			// the dial context can be released immediately on success.
			dialCancel()
			return conn, wsConn, sessionCancel, nil
		}
		dialCancel()
		lastErr = err

		if attempt == maxAttempts {
			break
		}
		wait := retryBase << (attempt - 1)
		if wait > maxRetryWait {
			wait = maxRetryWait
		}
		slog.Warn("tunnel dial retry", "attempt", attempt, "wait", wait, "error", err)
		time.Sleep(wait)
	}
	sessionCancel()
	return nil, nil, nil, fmt.Errorf("after %d attempts: %w", maxAttempts, lastErr)
}

func authHeader(token string) http.Header {
	h := make(http.Header)
	h.Set("Authorization", "Bearer "+token)
	return h
}

// clientKeepalive sends a real WebSocket control-frame ping.
//
// It must be a control frame, not an empty data write: padConn.Write discards
// an empty slice, so a conn-level write would send nothing at all once padding
// is on (which is the default) and the edge would still close the idle socket.
// Control frames also count as activity for every intermediary's idle timer.
// The pong is consumed by the concurrent read in io.Copy.
func clientKeepalive(wsConn *websocket.Conn, interval time.Duration, stop <-chan struct{}) {
	if wsConn == nil || interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := wsConn.Ping(ctx)
			cancel()
			if err != nil {
				slog.Debug("tunnel keepalive failed", "error", err)
				return
			}
		}
	}
}

func tlsTransport(insecure bool) *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
}

// ─── Main Dispatch ─────────────────────────────────────────────────────────

// parseRemoteURL validates the tunnel URL early so a typo fails fast with a
// clear message, and normalises http/https to ws/wss so users can paste the
// browser URL they were given.
func parseRemoteURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	case "ws", "wss":
	default:
		return nil, fmt.Errorf("scheme must be ws, wss, http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("URL is missing a host")
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = defaultTunnelPath
	}
	return u, nil
}

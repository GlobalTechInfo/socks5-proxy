package main

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ─── Configuration ─────────────────────────────────────────────────────────

type Config struct {
	ProxyPort    int      `json:"proxy_port"`
	AdminPort    int      `json:"admin_port"`
	MetricsPort  int      `json:"metrics_port"`
	MaxConns     int      `json:"max_connections"`
	AuthEnabled  bool     `json:"auth_enabled"`
	Username     string   `json:"username"`
	Password     string   `json:"password"`
	Whitelist    []string `json:"whitelist"`
	Blacklist    []string `json:"blacklist"`
	ReadTimeout  int      `json:"read_timeout_seconds"`
	WriteTimeout int      `json:"write_timeout_seconds"`
	IdleTimeout  int      `json:"idle_timeout_seconds"`

	// Admin/dashboard auth
	AdminEnabled bool   `json:"admin_auth_enabled"`
	AdminUser    string `json:"admin_username"`
	AdminPass    string `json:"admin_password"`

	// Security headers
	SecurityHeadersEnabled bool `json:"security_headers_enabled"`

	// Rate limiting (admin endpoints)
	RateLimitEnabled bool `json:"rate_limit_enabled"`
	RateLimitRPS     int  `json:"rate_limit_rps"`
}

func DefaultConfig() Config {
	return Config{
		ProxyPort:              1080,
		AdminPort:              8080,
		MetricsPort:            9090,
		MaxConns:               1000,
		AuthEnabled:            true,
		ReadTimeout:            30,
		WriteTimeout:           30,
		IdleTimeout:            120,
		AdminEnabled:           true,
		SecurityHeadersEnabled: true,
		RateLimitEnabled:       true,
		RateLimitRPS:           30,
	}
}

func LoadConfig(filename string) (Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(filename)
	if err != nil {
		return cfg, fmt.Errorf("read config %s: %w", filename, err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}

	// Environment variables override config file
	if port := os.Getenv("PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil && p > 0 {
			cfg.ProxyPort = p
		}
	}
	if port := os.Getenv("PROXY_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil && p > 0 {
			cfg.ProxyPort = p
		}
	}
	if port := os.Getenv("ADMIN_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil && p > 0 {
			cfg.AdminPort = p
		}
	}
	if port := os.Getenv("METRICS_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil && p > 0 {
			cfg.MetricsPort = p
		}
	}
	if user := os.Getenv("PROXY_USER"); user != "" {
		cfg.Username = user
	}
	if pass := os.Getenv("PROXY_PASS"); pass != "" {
		cfg.Password = pass
	}
	if max := os.Getenv("MAX_CONNECTIONS"); max != "" {
		if m, err := strconv.Atoi(max); err == nil && m > 0 {
			cfg.MaxConns = m
		}
	}

	// Admin auth env vars
	if user := os.Getenv("ADMIN_USER"); user != "" {
		cfg.AdminUser = user
	}
	if pass := os.Getenv("ADMIN_PASS"); pass != "" {
		cfg.AdminPass = pass
	}
	if v := os.Getenv("ADMIN_AUTH_ENABLED"); v != "" {
		cfg.AdminEnabled = v == "true" || v == "1"
	}
	if v := os.Getenv("SECURITY_HEADERS_ENABLED"); v != "" {
		cfg.SecurityHeadersEnabled = v == "true" || v == "1"
	}
	if v := os.Getenv("RATE_LIMIT_ENABLED"); v != "" {
		cfg.RateLimitEnabled = v == "true" || v == "1"
	}
	if v := os.Getenv("RATE_LIMIT_RPS"); v != "" {
		if r, err := strconv.Atoi(v); err == nil && r > 0 {
			cfg.RateLimitRPS = r
		}
	}

	return cfg, nil
}

// ─── SOCKS5 Protocol Constants ─────────────────────────────────────────────

const (
	socksVersion     = 0x05
	socksAuthVersion = 0x01

	methodNoAuth       = 0x00
	methodGSSAPI       = 0x01
	methodUserPassword = 0x02
	methodNoAcceptable = 0xFF

	cmdConnect = 0x01

	addrTypeIPv4 = 0x01
	addrTypeFQDN = 0x03
	addrTypeIPv6 = 0x04

	replySucceeded         = 0x00
	replyGeneralFailure    = 0x01
	replyConnNotAllowed    = 0x02
	replyNetworkUnreachable = 0x03
	replyHostUnreachable   = 0x04
	replyConnRefused       = 0x05
	replyTTLExpired        = 0x06
	replyCmdNotSupported   = 0x07
	replyAddrNotSupported  = 0x08

	authStatusSuccess = 0x00
	authStatusFailure = 0x01
)

// ─── Metrics ───────────────────────────────────────────────────────────────

var (
	metricActiveConns = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "socks5_active_connections",
		Help: "Current number of active SOCKS5 connections",
	})
	metricTotalConns = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "socks5_total_connections",
		Help: "Total number of SOCKS5 connections handled",
	})
	metricConnDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "socks5_connection_duration_seconds",
		Help:    "Duration of SOCKS5 connections in seconds",
		Buckets: []float64{0.1, 0.5, 1, 5, 10, 30, 60, 120, 300},
	})
	metricAuthFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "socks5_auth_failures_total",
		Help: "Total number of authentication failures",
	})
	metricBlockedConns = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "socks5_blocked_connections_total",
		Help: "Total number of blocked connections by IP",
	}, []string{"ip"})
	metricConnErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "socks5_connection_errors_total",
		Help: "Total connection errors by type",
	}, []string{"type"})
)

func init() {
	prometheus.MustRegister(
		metricActiveConns,
		metricTotalConns,
		metricConnDuration,
		metricAuthFailures,
		metricBlockedConns,
		metricConnErrors,
	)
}

// ─── Stats (for admin API) ─────────────────────────────────────────────────

type Stats struct {
	ActiveConns     int64             `json:"active_connections"`
	TotalConns      int64             `json:"total_connections"`
	AuthFailures    int64             `json:"auth_failures"`
	BlockedConns    int64             `json:"blocked_connections"`
	TopDestinations map[string]int64  `json:"top_destinations"`
	Uptime          string            `json:"uptime"`
	Version         string            `json:"version"`
}

type ProxyServer struct {
	cfg          Config
	configMu     sync.RWMutex
	logger       *slog.Logger
	startTime    time.Time
	activeConns  atomic.Int64
	totalConns   atomic.Int64
	authFailures atomic.Int64
	blockedConns atomic.Int64

	// Destination tracking
	destMu   sync.RWMutex
	dests    map[string]int64

	// Connection tracking for graceful shutdown
	connMu   sync.Mutex
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup

	// Rate limiter (shared reference for runtime updates)
	limiter *rateLimiter

	// Persistence
	store *Store

	// Shutdown
	shutdownOnce sync.Once
	shutdownCh   chan struct{}
}

func NewProxyServer(cfg Config) *ProxyServer {
	return &ProxyServer{
		cfg:       cfg,
		logger:    slog.Default(),
		startTime: time.Now(),
		dests:     make(map[string]int64),
		conns:     make(map[net.Conn]struct{}),
		shutdownCh: make(chan struct{}),
	}
}

func (s *ProxyServer) trackConn(c net.Conn) {
	s.connMu.Lock()
	s.conns[c] = struct{}{}
	s.connMu.Unlock()
}

func (s *ProxyServer) untrackConn(c net.Conn) {
	s.connMu.Lock()
	delete(s.conns, c)
	s.connMu.Unlock()
	c.Close()
}

func (s *ProxyServer) closeAllConns() {
	s.connMu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.conns = make(map[net.Conn]struct{})
	s.connMu.Unlock()
}

func (s *ProxyServer) isAllowedIP(ip string) bool {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	for _, blackIP := range s.cfg.Blacklist {
		if ip == blackIP {
			return false
		}
	}
	if len(s.cfg.Whitelist) > 0 {
		for _, whiteIP := range s.cfg.Whitelist {
			if ip == whiteIP {
				return true
			}
		}
		return false
	}
	return true
}

func (s *ProxyServer) recordDestination(dest string) {
	s.destMu.Lock()
	s.dests[dest]++
	s.destMu.Unlock()
}

func (s *ProxyServer) getTopDestinations(n int) map[string]int64 {
	s.destMu.RLock()
	defer s.destMu.RUnlock()

	if n > 100 {
		n = 100
	}
	result := make(map[string]int64)
	count := 0
	for k, v := range s.dests {
		if count >= n {
			break
		}
		result[k] = v
		count++
	}
	return result
}

func (s *ProxyServer) Stats() Stats {
	s.destMu.RLock()
	topDests := make(map[string]int64)
	for k, v := range s.dests {
		topDests[k] = v
	}
	s.destMu.RUnlock()

	return Stats{
		ActiveConns:     s.activeConns.Load(),
		TotalConns:      s.totalConns.Load(),
		AuthFailures:    s.authFailures.Load(),
		BlockedConns:    s.blockedConns.Load(),
		TopDestinations: topDests,
		Uptime:          time.Since(s.startTime).Truncate(time.Second).String(),
		Version:         "1.1.0",
	}
}

// ─── SOCKS5 Protocol Implementation ────────────────────────────────────────

func (s *ProxyServer) handleClient(conn net.Conn) {
	s.wg.Add(1)
	defer s.wg.Done()

	s.trackConn(conn)
	defer s.untrackConn(conn)

	clientIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()
	log := s.logger.With("client", clientIP)

	// Snapshot config under lock for this connection's lifetime
	s.configMu.RLock()
	cfgSnap := s.cfg
	s.configMu.RUnlock()

	// Check IP whitelist/blacklist BEFORE reading anything
	if !s.isAllowedIP(clientIP) {
		s.blockedConns.Add(1)
		metricBlockedConns.WithLabelValues(clientIP).Inc()
		log.Warn("blocked IP")
		buf := make([]byte, 2)
		conn.Read(buf)
		conn.SetWriteDeadline(time.Now().Add(time.Duration(cfgSnap.WriteTimeout) * time.Second))
		conn.Write([]byte{socksVersion, methodNoAcceptable})
		return
	}

	// Set initial read deadline for handshake
	conn.SetReadDeadline(time.Now().Add(time.Duration(cfgSnap.ReadTimeout) * time.Second))

	// Step 1: Method negotiation (RFC 1928 Section 3)
	method, err := s.negotiateMethod(conn, &cfgSnap)
	if err != nil {
		log.Error("method negotiation failed", "error", err)
		metricConnErrors.WithLabelValues("method_negotiation").Inc()
		return
	}

	// Step 2: Authentication (RFC 1929) if required
	var authenticatedUser *User
	if method == methodUserPassword {
		user, err := s.authenticateUser(conn, &cfgSnap)
		if err != nil {
			s.authFailures.Add(1)
			metricAuthFailures.Inc()
			log.Error("authentication failed", "error", err)
			return
		}
		authenticatedUser = user
		log = log.With("user", user.Username, "tier", user.Tier)
	} else if method != methodNoAuth {
		conn.SetWriteDeadline(time.Now().Add(time.Duration(cfgSnap.WriteTimeout) * time.Second))
		conn.Write([]byte{socksVersion, methodNoAcceptable})
		return
	}

	// Step 3: Read CONNECT request
	conn.SetReadDeadline(time.Now().Add(time.Duration(cfgSnap.ReadTimeout) * time.Second))
	target, err := s.readRequest(conn, &cfgSnap)
	if err != nil {
		log.Error("request read failed", "error", err)
		metricConnErrors.WithLabelValues("request_read").Inc()
		return
	}

	// Check per-user limits
	if authenticatedUser != nil && s.store != nil {
		// Check expiry
		if authenticatedUser.Expiry != nil {
			expiry, err := time.Parse("2006-01-02 15:04:05", *authenticatedUser.Expiry)
			if err == nil && time.Now().After(expiry) {
				log.Warn("user account expired")
				s.sendReply(conn, replyConnNotAllowed, &cfgSnap)
				return
			}
		}

		// Check data limit
		if authenticatedUser.DataLimitBytes > 0 && authenticatedUser.DataUsedBytes >= authenticatedUser.DataLimitBytes {
			log.Warn("user data limit reached", "used", authenticatedUser.DataUsedBytes, "limit", authenticatedUser.DataLimitBytes)
			s.sendReply(conn, replyConnNotAllowed, &cfgSnap)
			return
		}

		// Check connection limit
		if authenticatedUser.MaxConnections > 0 {
			activeConns, err := s.store.GetActiveConnCount(authenticatedUser.ID)
			if err == nil && activeConns >= int64(authenticatedUser.MaxConnections) {
				log.Warn("user connection limit reached", "active", activeConns, "limit", authenticatedUser.MaxConnections)
				s.sendReply(conn, replyConnNotAllowed, &cfgSnap)
				return
			}
		}
	}

	log = log.With("target", target)
	log.Info("connecting to target")

	// Step 4: Connect to target
	conn.SetReadDeadline(time.Now().Add(time.Duration(cfgSnap.IdleTimeout) * time.Second))
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Error("target connection failed", "error", err)
		s.sendReply(conn, replyConnRefused, &cfgSnap)
		metricConnErrors.WithLabelValues("target_connect").Inc()
		return
	}
	defer targetConn.Close()

	// Step 5: Send success reply
	if err := s.sendReply(conn, replySucceeded, &cfgSnap); err != nil {
		log.Error("reply send failed", "error", err)
		return
	}

	// Step 6: Relay data
	s.relay(conn, targetConn, log, target, &cfgSnap, authenticatedUser)
}

func (s *ProxyServer) negotiateMethod(conn net.Conn, cfg *Config) (byte, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, fmt.Errorf("read greeting header: %w", err)
	}

	if buf[0] != socksVersion {
		return 0, fmt.Errorf("unsupported SOCKS version: %d", buf[0])
	}

	nMethods := int(buf[1])
	if nMethods == 0 || nMethods > 255 {
		return 0, fmt.Errorf("invalid method count: %d", nMethods)
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, fmt.Errorf("read methods: %w", err)
	}

	var selected byte = methodNoAcceptable
	for _, m := range methods {
		switch m {
		case methodNoAuth:
			if !cfg.AuthEnabled {
				selected = methodNoAuth
			} else if selected == methodNoAcceptable {
				selected = methodNoAcceptable
			}
		case methodUserPassword:
			if cfg.AuthEnabled {
				selected = methodUserPassword
				break
			}
		}
	}

	conn.SetWriteDeadline(time.Now().Add(time.Duration(cfg.WriteTimeout) * time.Second))
	if _, err := conn.Write([]byte{socksVersion, selected}); err != nil {
		return 0, fmt.Errorf("write method response: %w", err)
	}

	return selected, nil
}

func (s *ProxyServer) authenticateUser(conn net.Conn, cfg *Config) (*User, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("read auth header: %w", err)
	}

	if buf[0] != socksAuthVersion {
		return nil, fmt.Errorf("unsupported auth version: %d", buf[0])
	}

	usernameLen := int(buf[1])
	if usernameLen == 0 || usernameLen > 255 {
		return nil, fmt.Errorf("invalid username length: %d", usernameLen)
	}

	username := make([]byte, usernameLen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return nil, fmt.Errorf("read username: %w", err)
	}

	passLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLenBuf); err != nil {
		return nil, fmt.Errorf("read password length: %w", err)
	}

	passwordLen := int(passLenBuf[0])
	if passwordLen > 255 {
		return nil, fmt.Errorf("invalid password length: %d", passwordLen)
	}

	password := make([]byte, passwordLen)
	if _, err := io.ReadFull(conn, password); err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}

	conn.SetWriteDeadline(time.Now().Add(time.Duration(cfg.WriteTimeout) * time.Second))

	// Try multi-user auth from database first
	if s.store != nil {
		user, err := s.store.GetUser(string(username))
		if err == nil && user != nil {
			// Check enabled
			if !user.Enabled {
				conn.Write([]byte{socksAuthVersion, authStatusFailure})
				return nil, fmt.Errorf("user %s is disabled", string(username))
			}

			// Constant-time password comparison
			if subtle.ConstantTimeCompare(password, []byte(user.PasswordHash)) == 1 {
				if _, err := conn.Write([]byte{socksAuthVersion, authStatusSuccess}); err != nil {
					return nil, fmt.Errorf("write auth success: %w", err)
				}
				return user, nil
			}

			conn.Write([]byte{socksAuthVersion, authStatusFailure})
			return nil, fmt.Errorf("invalid credentials for user %s", string(username))
		}
	}

	// Fall back to legacy single-user auth
	userMatch := subtle.ConstantTimeCompare(username, []byte(cfg.Username))
	passMatch := subtle.ConstantTimeCompare(password, []byte(cfg.Password))
	authOK := userMatch == 1 && passMatch == 1

	if authOK {
		if _, err := conn.Write([]byte{socksAuthVersion, authStatusSuccess}); err != nil {
			return nil, fmt.Errorf("write auth success: %w", err)
		}
		// Return a virtual user for legacy auth
		return &User{
			Username:       string(username),
			Tier:           "unlimited",
			MaxConnections: -1,
			BandwidthMbps:  -1,
			DataLimitBytes: -1,
			Enabled:        true,
		}, nil
	}

	if _, err := conn.Write([]byte{socksAuthVersion, authStatusFailure}); err != nil {
		return nil, fmt.Errorf("write auth failure: %w", err)
	}
	return nil, errors.New("invalid credentials")
}

func (s *ProxyServer) readRequest(conn net.Conn, cfg *Config) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("read request header: %w", err)
	}

	if header[0] != socksVersion {
		return "", fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}
	if header[1] != cmdConnect {
		s.sendReply(conn, replyCmdNotSupported, cfg)
		return "", fmt.Errorf("unsupported command: %d", header[1])
	}

	var host string
	var port uint16

	switch header[3] {
	case addrTypeIPv4:
		addr := make([]byte, 6)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("read IPv4 addr: %w", err)
		}
		host = net.IPv4(addr[0], addr[1], addr[2], addr[3]).String()
		port = binary.BigEndian.Uint16(addr[4:6])

	case addrTypeFQDN:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", fmt.Errorf("read FQDN length: %w", err)
		}
		domainLen := int(lenBuf[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", fmt.Errorf("read FQDN: %w", err)
		}
		host = string(domain)
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, portBuf); err != nil {
			return "", fmt.Errorf("read FQDN port: %w", err)
		}
		port = binary.BigEndian.Uint16(portBuf)

	case addrTypeIPv6:
		addr := make([]byte, 18)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("read IPv6 addr: %w", err)
		}
		host = net.IP(addr[:16]).String()
		port = binary.BigEndian.Uint16(addr[16:18])

	default:
		s.sendReply(conn, replyAddrNotSupported, cfg)
		return "", fmt.Errorf("unsupported address type: %d", header[3])
	}

	return fmt.Sprintf("%s:%d", host, port), nil
}

func (s *ProxyServer) sendReply(conn net.Conn, reply byte, cfg *Config) error {
	conn.SetWriteDeadline(time.Now().Add(time.Duration(cfg.WriteTimeout) * time.Second))
	resp := []byte{
		socksVersion, reply, 0x00,
		addrTypeIPv4, 0, 0, 0, 0,
		0, 0,
	}
	_, err := conn.Write(resp)
	return err
}

func (s *ProxyServer) relay(client, target net.Conn, log *slog.Logger, targetAddr string, cfg *Config, user *User) {
	s.activeConns.Add(1)
	s.totalConns.Add(1)
	metricActiveConns.Inc()
	metricTotalConns.Inc()
	s.recordDestination(targetAddr)

	startTime := time.Now()

	// Track user connection
	var connID int64
	if user != nil && s.store != nil && user.ID > 0 {
		id, err := s.store.TrackConnectionStart(user.ID, targetAddr)
		if err == nil {
			connID = id
		}
	}

	client.SetReadDeadline(time.Now().Add(time.Duration(cfg.IdleTimeout) * time.Second))
	target.SetReadDeadline(time.Now().Add(time.Duration(cfg.IdleTimeout) * time.Second))

	var wg sync.WaitGroup
	var bytesUp, bytesDown atomic.Int64
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, err := io.Copy(target, client)
		if err != nil && !isClosedConnError(err) {
			log.Debug("client->target copy error", "error", err)
		}
		bytesUp.Add(n)
		target.SetReadDeadline(time.Now())
	}()

	go func() {
		defer wg.Done()
		n, err := io.Copy(client, target)
		if err != nil && !isClosedConnError(err) {
			log.Debug("target->client copy error", "error", err)
		}
		bytesDown.Add(n)
		client.SetReadDeadline(time.Now())
	}()

	wg.Wait()

	// Track connection end
	if connID > 0 && s.store != nil {
		s.store.TrackConnectionEnd(connID, bytesUp.Load(), bytesDown.Load())
	}

	duration := time.Since(startTime).Seconds()
	metricConnDuration.Observe(duration)
	metricActiveConns.Dec()
	s.activeConns.Add(-1)

	log.Info("connection closed",
		"duration", time.Since(startTime).Truncate(time.Millisecond),
		"bytes_up", bytesUp.Load(),
		"bytes_down", bytesDown.Load(),
	)
}

func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe")
}

// ─── HTTP Security Middleware ──────────────────────────────────────────────

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func basicAuth(user, pass string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}
			u, p, ok := r.BasicAuth()
			if !ok ||
				subtle.ConstantTimeCompare([]byte(u), []byte(user)) != 1 ||
				subtle.ConstantTimeCompare([]byte(p), []byte(pass)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="Admin"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ─── Rate Limiter ──────────────────────────────────────────────────────────

type rateLimiter struct {
	mu       sync.Mutex
	tokens   float64
	maxRate  float64
	lastTime time.Time
}

func newRateLimiter(rps int) *rateLimiter {
	return &rateLimiter{
		tokens:   float64(rps),
		maxRate:  float64(rps),
		lastTime: time.Now(),
	}
}

func (rl *rateLimiter) setRPS(rps int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.maxRate = float64(rps)
	if rl.tokens > rl.maxRate {
		rl.tokens = rl.maxRate
	}
}

func (rl *rateLimiter) allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastTime).Seconds()
	rl.lastTime = now
	rl.tokens += elapsed * rl.maxRate
	if rl.tokens > rl.maxRate {
		rl.tokens = rl.maxRate
	}
	if rl.tokens < 1 {
		return false
	}
	rl.tokens--
	return true
}

func rateLimit(limiter *rateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.allow() {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ─── No-Directory-Listing File Server ──────────────────────────────────────

func noDirListing(root http.FileSystem) http.Handler {
	fs := http.FileServer(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to open the file; if it's a directory, block it
		f, err := root.Open(r.URL.Path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()

		stat, err := f.Stat()
		if err != nil || stat.IsDir() {
			http.NotFound(w, r)
			return
		}

		fs.ServeHTTP(w, r)
	})
}

// ─── HTTP Servers (Admin + Metrics) ────────────────────────────────────────

func (s *ProxyServer) startAdminServer(addr string) *http.Server {
	mux := http.NewServeMux()

	// /health is always open (for load balancers / probes)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"uptime":  time.Since(s.startTime).Truncate(time.Second).String(),
			"version": "1.1.0",
		})
	})

	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.Stats())
	})

	mux.HandleFunc("/api/top-destinations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		n := 10
		if v := r.URL.Query().Get("n"); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
				n = parsed
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.getTopDestinations(n))
	})

	// GET /api/config - return current config (passwords masked)
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			s.configMu.RLock()
			cfg := s.cfg
			s.configMu.RUnlock()

			type safeConfig struct {
				MaxConnections        int    `json:"max_connections"`
				ProxyUser             string `json:"proxy_user"`
				ProxyPassHidden       string `json:"proxy_pass"`
				AuthEnabled           bool   `json:"auth_enabled"`
				AdminAuthEnabled      bool   `json:"admin_auth_enabled"`
				SecurityHeadersEnabled bool  `json:"security_headers_enabled"`
				RateLimitEnabled      bool   `json:"rate_limit_enabled"`
				RateLimitRPS          int    `json:"rate_limit_rps"`
			}
			masked := "****"
			if cfg.Password == "" {
				masked = ""
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(safeConfig{
				MaxConnections:         cfg.MaxConns,
				ProxyUser:              cfg.Username,
				ProxyPassHidden:        masked,
				AuthEnabled:            cfg.AuthEnabled,
				AdminAuthEnabled:       cfg.AdminEnabled,
				SecurityHeadersEnabled: cfg.SecurityHeadersEnabled,
				RateLimitEnabled:       cfg.RateLimitEnabled,
				RateLimitRPS:           cfg.RateLimitRPS,
			})
			return
		}

		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var patch struct {
			MaxConnections         *int    `json:"max_connections"`
			ProxyUser              *string `json:"proxy_user"`
			ProxyPass              *string `json:"proxy_pass"`
			AuthEnabled            *bool   `json:"auth_enabled"`
			AdminAuthEnabled       *bool   `json:"admin_auth_enabled"`
			AdminUser              *string `json:"admin_user"`
			AdminPass              *string `json:"admin_pass"`
			SecurityHeadersEnabled *bool   `json:"security_headers_enabled"`
			RateLimitEnabled       *bool   `json:"rate_limit_enabled"`
			RateLimitRPS           *int    `json:"rate_limit_rps"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&patch); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		s.configMu.Lock()
		if patch.MaxConnections != nil && *patch.MaxConnections > 0 {
			s.cfg.MaxConns = *patch.MaxConnections
		}
		if patch.ProxyUser != nil {
			s.cfg.Username = *patch.ProxyUser
		}
		if patch.ProxyPass != nil && *patch.ProxyPass != "" && *patch.ProxyPass != "****" {
			s.cfg.Password = *patch.ProxyPass
		}
		if patch.AuthEnabled != nil {
			s.cfg.AuthEnabled = *patch.AuthEnabled
		}
		if patch.AdminAuthEnabled != nil {
			s.cfg.AdminEnabled = *patch.AdminAuthEnabled
		}
		if patch.AdminUser != nil {
			s.cfg.AdminUser = *patch.AdminUser
		}
		if patch.AdminPass != nil && *patch.AdminPass != "" && *patch.AdminPass != "****" {
			s.cfg.AdminPass = *patch.AdminPass
		}
		if patch.SecurityHeadersEnabled != nil {
			s.cfg.SecurityHeadersEnabled = *patch.SecurityHeadersEnabled
		}
		if patch.RateLimitEnabled != nil {
			s.cfg.RateLimitEnabled = *patch.RateLimitEnabled
		}
		if patch.RateLimitRPS != nil && *patch.RateLimitRPS > 0 {
			s.cfg.RateLimitRPS = *patch.RateLimitRPS
		}
		newCfg := s.cfg
		s.configMu.Unlock()

		// Update rate limiter dynamically
		if s.limiter != nil {
			s.limiter.setRPS(newCfg.RateLimitRPS)
		}

		// Persist to database
		if s.store != nil {
			batch := map[string]string{
				"max_connections":          fmt.Sprintf("%d", newCfg.MaxConns),
				"proxy_user":              newCfg.Username,
				"auth_enabled":            fmt.Sprintf("%v", newCfg.AuthEnabled),
				"admin_auth_enabled":      fmt.Sprintf("%v", newCfg.AdminEnabled),
				"admin_username":          newCfg.AdminUser,
				"security_headers_enabled": fmt.Sprintf("%v", newCfg.SecurityHeadersEnabled),
				"rate_limit_enabled":      fmt.Sprintf("%v", newCfg.RateLimitEnabled),
				"rate_limit_rps":          fmt.Sprintf("%d", newCfg.RateLimitRPS),
			}
			if patch.ProxyPass != nil && *patch.ProxyPass != "" && *patch.ProxyPass != "****" {
				batch["proxy_pass"] = newCfg.Password
			}
			if patch.AdminPass != nil && *patch.AdminPass != "" && *patch.AdminPass != "****" {
				batch["admin_pass"] = newCfg.AdminPass
			}
			if err := s.store.SaveConfigBatch(batch); err != nil {
				s.logger.Error("failed to persist config to db", "error", err)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
	})

	// GET /api/history/stats - historical stats snapshots
	mux.HandleFunc("/api/history/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.store == nil {
			http.Error(w, "database not available", http.StatusServiceUnavailable)
			return
		}
		n := 60
		if v := r.URL.Query().Get("n"); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
				n = parsed
			}
		}
		history, err := s.store.GetStatsHistory(n)
		if err != nil {
			http.Error(w, "query failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(history)
	})

	// GET /api/history/destinations - destination history
	mux.HandleFunc("/api/history/destinations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.store == nil {
			http.Error(w, "database not available", http.StatusServiceUnavailable)
			return
		}
		n := 50
		if v := r.URL.Query().Get("n"); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
				n = parsed
			}
		}
		history, err := s.store.GetDestinationHistory(n)
		if err != nil {
			http.Error(w, "query failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(history)
	})

	// GET /api/history/top-alltime - all-time top destinations
	mux.HandleFunc("/api/history/top-alltime", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.store == nil {
			http.Error(w, "database not available", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.store.GetTopDestinationsAllTime(100))
	})

	// ─── User Management ────────────────────────────────────────────────

	// GET /api/users - list all users
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		if s.store == nil {
			http.Error(w, "database not available", http.StatusServiceUnavailable)
			return
		}
		if r.Method == http.MethodGet {
			users, err := s.store.ListUsers()
			if err != nil {
				http.Error(w, "query failed: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(users)
			return
		}

		// POST /api/users - create user
		if r.Method == http.MethodPost {
			var req struct {
				Username string `json:"username"`
				Password string `json:"password"`
				Tier     string `json:"tier"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
				http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
				return
			}
			if req.Username == "" || req.Tier == "" {
				http.Error(w, "username and tier required", http.StatusBadRequest)
				return
			}
			// Auto-generate password if empty
			if req.Password == "" {
				req.Password = GeneratePassword()
			}
			user, err := s.store.CreateUser(req.Username, req.Password, req.Tier)
			if err != nil {
				http.Error(w, "create failed: "+err.Error(), http.StatusInternalServerError)
				return
			}
			// Return user with generated password
			type createUserResp struct {
				*User
				Password string `json:"password,omitempty"`
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(createUserResp{User: user, Password: req.Password})
			return
		}

		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})

	// PUT /api/users/:id - update user
	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		if s.store == nil {
			http.Error(w, "database not available", http.StatusServiceUnavailable)
			return
		}

		// Parse path: /api/users/123 or /api/users/123/reset
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/users/"), "/")
		if len(parts) == 0 || parts[0] == "" {
			http.Error(w, "user ID required", http.StatusBadRequest)
			return
		}

		id := parseInt64(parts[0])

		// POST /api/users/:id/reset - reset user data usage
		if len(parts) == 2 && parts[1] == "reset" && r.Method == http.MethodPost {
			if err := s.store.ResetUserData(id); err != nil {
				http.Error(w, "reset failed: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "reset"})
			return
		}

		// GET /api/users/:id
		if r.Method == http.MethodGet && len(parts) == 1 {
			user, err := s.store.GetUserByID(id)
			if err != nil {
				http.Error(w, "user not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(user)
			return
		}

		// DELETE /api/users/:id
		if r.Method == http.MethodDelete && len(parts) == 1 {
			if err := s.store.DeleteUser(id); err != nil {
				http.Error(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			return
		}

		// PUT /api/users/:id
		if r.Method == http.MethodPut && len(parts) == 1 {
			var req struct {
				Tier     *string `json:"tier"`
				Password *string `json:"password"`
				Enabled  *bool   `json:"enabled"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
				http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
				return
			}
			if err := s.store.UpdateUser(id, req.Tier, req.Password, req.Enabled); err != nil {
				http.Error(w, "update failed: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
			return
		}

		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})

	// GET /api/tiers - list available tiers
	mux.HandleFunc("/api/tiers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Tiers)
	})

	// WebSocket-to-SOCKS5 bridge for tunneling through HTTP
	var upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// First message from client: target address (host:port)
		_, target, err := conn.ReadMessage()
		if err != nil {
			return
		}

		// Connect to local SOCKS5 proxy
		proxyAddr := fmt.Sprintf("127.0.0.1:%d", s.cfg.ProxyPort)
		proxyConn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			conn.WriteMessage(websocket.TextMessage, []byte("error: "+err.Error()))
			return
		}
		defer proxyConn.Close()

		// SOCKS5 handshake
		authMethods := []byte{0x05, 0x01, 0x00} // no auth
		if s.cfg.AuthEnabled {
			authMethods = []byte{0x05, 0x01, 0x02} // username/password
		}
		if _, err := proxyConn.Write(authMethods); err != nil {
			return
		}
		resp := make([]byte, 2)
		if _, err := io.ReadFull(proxyConn, resp); err != nil || resp[1] == 0xFF {
			return
		}

		// Auth if needed
		if s.cfg.AuthEnabled {
			userBytes := []byte(s.cfg.Username)
			passBytes := []byte(s.cfg.Password)
			authPacket := make([]byte, 3+len(userBytes)+len(passBytes))
			authPacket[0] = 0x01
			authPacket[1] = byte(len(userBytes))
			copy(authPacket[2:2+len(userBytes)], userBytes)
			authPacket[2+len(userBytes)] = byte(len(passBytes))
			copy(authPacket[3+len(userBytes):], passBytes)
			if _, err := proxyConn.Write(authPacket); err != nil {
				return
			}
			authResp := make([]byte, 2)
			if _, err := io.ReadFull(proxyConn, authResp); err != nil || authResp[1] != 0x00 {
				return
			}
		}

		// SOCKS5 CONNECT request - parse target
		host, portStr, err := net.SplitHostPort(string(target))
		if err != nil {
			return
		}
		port, _ := strconv.Atoi(portStr)

		// Build CONNECT request
		var connectReq []byte
		connectReq = append(connectReq, 0x05, 0x01, 0x00) // VER, CMD=CONNECT, RSV

		ip := net.ParseIP(host)
		if ip4 := ip.To4(); ip4 != nil {
			connectReq = append(connectReq, 0x01) // IPv4
			connectReq = append(connectReq, ip4...)
		} else if ip6 := ip.To16(); ip6 != nil {
			connectReq = append(connectReq, 0x04) // IPv6
			connectReq = append(connectReq, ip6...)
		} else {
			connectReq = append(connectReq, 0x03) // Domain
			connectReq = append(connectReq, byte(len(host)))
			connectReq = append(connectReq, []byte(host)...)
		}
		connectReq = append(connectReq, byte(port>>8), byte(port&0xFF))

		if _, err := proxyConn.Write(connectReq); err != nil {
			return
		}

		// Read CONNECT response
		connectResp := make([]byte, 10)
		if _, err := io.ReadFull(proxyConn, connectResp); err != nil {
			return
		}
		if connectResp[1] != 0x00 {
			return
		}

		// Bridge: WebSocket <-> SOCKS5 proxy
		done := make(chan struct{})
		go func() {
			defer close(done)
			buf := make([]byte, 32*1024)
			for {
				n, err := proxyConn.Read(buf)
				if n > 0 {
					conn.WriteMessage(websocket.BinaryMessage, buf[:n])
				}
				if err != nil {
					return
				}
			}
		}()
		go func() {
			defer conn.Close()
			for {
				_, msg, err := conn.ReadMessage()
				if err != nil {
					proxyConn.Close()
					return
				}
				if _, err := proxyConn.Write(msg); err != nil {
					return
				}
			}
		}()
		<-done
	})

	mux.HandleFunc("/chart.min.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/chart.min.js")
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, "web/index.html")
	})

	var handler http.Handler = mux

	// Apply middleware stack (outermost first)
	if s.cfg.RateLimitEnabled {
		s.limiter = newRateLimiter(s.cfg.RateLimitRPS)
		handler = rateLimit(s.limiter)(handler)
	}
	if s.cfg.AdminEnabled && s.cfg.AdminUser != "" && s.cfg.AdminPass != "" {
		handler = basicAuth(s.cfg.AdminUser, s.cfg.AdminPass)(handler)
	}
	if s.cfg.SecurityHeadersEnabled {
		handler = securityHeaders(handler)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 3 * time.Second,
		MaxHeaderBytes:    8192,
	}

	go func() {
		s.logger.Info("admin server started", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("admin server error", "error", err)
		}
	}()

	return srv
}

func (s *ProxyServer) startMetricsServer(addr string) *http.Server {
	mux := http.NewServeMux()

	// Prometheus endpoint
	mux.Handle("/prometheus", promhttp.Handler())

	// Live stats API for charts
	mux.HandleFunc("/api/live", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"active_connections": s.activeConns.Load(),
			"total_connections":  s.totalConns.Load(),
			"auth_failures":     s.authFailures.Load(),
			"blocked_conns":     s.blockedConns.Load(),
			"uptime_seconds":    int(time.Since(s.startTime).Seconds()),
		})
	})

	mux.HandleFunc("/api/history/stats", func(w http.ResponseWriter, r *http.Request) {
		if s.store == nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("[]"))
			return
		}
		n := 120
		if v := r.URL.Query().Get("n"); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
				n = parsed
			}
		}
		history, err := s.store.GetStatsHistory(n)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(history)
	})

	mux.HandleFunc("/api/history/destinations", func(w http.ResponseWriter, r *http.Request) {
		if s.store == nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("[]"))
			return
		}
		n := 50
		if v := r.URL.Query().Get("n"); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
				n = parsed
			}
		}
		history, err := s.store.GetDestinationHistory(n)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(history)
	})

	mux.HandleFunc("/api/history/top-alltime", func(w http.ResponseWriter, r *http.Request) {
		if s.store == nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("{}"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.store.GetTopDestinationsAllTime(20))
	})

	// Serve Chart.js locally
	mux.HandleFunc("/chart.min.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/chart.min.js")
	})

	// Serve the dashboard at / and /metrics
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(metricsDashboard))
	})

	var handler http.Handler = mux

	if s.cfg.SecurityHeadersEnabled {
		handler = securityHeaders(handler)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 3 * time.Second,
		MaxHeaderBytes:    8192,
	}

	go func() {
		s.logger.Info("metrics dashboard started", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("metrics server error", "error", err)
		}
	}()

	return srv
}

// ─── Main ──────────────────────────────────────────────────────────────────

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	configFile := "config.json"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	cfg, err := LoadConfig(configFile)
	if err != nil {
		logger.Error("failed to load config", "error", err, "file", configFile)
		os.Exit(1)
	}

	// Initialize persistence store
	dbPath := "data/socks5.db"
	store, err := NewStore(dbPath, logger)
	if err != nil {
		logger.Error("failed to open database", "error", err, "path", dbPath)
		os.Exit(1)
	}
	defer store.Close()

	// Load persisted config overrides from DB
	if dbCfg := store.LoadConfig(); len(dbCfg) > 0 {
		if v, ok := dbCfg["max_connections"]; ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				cfg.MaxConns = n
			}
		}
		if v, ok := dbCfg["proxy_user"]; ok {
			cfg.Username = v
		}
		if v, ok := dbCfg["proxy_pass"]; ok {
			cfg.Password = v
		}
		if v, ok := dbCfg["auth_enabled"]; ok {
			cfg.AuthEnabled = v == "true"
		}
		if v, ok := dbCfg["admin_auth_enabled"]; ok {
			cfg.AdminEnabled = v == "true"
		}
		if v, ok := dbCfg["admin_username"]; ok {
			cfg.AdminUser = v
		}
		if v, ok := dbCfg["admin_pass"]; ok {
			cfg.AdminPass = v
		}
		if v, ok := dbCfg["security_headers_enabled"]; ok {
			cfg.SecurityHeadersEnabled = v == "true"
		}
		if v, ok := dbCfg["rate_limit_enabled"]; ok {
			cfg.RateLimitEnabled = v == "true"
		}
		if v, ok := dbCfg["rate_limit_rps"]; ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				cfg.RateLimitRPS = n
			}
		}
		logger.Info("loaded config overrides from database")
	}

	server := NewProxyServer(cfg)
	server.store = store

	adminAddr := fmt.Sprintf(":%d", cfg.AdminPort)
	adminSrv := server.startAdminServer(adminAddr)

	metricsAddr := fmt.Sprintf(":%d", cfg.MetricsPort)
	metricsSrv := server.startMetricsServer(metricsAddr)

	proxyAddr := fmt.Sprintf(":%d", cfg.ProxyPort)
	listener, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		logger.Error("failed to start proxy listener", "error", err)
		os.Exit(1)
	}
	defer listener.Close()

	// Periodic stats persistence (every 60 seconds)
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				server.destMu.RLock()
				dests := make(map[string]int64, len(server.dests))
				for k, v := range server.dests {
					dests[k] = v
				}
				server.destMu.RUnlock()

				store.SaveStatsSnapshot(
					server.activeConns.Load(),
					server.totalConns.Load(),
					server.authFailures.Load(),
					server.blockedConns.Load(),
				)
				store.SaveDestinations(dests)
			case <-server.shutdownCh:
				return
			}
		}
	}()

	// Cleanup old records weekly
	go func() {
		ticker := time.NewTicker(24 * time.Hour * 7)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := store.Cleanup(90); err != nil {
					logger.Warn("cleanup failed", "error", err)
				}
			case <-server.shutdownCh:
				return
			}
		}
	}()

	logger.Info("proxy server started",
		"proxy", proxyAddr,
		"admin", adminAddr,
		"metrics", metricsAddr,
		"auth", cfg.AuthEnabled,
		"admin_auth", cfg.AdminEnabled,
		"security_headers", cfg.SecurityHeadersEnabled,
		"rate_limit", cfg.RateLimitEnabled,
		"max_conns", cfg.MaxConns,
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-server.shutdownCh:
					return
				default:
					logger.Error("accept error", "error", err)
					time.Sleep(100 * time.Millisecond)
					continue
				}
			}

			// Check connection limit (read under lock for dynamic updates)
			server.configMu.RLock()
			maxConns := server.cfg.MaxConns
			server.configMu.RUnlock()
			if server.activeConns.Load() >= int64(maxConns) {
				logger.Warn("max connections reached, rejecting", "client", conn.RemoteAddr())
				conn.Close()
				continue
			}

			go server.handleClient(conn)
		}
	}()

	<-ctx.Done()
	logger.Info("shutdown signal received, draining connections...")

	listener.Close()
	close(server.shutdownCh)

	httpCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	adminSrv.Shutdown(httpCtx)
	metricsSrv.Shutdown(httpCtx)

	done := make(chan struct{})
	go func() {
		server.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("all connections drained")
	case <-time.After(10 * time.Second):
		logger.Warn("shutdown timeout, force closing connections")
		server.closeAllConns()
		server.wg.Wait()
	}

	// Save final stats before shutdown
	store.SaveStatsSnapshot(
		server.activeConns.Load(),
		server.totalConns.Load(),
		server.authFailures.Load(),
		server.blockedConns.Load(),
	)
	server.destMu.RLock()
	dests := make(map[string]int64, len(server.dests))
	for k, v := range server.dests {
		dests[k] = v
	}
	server.destMu.RUnlock()
	store.SaveDestinations(dests)

	logger.Info("proxy server stopped")
}

func parseInt64(s string) int64 {
	var n int64
	fmt.Sscanf(s, "%d", &n)
	return n
}

const metricsDashboard = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOCKS5 Proxy Metrics</title>
<script src="/chart.min.js"></script>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:#0a0a0f;color:#e0e0e0;font-family:'Courier New',monospace;overflow-x:hidden}
  .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;padding:20px;max-width:1600px;margin:0 auto}
  .card{background:linear-gradient(145deg,#12121a,#1a1a2e);border:1px solid #1e1e3a;border-radius:12px;padding:20px;position:relative;overflow:hidden}
  .card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,#00f0ff,transparent)}
  .card h3{font-size:11px;text-transform:uppercase;letter-spacing:2px;color:#555;margin-bottom:8px}
  .card .value{font-size:32px;font-weight:bold;background:linear-gradient(135deg,#00f0ff,#7b2dff);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
  .card .sub{font-size:11px;color:#444;margin-top:4px}
  .charts{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:0 20px 20px;max-width:1600px;margin:0 auto}
  .chart-box{background:linear-gradient(145deg,#12121a,#1a1a2e);border:1px solid #1e1e3a;border-radius:12px;padding:20px;position:relative;overflow:hidden;min-height:280px}
  .chart-box canvas{position:relative;width:100%!important;height:220px!important}
  .chart-box::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,#7b2dff,transparent)}
  .chart-box h2{font-size:12px;text-transform:uppercase;letter-spacing:3px;color:#555;margin-bottom:15px}
  .full-width{grid-column:1/-1}
  .bar-chart{display:flex;align-items:flex-end;gap:4px;height:220px;padding-top:10px}
  .bar{flex:1;background:linear-gradient(180deg,#00f0ff,#7b2dff);border-radius:4px 4px 0 0;min-width:20px;position:relative;transition:height 0.5s ease;cursor:pointer}
  .bar:hover{opacity:0.8}
  .bar .label{position:absolute;bottom:-20px;left:50%;transform:translateX(-50%);font-size:8px;color:#555;white-space:nowrap;max-width:60px;overflow:hidden;text-overflow:ellipsis}
  .bar .tip{position:absolute;top:-25px;left:50%;transform:translateX(-50%);background:#1e1e3a;color:#00f0ff;padding:2px 6px;border-radius:4px;font-size:10px;white-space:nowrap;opacity:0;transition:opacity 0.2s}
  .bar:hover .tip{opacity:1}
  .timeline{display:flex;gap:1px;height:60px;align-items:flex-end}
  .tick{flex:1;background:#00f0ff;border-radius:1px;min-height:2px;transition:height 0.3s;opacity:0.7}
  .header{padding:20px;text-align:center;border-bottom:1px solid #1e1e3a}
  .header h1{font-size:14px;letter-spacing:8px;text-transform:uppercase;background:linear-gradient(135deg,#00f0ff,#7b2dff);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
  .header .pulse{display:inline-block;width:8px;height:8px;background:#00f0ff;border-radius:50%;margin-right:10px;animation:pulse 2s infinite}
  @keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 10px #00f0ff}50%{opacity:0.5;box-shadow:0 0 5px #00f0ff}}
  .glow{animation:glow 3s ease-in-out infinite alternate}
  @keyframes glow{from{text-shadow:0 0 5px #00f0ff}to{text-shadow:0 0 20px #00f0ff,0 0 40px #7b2dff}}
  canvas{width:100%!important;height:220px!important}
  @media(max-width:900px){.grid{grid-template-columns:1fr 1fr}.charts{grid-template-columns:1fr}}
  @media(max-width:500px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="header">
  <h1><span class="pulse"></span>SOCKS5 Proxy Metrics</h1>
</div>

<div class="grid">
  <div class="card"><h3>Active Connections</h3><div class="value" id="v-active">0</div><div class="sub" id="v-active-sub">current</div></div>
  <div class="card"><h3>Total Connections</h3><div class="value" id="v-total">0</div><div class="sub" id="v-total-sub">all time</div></div>
  <div class="card"><h3>Auth Failures</h3><div class="value" id="v-auth">0</div><div class="sub" id="v-auth-sub">attempts</div></div>
  <div class="card"><h3>Blocked IPs</h3><div class="value" id="v-blocked">0</div><div class="sub" id="v-blocked-sub">rejected</div></div>
</div>

<div class="grid">
  <div class="card" style="grid-column:1/-1"><h3>Connection Activity (last 60s)</h3>
    <div class="timeline" id="timeline"></div>
  </div>
</div>

<div class="charts">
  <div class="chart-box"><h2>Connections Over Time</h2><canvas id="chart-connections"></canvas></div>
  <div class="chart-box"><h2>Top Destinations</h2><canvas id="chart-destinations"></canvas></div>
  <div class="chart-box"><h2>Auth Failures</h2><canvas id="chart-auth"></canvas></div>
  <div class="chart-box"><h2>Blocked Connections</h2><canvas id="chart-blocked"></canvas></div>
</div>

<div class="charts">
  <div class="chart-box full-width"><h2>Destination Heatmap</h2>
    <div class="bar-chart" id="heatmap"></div>
  </div>
</div>

<script>
var timelineData=[];
for(var i=0;i<60;i++)timelineData.push(0);

var chartOpts={responsive:true,maintainAspectRatio:false,animation:{duration:300},plugins:{legend:{display:false}},scales:{x:{display:false},y:{beginAtZero:true,grid:{color:'#1e1e3a'},ticks:{color:'#444',font:{family:'Courier New',size:10}}}}};

var ctxConn=document.getElementById('chart-connections').getContext('2d');
var chartConn=new Chart(ctxConn,{type:'line',data:{labels:[],datasets:[{label:'Active',data:[],borderColor:'#00f0ff',backgroundColor:'rgba(0,240,255,0.1)',fill:true,tension:0.4,pointRadius:0,borderWidth:2},{label:'Total',data:[],borderColor:'#7b2dff',backgroundColor:'rgba(123,45,255,0.1)',fill:true,tension:0.4,pointRadius:0,borderWidth:2}]},options:{...chartOpts,plugins:{legend:{display:true,labels:{color:'#555',font:{family:'Courier New',size:10}}}}}});

var ctxDest=document.getElementById('chart-destinations').getContext('2d');
var chartDest=new Chart(ctxDest,{type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:['#00f0ff','#7b2dff','#ff006e','#ffbe0b','#00f5d4','#fee440','#f15bb5','#9b5de5']}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'right',labels:{color:'#555',font:{family:'Courier New',size:10},boxWidth:12,padding:8}}}}});

var ctxAuth=document.getElementById('chart-auth').getContext('2d');
var chartAuth=new Chart(ctxAuth,{type:'bar',data:{labels:[],datasets:[{data:[],backgroundColor:'rgba(255,0,110,0.6)',borderColor:'#ff006e',borderWidth:1,borderRadius:4}]},options:chartOpts});

var ctxBlocked=document.getElementById('chart-blocked').getContext('2d');
var chartBlocked=new Chart(ctxBlocked,{type:'bar',data:{labels:[],datasets:[{data:[],backgroundColor:'rgba(255,190,11,0.6)',borderColor:'#ffbe0b',borderWidth:1,borderRadius:4}]},options:chartOpts});

function renderTimeline(){
  var el=document.getElementById('timeline');
  el.innerHTML='';
  var max=Math.max.apply(null,timelineData)||1;
  for(var i=0;i<timelineData.length;i++){
    var d=document.createElement('div');
    d.className='tick';
    d.style.height=Math.max(2,(timelineData[i]/max)*100)+'%';
    el.appendChild(d);
  }
}

function renderHeatmap(data){
  var el=document.getElementById('heatmap');
  el.innerHTML='';
  if(!data)return;
  var entries=Object.entries(data).sort(function(a,b){return b[1]-a[1]}).slice(0,20);
  if(entries.length===0)return;
  var max=entries[0][1]||1;
  for(var i=0;i<entries.length;i++){
    var h=Math.max(10,(entries[i][1]/max)*100);
    var bar=document.createElement('div');
    bar.className='bar';
    bar.style.height=h+'%';
    bar.innerHTML='<div class="tip">'+entries[i][0]+': '+entries[i][1]+'</div><div class="label">'+entries[i][0]+'</div>';
    el.appendChild(bar);
  }
}

function updateCharts(history){
  if(!history||history.length===0)return;
  var labels=[];var active=[];var total=[];
  for(var i=history.length-1;i>=0;i--){
    var t=new Date(history[i].recorded_at);
    labels.push(t.getHours()+':'+String(t.getMinutes()).padStart(2,'0'));
    active.push(history[i].active_connections);
    total.push(history[i].total_connections);
  }
  chartConn.data.labels=labels;
  chartConn.data.datasets[0].data=active;
  chartConn.data.datasets[1].data=total;
  chartConn.update('none');

  var authLabels=[];var authData=[];
  var blLabels=[];var blData=[];
  for(var i=Math.max(0,history.length-20);i<history.length;i++){
    var t=new Date(history[i].recorded_at);
    var l=t.getHours()+':'+String(t.getMinutes()).padStart(2,'0');
    authLabels.push(l);authData.push(history[i].auth_failures);
    blLabels.push(l);blData.push(history[i].blocked_connections);
  }
  chartAuth.data.labels=authLabels;
  chartAuth.data.datasets[0].data=authData;
  chartAuth.update('none');
  chartBlocked.data.labels=blLabels;
  chartBlocked.data.datasets[0].data=blData;
  chartBlocked.update('none');
}

function animateValue(el,end){
  var start=parseInt(el.textContent)||0;
  if(start===end)return;
  var diff=end-start;
  var steps=20;
  var step=0;
  var timer=setInterval(function(){
    step++;
    el.textContent=Math.round(start+diff*(step/steps));
    if(step>=steps)clearInterval(timer);
  },15);
}

var prevActive=0;var prevTotal=0;var prevAuth=0;var prevBlocked=0;

async function poll(){
  try{
    var r=await fetch('/api/live');
    var d=await r.json();
    var a=d.active_connections||0;
    var t=d.total_connections||0;
    var af=d.auth_failures||0;
    var bl=d.blocked_conns||0;
    animateValue(document.getElementById('v-active'),a);
    animateValue(document.getElementById('v-total'),t);
    animateValue(document.getElementById('v-auth'),af);
    animateValue(document.getElementById('v-blocked'),bl);
    if(a!==prevActive){
      document.getElementById('v-active-sub').textContent=a>prevActive?'+'+(a-prevActive)+' now':'-'+(prevActive-a)+' now';
      prevActive=a;
    }
    timelineData.push(a);
    if(timelineData.length>60)timelineData.shift();
    renderTimeline();
  }catch(e){}
}

async function pollHistory(){
  try{
    var r=await fetch('/api/history/stats?n=120');
    var d=await r.json();
    updateCharts(d);
  }catch(e){}
  try{
    var r=await fetch('/api/history/top-alltime');
    var d=await r.json();
    renderHeatmap(d);
    if(d){
      var entries=Object.entries(d).sort(function(a,b){return b[1]-a[1]}).slice(0,8);
      chartDest.data.labels=entries.map(function(e){return e[0]});
      chartDest.data.datasets[0].data=entries.map(function(e){return e[1]});
      chartDest.update('none');
    }
  }catch(e){}
}

renderTimeline();
poll();
pollHistory();
setInterval(poll,2000);
setInterval(pollHistory,10000);
</script>
</body>
</html>`

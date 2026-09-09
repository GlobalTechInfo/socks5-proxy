package main

import (
	"context"
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
}

func DefaultConfig() Config {
	return Config{
		ProxyPort:    1080,
		AdminPort:    8080,
		MetricsPort:  9090,
		MaxConns:     1000,
		AuthEnabled:  true,
		ReadTimeout:  30,
		WriteTimeout: 30,
		IdleTimeout:  120,
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

	// Environment variables override config file (required for Koyeb/PaaS)
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

var replyText = map[byte]string{
	replySucceeded:          "succeeded",
	replyGeneralFailure:     "general SOCKS server failure",
	replyConnNotAllowed:     "connection not allowed by ruleset",
	replyNetworkUnreachable: "network unreachable",
	replyHostUnreachable:    "host unreachable",
	replyConnRefused:        "connection refused",
	replyTTLExpired:         "TTL expired",
	replyCmdNotSupported:    "command not supported",
	replyAddrNotSupported:   "address type not supported",
}

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
	ActiveConns   int64             `json:"active_connections"`
	TotalConns    int64             `json:"total_connections"`
	AuthFailures  int64             `json:"auth_failures"`
	BlockedConns  int64             `json:"blocked_connections"`
	TopDestinations map[string]int64 `json:"top_destinations"`
	Uptime        string            `json:"uptime"`
	Version       string            `json:"version"`
}

type ProxyServer struct {
	cfg          Config
	logger       *slog.Logger
	startTime    time.Time
	activeConns  atomic.Int64
	totalConns   atomic.Int64
	authFailures atomic.Int64
	blockedConns atomic.Int64

	// Destination tracking
	destMu   sync.RWMutex
	dests    map[string]int64

	// IP-based rate limiting / blocking
	ipMu   sync.RWMutex
	ipConns map[string]int64

	// Connection tracking for graceful shutdown
	connMu   sync.Mutex
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup

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
		ipConns:   make(map[string]int64),
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
	s.ipMu.RLock()
	defer s.ipMu.RUnlock()

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

	// Check IP whitelist/blacklist BEFORE reading anything
	if !s.isAllowedIP(clientIP) {
		s.blockedConns.Add(1)
		metricBlockedConns.WithLabelValues(clientIP).Inc()
		log.Warn("blocked IP")
		// Still need to read the client greeting before responding
		// to avoid confusing the client
		buf := make([]byte, 2)
		conn.Read(buf) // ignore result
		conn.SetWriteDeadline(time.Now().Add(time.Duration(s.cfg.WriteTimeout) * time.Second))
		conn.Write([]byte{socksVersion, methodNoAcceptable})
		return
	}

	// Set initial read deadline for handshake
	conn.SetReadDeadline(time.Now().Add(time.Duration(s.cfg.ReadTimeout) * time.Second))

	// Step 1: Method negotiation (RFC 1928 Section 3)
	method, err := s.negotiateMethod(conn)
	if err != nil {
		log.Error("method negotiation failed", "error", err)
		metricConnErrors.WithLabelValues("method_negotiation").Inc()
		return
	}

	// Step 2: Authentication (RFC 1929) if required
	if method == methodUserPassword {
		if err := s.authenticate(conn); err != nil {
			s.authFailures.Add(1)
			metricAuthFailures.Inc()
			log.Error("authentication failed", "error", err)
			return
		}
	} else if method != methodNoAuth {
		// Client chose a method we don't support
		conn.SetWriteDeadline(time.Now().Add(time.Duration(s.cfg.WriteTimeout) * time.Second))
		conn.Write([]byte{socksVersion, methodNoAcceptable})
		return
	}

	// Step 3: Read CONNECT request
	conn.SetReadDeadline(time.Now().Add(time.Duration(s.cfg.ReadTimeout) * time.Second))
	target, err := s.readRequest(conn)
	if err != nil {
		log.Error("request read failed", "error", err)
		metricConnErrors.WithLabelValues("request_read").Inc()
		return
	}

	log = log.With("target", target)
	log.Info("connecting to target")

	// Step 4: Connect to target
	conn.SetReadDeadline(time.Now().Add(time.Duration(s.cfg.IdleTimeout) * time.Second))
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Error("target connection failed", "error", err)
		s.sendReply(conn, replyConnRefused)
		metricConnErrors.WithLabelValues("target_connect").Inc()
		return
	}
	defer targetConn.Close()

	// Step 5: Send success reply
	if err := s.sendReply(conn, replySucceeded); err != nil {
		log.Error("reply send failed", "error", err)
		return
	}

	// Step 6: Relay data
	s.relay(conn, targetConn, log, target)
}

func (s *ProxyServer) negotiateMethod(conn net.Conn) (byte, error) {
	// Read client greeting: VER | NMETHODS | METHODS[1..NMETHODS]
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

	// Select best method: prefer auth if enabled, otherwise no-auth
	var selected byte = methodNoAcceptable
	for _, m := range methods {
		switch m {
		case methodNoAuth:
			if !s.cfg.AuthEnabled {
				selected = methodNoAuth
			} else if selected == methodNoAcceptable {
				selected = methodNoAcceptable // keep looking
			}
		case methodUserPassword:
			if s.cfg.AuthEnabled {
				selected = methodUserPassword
				break // best match, stop searching
			}
		}
	}

	// Send method selection response: VER | METHOD
	conn.SetWriteDeadline(time.Now().Add(time.Duration(s.cfg.WriteTimeout) * time.Second))
	if _, err := conn.Write([]byte{socksVersion, selected}); err != nil {
		return 0, fmt.Errorf("write method response: %w", err)
	}

	return selected, nil
}

func (s *ProxyServer) authenticate(conn net.Conn) error {
	// RFC 1929: Read auth subnegotiation
	// Client sends: VER(1) | ULEN(1) | USERNAME(ULEN) | PLEN(1) | PASSWORD(PLEN)

	// Read VER and ULEN
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("read auth header: %w", err)
	}

	if buf[0] != socksAuthVersion {
		return fmt.Errorf("unsupported auth version: %d", buf[0])
	}

	usernameLen := int(buf[1])
	if usernameLen == 0 || usernameLen > 255 {
		return fmt.Errorf("invalid username length: %d", usernameLen)
	}

	// Read username
	username := make([]byte, usernameLen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return fmt.Errorf("read username: %w", err)
	}

	// Read password length
	passLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLenBuf); err != nil {
		return fmt.Errorf("read password length: %w", err)
	}

	passwordLen := int(passLenBuf[0])
	if passwordLen > 255 {
		return fmt.Errorf("invalid password length: %d", passwordLen)
	}

	// Read password
	password := make([]byte, passwordLen)
	if _, err := io.ReadFull(conn, password); err != nil {
		return fmt.Errorf("read password: %w", err)
	}

	// Validate credentials
	authOK := string(username) == s.cfg.Username && string(password) == s.cfg.Password

	// Send auth response: VER(1) | STATUS(1)
	conn.SetWriteDeadline(time.Now().Add(time.Duration(s.cfg.WriteTimeout) * time.Second))
	if authOK {
		if _, err := conn.Write([]byte{socksAuthVersion, authStatusSuccess}); err != nil {
			return fmt.Errorf("write auth success: %w", err)
		}
		return nil
	}

	if _, err := conn.Write([]byte{socksAuthVersion, authStatusFailure}); err != nil {
		return fmt.Errorf("write auth failure: %w", err)
	}
	return errors.New("invalid credentials")
}

func (s *ProxyServer) readRequest(conn net.Conn) (string, error) {
	// Read request header: VER | CMD | RSV | ATYP
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("read request header: %w", err)
	}

	if header[0] != socksVersion {
		return "", fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}
	if header[1] != cmdConnect {
		s.sendReply(conn, replyCmdNotSupported)
		return "", fmt.Errorf("unsupported command: %d", header[1])
	}

	// Read address based on type
	var host string
	var port uint16

	switch header[3] {
	case addrTypeIPv4:
		addr := make([]byte, 6) // 4 bytes IP + 2 bytes port
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
		addr := make([]byte, 18) // 16 bytes IP + 2 bytes port
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("read IPv6 addr: %w", err)
		}
		host = net.IP(addr[:16]).String()
		port = binary.BigEndian.Uint16(addr[16:18])

	default:
		s.sendReply(conn, replyAddrNotSupported)
		return "", fmt.Errorf("unsupported address type: %d", header[3])
	}

	return fmt.Sprintf("%s:%d", host, port), nil
}

func (s *ProxyServer) sendReply(conn net.Conn, reply byte) error {
	conn.SetWriteDeadline(time.Now().Add(time.Duration(s.cfg.WriteTimeout) * time.Second))
	// Reply: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
	resp := []byte{
		socksVersion, reply, 0x00, // VER, REP, RSV
		addrTypeIPv4, 0, 0, 0, 0, // ATYP=IPv4, BND.ADDR=0.0.0.0
		0, 0, // BND.PORT=0
	}
	_, err := conn.Write(resp)
	return err
}

func (s *ProxyServer) relay(client, target net.Conn, log *slog.Logger, targetAddr string) {
	// Update counters
	s.activeConns.Add(1)
	s.totalConns.Add(1)
	metricActiveConns.Inc()
	metricTotalConns.Inc()
	s.recordDestination(targetAddr)

	startTime := time.Now()

	// Set idle timeout for data relay phase
	client.SetReadDeadline(time.Now().Add(time.Duration(s.cfg.IdleTimeout) * time.Second))
	target.SetReadDeadline(time.Now().Add(time.Duration(s.cfg.IdleTimeout) * time.Second))

	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Target
	go func() {
		defer wg.Done()
		_, err := io.Copy(target, client)
		if err != nil && !isClosedConnError(err) {
			log.Debug("client->target copy error", "error", err)
		}
		target.SetReadDeadline(time.Now()) // unblock other goroutine
	}()

	// Target -> Client
	go func() {
		defer wg.Done()
		_, err := io.Copy(client, target)
		if err != nil && !isClosedConnError(err) {
			log.Debug("target->client copy error", "error", err)
		}
		client.SetReadDeadline(time.Now()) // unblock other goroutine
	}()

	wg.Wait()

	// Update metrics
	duration := time.Since(startTime).Seconds()
	metricConnDuration.Observe(duration)
	metricActiveConns.Dec()
	s.activeConns.Add(-1)

	log.Info("connection closed", "duration", time.Since(startTime).Truncate(time.Millisecond))
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

// ─── HTTP Servers (Admin + Metrics) ────────────────────────────────────────

func (s *ProxyServer) startAdminServer(addr string) *http.Server {
	mux := http.NewServeMux()

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
		n := 10
		if v := r.URL.Query().Get("n"); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
				n = parsed
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.getTopDestinations(n))
	})

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
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
	mux.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	go func() {
		s.logger.Info("metrics server started", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("metrics server error", "error", err)
		}
	}()

	return srv
}

// ─── Main ──────────────────────────────────────────────────────────────────

func main() {
	// Structured logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Load config
	configFile := "config.json"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	cfg, err := LoadConfig(configFile)
	if err != nil {
		logger.Error("failed to load config", "error", err, "file", configFile)
		os.Exit(1)
	}

	server := NewProxyServer(cfg)

	// Start admin server
	adminAddr := fmt.Sprintf(":%d", cfg.AdminPort)
	adminSrv := server.startAdminServer(adminAddr)

	// Start metrics server
	metricsAddr := fmt.Sprintf(":%d", cfg.MetricsPort)
	metricsSrv := server.startMetricsServer(metricsAddr)

	// Start proxy listener
	proxyAddr := fmt.Sprintf(":%d", cfg.ProxyPort)
	listener, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		logger.Error("failed to start proxy listener", "error", err)
		os.Exit(1)
	}
	defer listener.Close()

	logger.Info("proxy server started",
		"proxy", proxyAddr,
		"admin", adminAddr,
		"metrics", metricsAddr,
		"auth", cfg.AuthEnabled,
		"max_conns", cfg.MaxConns,
	)

	// Graceful shutdown handling
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Accept loop in goroutine
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				// Check if we're shutting down
				select {
				case <-server.shutdownCh:
					return
				default:
					logger.Error("accept error", "error", err)
					time.Sleep(100 * time.Millisecond)
					continue
				}
			}

			// Check connection limit
			if server.activeConns.Load() >= int64(cfg.MaxConns) {
				logger.Warn("max connections reached, rejecting", "client", conn.RemoteAddr())
				conn.Close()
				continue
			}

			go server.handleClient(conn)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()
	logger.Info("shutdown signal received, draining connections...")

	// Close listener to stop accepting new connections
	listener.Close()
	close(server.shutdownCh)

	// Shutdown HTTP servers with timeout
	httpCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	adminSrv.Shutdown(httpCtx)
	metricsSrv.Shutdown(httpCtx)

	// Wait for existing connections to finish (with timeout)
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

	logger.Info("proxy server stopped")
}

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ─── REALITY (Xray) ────────────────────────────────────────────────────────
//
// REALITY is an Xray transport that is indistinguishable from a real website.
// The server presents the certificate of a target site, forwarding every
// unauthenticated connection to it, so an active prober sees a live website and
// not a proxy. Clients that authenticate are equally invisible: same
// certificate, same handshake, same site.
//
// It cannot be implemented inside this binary. It needs uTLS (a fork of
// crypto/tls) plus certificate relay and X25519 authentication, and hand-
// rolling that is how you ship broken crypto. So the real xray binary is
// supervised as a child process, which also means no new Go dependency.
//
// This service stays the brain. Xray terminates VLESS+REALITY and forwards
// every session to the SOCKS5 port here, so users, tiers, rate limits, metrics
// and destination statistics behave identically no matter which door a
// session arrived through. Competing with xray-core as a library instead would
// mean ~100 modules and a large dependency tree, so the child process wins on
// every axis that matters: correctness, binary size, CGO-free builds.
//
// One hard constraint: this needs a dedicated IP with raw TCP to it. Behind a
// shared CDN edge the TLS handshake terminates at the edge, so a REALITY client
// never reaches this process at all. Use the WebSocket tunnel on CDN-fronted
// PaaS platforms.

const (
	realityInboundTag        = "reality-in"
	realitySocksTag          = "proxy"
	realityDirectTag         = "direct"
	realityClientTag         = "socks-in"
	defaultRealityBind       = "0.0.0.0:443"
	defaultRealityDest       = "www.lovelive-anime.jp:443"
	defaultRealityClientFile = "reality-client.json"

	// DB keys for values generated once and reused afterwards. A REALITY key
	// that changes on every restart would silently break every saved client
	// profile, so the generated pair is persisted.
	dbRealityPrivateKey = "reality_private_key"
	dbRealityShortID    = "reality_short_id"
	dbRealityClientIDs  = "reality_client_ids"
)

// realityKeys is everything both the server and the client config need.
type realityKeys struct {
	PrivateKey string
	PublicKey  string
	ShortID    string
	ClientIDs  []string
	ServerName string
}

// ─── Config rendering ───────────────────────────────────────────────────────
//
// Typed structs rather than string templates: a malformed field then fails to
// compile or marshal instead of producing a config xray rejects at runtime.

type realityServerConfig struct {
	Log struct {
		LogLevel string `json:"loglevel"`
	} `json:"log"`
	Inbounds  []realityInbound     `json:"inbounds"`
	Outbounds []realityOutbound    `json:"outbounds"`
	Routing   realityRoutingConfig `json:"routing"`
}

type realityRoutingConfig struct {
	Rules []realityRoutingRule `json:"rules"`
}

type realityRoutingRule struct {
	Type        string   `json:"type"`
	InboundTag  []string `json:"inboundTag"`
	OutboundTag string   `json:"outboundTag"`
}

type realityInbound struct {
	Tag            string                 `json:"tag"`
	Listen         string                 `json:"listen"`
	Port           int                    `json:"port"`
	Protocol       string                 `json:"protocol"`
	Settings       realityInboundSettings `json:"settings"`
	StreamSettings realityServerStream    `json:"streamSettings"`
}

type realityInboundSettings struct {
	Clients    []realityClient `json:"clients"`
	Decryption string          `json:"decryption"`
}

type realityClient struct {
	ID    string `json:"id"`
	Email string `json:"email,omitempty"`
}

type realityServerStream struct {
	Network         string                  `json:"network"`
	Security        string                  `json:"security"`
	RealitySettings realityServerRealityCfg `json:"realitySettings"`
}

type realityServerRealityCfg struct {
	Dest        string   `json:"dest"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIds    []string `json:"shortIds"`
}

type realityOutbound struct {
	Tag      string                   `json:"tag"`
	Protocol string                   `json:"protocol"`
	Settings *realityOutboundSettings `json:"settings,omitempty"`
}

type realityOutboundSettings struct {
	Servers []realitySocksServer `json:"servers"`
}

type realitySocksServer struct {
	Address string        `json:"address"`
	Port    int           `json:"port"`
	Users   []realityUser `json:"users,omitempty"`
}

type realityUser struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type realityClientConfig struct {
	Log struct {
		LogLevel string `json:"loglevel"`
	} `json:"log"`
	Inbounds  []realitySocksInbound `json:"inbounds"`
	Outbounds []realityVLESSPtr     `json:"outbounds"`
}

type realitySocksInbound struct {
	Tag      string                    `json:"tag"`
	Listen   string                    `json:"listen"`
	Port     int                       `json:"port"`
	Protocol string                    `json:"protocol"`
	Settings realitySocksInboundConfig `json:"settings"`
}

type realitySocksInboundConfig struct {
	Auth string `json:"auth"`
	UDP  bool   `json:"udp"`
}

type realityVLESSPtr struct {
	Protocol       string                   `json:"protocol"`
	Settings       realityClientOutboundCfg `json:"settings"`
	StreamSettings realityClientStreamCfg   `json:"streamSettings"`
}

type realityClientOutboundCfg struct {
	Vnext []realityVnextServer `json:"vnext"`
}

type realityVnextServer struct {
	Address string               `json:"address"`
	Port    int                  `json:"port"`
	Users   []realityVLESSPerson `json:"users"`
}

type realityVLESSPerson struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
}

type realityClientStreamCfg struct {
	Network         string                  `json:"network"`
	Security        string                  `json:"security"`
	RealitySettings realityClientRealityCfg `json:"realitySettings"`
}

type realityClientRealityCfg struct {
	Fingerprint string `json:"fingerprint"`
	ServerName  string `json:"serverName"`
	PublicKey   string `json:"publicKey"`
	ShortId     string `json:"shortId"`
	SpiderX     string `json:"spiderX"`
}

// renderRealityServerConfig builds the xray config this service runs as a child
// process: VLESS+REALITY in, SOCKS5 out, straight back into this proxy.
func renderRealityServerConfig(cfg Config, k realityKeys) ([]byte, error) {
	host, port, err := splitHostPort(cfg.RealityBind)
	if err != nil {
		return nil, fmt.Errorf("reality_bind: %w", err)
	}

	out := realityServerConfig{}
	out.Log.LogLevel = "warning"

	clients := make([]realityClient, 0, len(k.ClientIDs))
	for _, id := range k.ClientIDs {
		clients = append(clients, realityClient{ID: id})
	}

	inbound := realityInbound{
		Tag:      realityInboundTag,
		Listen:   host,
		Port:     port,
		Protocol: "vless",
		Settings: realityInboundSettings{
			Clients: clients,
			// VLESS carries no transport encryption of its own; REALITY does.
			Decryption: "none",
		},
		StreamSettings: realityServerStream{
			// "raw" is the current name for what older releases called "tcp".
			Network:  "raw",
			Security: "reality",
			RealitySettings: realityServerRealityCfg{
				Dest:        cfg.RealityDest,
				ServerNames: realityServerNames(cfg, k),
				PrivateKey:  k.PrivateKey,
				ShortIds:    []string{k.ShortID},
			},
		},
	}
	out.Inbounds = []realityInbound{inbound}

	// Every REALITY session is handed to this proxy's SOCKS5 port, so user
	// management, tiers and rate limits still apply. It is a child process on
	// the same host, so loopback is always the right address.
	socksOut := realityOutbound{
		Tag:      realitySocksTag,
		Protocol: "socks",
		Settings: &realityOutboundSettings{
			Servers: []realitySocksServer{{
				Address: "127.0.0.1",
				Port:    cfg.ProxyPort,
			}},
		},
	}
	if cfg.AuthEnabled && cfg.Username != "" {
		socksOut.Settings.Servers[0].Users = []realityUser{{User: cfg.Username, Pass: cfg.Password}}
	}

	out.Outbounds = []realityOutbound{
		socksOut,
		{Tag: realityDirectTag, Protocol: "freedom"},
	}
	out.Routing = realityRoutingConfig{
		Rules: []realityRoutingRule{{
			Type:        "field",
			InboundTag:  []string{realityInboundTag},
			OutboundTag: realitySocksTag,
		}},
	}

	return json.MarshalIndent(out, "", "  ")
}

// realityServerNames is the SNI list REALITY will impersonate. It defaults to
// the camouflage host itself, which is the only value guaranteed to match the
// certificate it serves.
func realityServerNames(cfg Config, k realityKeys) []string {
	if len(cfg.RealityServerNames) > 0 {
		return cfg.RealityServerNames
	}
	if k.ServerName != "" {
		return []string{k.ServerName}
	}
	if host, _, err := splitHostPort(cfg.RealityDest); err == nil {
		return []string{host}
	}
	return nil
}

// renderRealityClientConfig builds the matching client config: a local SOCKS5
// port that exits over REALITY. This is the config a phone or laptop runs, so
// nothing but Xray is needed on the client side.
func renderRealityClientConfig(address string, port int, listen string, listenPort int, k realityKeys) ([]byte, error) {
	if len(k.ClientIDs) == 0 {
		return nil, errors.New("no VLESS client id available")
	}
	out := realityClientConfig{}
	out.Log.LogLevel = "warning"
	out.Inbounds = []realitySocksInbound{{
		Tag:      realityClientTag,
		Listen:   listen,
		Port:     listenPort,
		Protocol: "socks",
		Settings: realitySocksInboundConfig{Auth: "noauth", UDP: false},
	}}
	out.Outbounds = []realityVLESSPtr{{
		Protocol: "vless",
		Settings: realityClientOutboundCfg{
			Vnext: []realityVnextServer{{
				Address: address,
				Port:    port,
				Users:   []realityVLESSPerson{{ID: k.ClientIDs[0], Encryption: "none"}},
			}},
		},
		StreamSettings: realityClientStreamCfg{
			Network:  "raw",
			Security: "reality",
			RealitySettings: realityClientRealityCfg{
				// Chrome is the fingerprint the overwhelming majority of REALITY
				// clients present, so it is the least surprising choice.
				Fingerprint: "chrome",
				ServerName:  k.ServerName,
				PublicKey:   k.PublicKey,
				ShortId:     k.ShortID,
				SpiderX:     "/",
			},
		},
	}}
	return json.MarshalIndent(out, "", "  ")
}

func splitHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("%q is not host:port", addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("%q has no valid port", addr)
	}
	return host, port, nil
}

// ─── Key material ───────────────────────────────────────────────────────────

// runXray invokes the xray CLI and returns its combined output. The output is
// returned on failure too, because "address already in use" and friends only
// ever appear there.
func runXray(bin string, args ...string) (string, error) {
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("xray %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// parseX25519 reads `xray x25519` output by key name, not by position. The
// label has changed across releases ("Public key", then "Password
// (PublicKey)"), so matching the substring survives an xray upgrade where
// positional parsing would silently produce the wrong key.
func parseX25519(out string) (privateKey, publicKey string) {
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		// Releases have spelled these labels both "PrivateKey" and
		// "Private key", so compare without spaces.
		key = strings.ReplaceAll(key, " ", "")
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		switch {
		case strings.Contains(key, "privatekey"):
			privateKey = value
		case strings.Contains(key, "publickey"):
			publicKey = value
		}
	}
	return privateKey, publicKey
}

// resolveRealityKeys assembles the key material, generating and persisting
// whatever the operator did not supply. A REALITY key that changed on every
// restart would silently break every saved client profile, so the generated
// pair is stored and reused.
func resolveRealityKeys(cfg Config, persisted map[string]string, store *Store, logger *slog.Logger) (realityKeys, error) {
	bin := cfg.RealityXrayBin
	if bin == "" {
		bin = "xray"
	}

	keys := realityKeys{}

	// x25519 is deterministic from a private key, so one invocation covers both
	// cases: with -i it derives the public key from a key we already have,
	// without it, xray invents a pair.
	var out string
	var err error
	privateKey := firstNonEmpty(cfg.RealityPrivateKey, persisted[dbRealityPrivateKey])
	generatedKey := privateKey == ""
	if generatedKey {
		out, err = runXray(bin, "x25519")
	} else {
		out, err = runXray(bin, "x25519", "-i", privateKey)
	}
	if err != nil {
		return keys, err
	}
	foundPriv, foundPub := parseX25519(out)
	if privateKey == "" {
		privateKey = foundPriv
	}
	if privateKey == "" {
		return keys, errors.New("xray x25519 returned no private key")
	}
	if foundPub == "" {
		return keys, errors.New("xray x25519 returned no public key")
	}
	keys.PrivateKey = privateKey
	keys.PublicKey = foundPub
	if generatedKey {
		logger.Info("generated REALITY keypair", "hint", "set REALITY_PRIVATE_KEY to pin it, otherwise it is reused from the database")
	}

	keys.ShortID = firstNonEmpty(cfg.RealityShortIDs...)
	if keys.ShortID == "" {
		keys.ShortID = persisted[dbRealityShortID]
	}
	generatedShortID := keys.ShortID == ""
	if generatedShortID {
		raw := make([]byte, 8)
		if _, err := rand.Read(raw); err != nil {
			return keys, fmt.Errorf("generate short id: %w", err)
		}
		// REALITY short ids are hex, up to 16 characters.
		keys.ShortID = hex.EncodeToString(raw)
	}

	keys.ClientIDs = nonEmpty(cfg.RealityClientIDs)
	if len(keys.ClientIDs) == 0 && persisted[dbRealityClientIDs] != "" {
		keys.ClientIDs = splitList(persisted[dbRealityClientIDs])
	}
	generatedIDs := len(keys.ClientIDs) == 0
	if generatedIDs {
		out, err := runXray(bin, "uuid")
		if err != nil {
			return keys, err
		}
		if id := strings.TrimSpace(out); id != "" {
			keys.ClientIDs = []string{strings.Fields(id)[0]}
		}
		if len(keys.ClientIDs) == 0 {
			return keys, errors.New("xray uuid returned no id")
		}
	}

	if keys.ServerName = firstNonEmpty(cfg.RealityServerNames...); keys.ServerName == "" {
		// The camouflage host is the only SNI guaranteed to match the
		// certificate REALITY serves, so it is the default.
		if host, _, err := splitHostPort(cfg.RealityDest); err == nil {
			keys.ServerName = host
		}
	}

	if store != nil {
		if generatedKey {
			saveRealitySetting(store, logger, dbRealityPrivateKey, keys.PrivateKey)
		}
		if generatedShortID {
			saveRealitySetting(store, logger, dbRealityShortID, keys.ShortID)
		}
		if generatedIDs {
			saveRealitySetting(store, logger, dbRealityClientIDs, strings.Join(keys.ClientIDs, ","))
		}
	}

	return keys, nil
}

func saveRealitySetting(store *Store, logger *slog.Logger, key, value string) {
	if err := store.SaveConfig(key, value); err != nil {
		// Non-fatal: the value is still in use this run, it just will not
		// survive a restart.
		logger.Warn("could not persist REALITY setting; it will change on restart",
			"key", key, "error", err)
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func nonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func splitList(v string) []string {
	return nonEmpty(strings.Split(v, ","))
}

// ─── Supervision ────────────────────────────────────────────────────────────

// xrayLogWriter forwards a child's output to slog a line at a time. Xray logs
// one message per line, and splitting keeps the proxy's own log readable when
// the two are interleaved.
type xrayLogWriter struct {
	logger *slog.Logger
	mu     sync.Mutex
	buf    []byte
}

func (w *xrayLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		if line := strings.TrimSpace(string(w.buf[:i])); line != "" {
			w.logger.Info("xray", "line", line)
		}
		w.buf = w.buf[i+1:]
	}
	return len(p), nil
}

// pruneStaleRealityConfigs deletes config files left behind by a process that
// was killed rather than shut down. Each one holds the REALITY private key and
// the proxy credentials, so leaving them in /tmp forever is not acceptable; the
// age cutoff keeps this from deleting the config of a second instance that is
// still running on the same host.
func pruneStaleRealityConfigs(maxAge time.Duration) {
	matches, err := filepath.Glob("xray-reality-*.json") //nolint:gosec // os.CreateTemp, not a pattern from input
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for _, path := range matches {
		if info, err := os.Stat(path); err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(path)
		}
	}
}

// realityRunner owns the xray child process.
type realityRunner struct {
	bin     string
	cfgFile string
	logger  *slog.Logger

	mu      sync.Mutex
	cmd     *exec.Cmd
	stopped bool

	stop   chan struct{}
	exited chan struct{}
}

// startReality validates the rendered config before serving, so a broken setup
// fails loudly at startup instead of leaving a silent dead front door.
func startReality(cfg Config, k realityKeys, logger *slog.Logger) (*realityRunner, error) {
	data, err := renderRealityServerConfig(cfg, k)
	if err != nil {
		return nil, err
	}

	file, err := os.CreateTemp("", "xray-reality-*.json")
	if err != nil {
		return nil, fmt.Errorf("write xray config: %w", err)
	}
	cfgFile := file.Name()
	if _, err := file.Write(data); err != nil {
		file.Close()
		os.Remove(cfgFile)
		return nil, fmt.Errorf("write xray config: %w", err)
	}
	file.Close()
	// CreateTemp already opens 0600, which matters: the file holds the REALITY
	// private key and the proxy credentials.

	bin := cfg.RealityXrayBin
	if bin == "" {
		bin = "xray"
	}
	if _, err := runXray(bin, "run", "-c", cfgFile, "--test"); err != nil {
		// runXray already carries xray's own complaint, which is the part worth
		// reading ("failed to listen...", "invalid private key", and so on).
		os.Remove(cfgFile)
		return nil, err
	}

	pruneStaleRealityConfigs(24 * time.Hour)

	r := &realityRunner{
		bin:     bin,
		cfgFile: cfgFile,
		logger:  logger,
		stop:    make(chan struct{}),
		exited:  make(chan struct{}),
	}
	go r.supervise()

	if host, port, err := splitHostPort(cfg.RealityBind); err == nil {
		r.waitReady(host, port, 10*time.Second)
	}
	return r, nil
}

// waitReady logs whether the REALITY port started answering. A failure here is
// not fatal: xray may still be retrying, and its own log carries the reason.
func (r *realityRunner) waitReady(host string, port int, timeout time.Duration) {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", target, 300*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	r.logger.Warn("reality port is not answering yet; see the xray log lines above", "addr", target)
}

// supervise keeps xray alive. Without this a single crash would silently remove
// the front door while every dashboard still reported a healthy proxy.
func (r *realityRunner) supervise() {
	defer close(r.exited)

	delay := 5 * time.Second
	for {
		if r.isStopped() {
			return
		}

		w := &xrayLogWriter{logger: r.logger}
		cmd := exec.Command(r.bin, "run", "-c", r.cfgFile)
		cmd.Stdout, cmd.Stderr = w, w

		if err := cmd.Start(); err != nil {
			r.logger.Error("reality: cannot start xray", "error", err)
		} else {
			r.setCmd(cmd)
			waitErr := cmd.Wait()
			r.setCmd(nil)
			if r.isStopped() {
				return
			}
			r.logger.Error("reality: xray exited, restarting", "error", waitErr)
		}

		select {
		case <-time.After(delay):
		case <-r.stop:
			return
		}
		if delay < time.Minute {
			delay *= 2
			if delay > time.Minute {
				delay = time.Minute
			}
		}
	}
}

func (r *realityRunner) setCmd(cmd *exec.Cmd) {
	r.mu.Lock()
	r.cmd = cmd
	r.mu.Unlock()
}

func (r *realityRunner) isStopped() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stopped
}

// Stop asks xray to exit, then removes the config holding the private key.
func (r *realityRunner) Stop() {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	cmd := r.cmd
	r.mu.Unlock()
	close(r.stop)

	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-r.exited:
	case <-time.After(5 * time.Second):
		r.mu.Lock()
		cmd = r.cmd
		r.mu.Unlock()
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}
	_ = os.Remove(r.cfgFile)
}

// ─── Wiring ─────────────────────────────────────────────────────────────────

// startRealityForServer resolves keys, starts the child and writes the client
// config operators copy to their own devices.
func startRealityForServer(cfg Config, persisted map[string]string, store *Store, logger *slog.Logger) (*realityRunner, error) {
	if _, err := exec.LookPath(orDefault(cfg.RealityXrayBin, "xray")); err != nil {
		if _, statErr := os.Stat(orDefault(cfg.RealityXrayBin, "xray")); statErr != nil {
			return nil, fmt.Errorf("reality_enabled is set but the xray binary is missing: set XRAY_BIN or install it (Docker images ship it at /usr/local/bin/xray)")
		}
	}

	keys, err := resolveRealityKeys(cfg, persisted, store, logger)
	if err != nil {
		return nil, err
	}

	if _, port, err := splitHostPort(cfg.RealityBind); err == nil && port == cfg.SinglePort && cfg.SinglePort != 0 {
		logger.Warn("reality port and SINGLE_PORT are the same; xray will fail to bind", "port", port)
	}

	runner, err := startReality(cfg, keys, logger)
	if err != nil {
		return nil, err
	}

	address := cfg.RealityPublicHost
	if address == "" {
		// Better a visible placeholder than a config that silently points at
		// an unroutable address.
		address = "SERVER_IP"
	}
	_, port, err := splitHostPort(cfg.RealityBind)
	if err != nil {
		port = 443
	}
	clientFile := orDefault(cfg.RealityClientFile, defaultRealityClientFile)
	if data, err := renderRealityClientConfig(address, port, "127.0.0.1", 1081, keys); err == nil {
		if err := os.WriteFile(clientFile, data, 0o600); err != nil {
			logger.Warn("could not write client config", "path", clientFile, "error", err)
		} else {
			logger.Info("wrote REALITY client config", "path", clientFile,
				"edit", "replace SERVER_IP with this host's IP or domain, then run: xray run -c "+clientFile)
		}
	}

	logger.Info("reality enabled",
		"bind", cfg.RealityBind,
		"dest", cfg.RealityDest,
		"server_name", keys.ServerName,
		"public_key", keys.PublicKey,
		"short_id", keys.ShortID,
		"client_id", strings.Join(keys.ClientIDs, ","))
	return runner, nil
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// ─── reality-client subcommand ──────────────────────────────────────────────

// runRealityClient runs xray locally with the config the server wrote, so a
// machine that has no Xray app still gets a SOCKS5 port that exits over
// REALITY. It is a thin wrapper: everything it needs is in the file.
func runRealityClient(args []string) error {
	fs := flag.NewFlagSet("reality-client", flag.ContinueOnError)
	cfgFile := fs.String("config", defaultRealityClientFile, "client config written by the server")
	server := fs.String("server", "", "override the server address (host or host:port)")
	listen := fs.String("listen", "", "override the local SOCKS5 listen address (default 127.0.0.1:1081)")
	bin := fs.String("bin", "xray", "path to the xray binary")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}

	data, err := os.ReadFile(*cfgFile)
	if err != nil {
		return fmt.Errorf("read %s: %w", *cfgFile, err)
	}

	var cfg realityClientConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse %s: %w", *cfgFile, err)
	}
	if len(cfg.Outbounds) == 0 || len(cfg.Inbounds) == 0 {
		return fmt.Errorf("%s is not a REALITY client config", *cfgFile)
	}

	// Only rewrite when something actually changes. Running the operator's own
	// file as-is means no copy to leak if this process is killed, and any
	// hand-made edits in it survive.
	cfgPath := *cfgFile
	if *server != "" || *listen != "" {
		if *server != "" {
			vnext := cfg.Outbounds[0].Settings.Vnext
			if len(vnext) == 0 {
				return fmt.Errorf("%s has no vnext entry", *cfgFile)
			}
			host := *server
			port := vnext[0].Port
			if h, p, err := splitHostPort(*server); err == nil {
				host = h
				port = p
			}
			vnext[0].Address, vnext[0].Port = host, port
		}
		if *listen != "" {
			host, port, err := splitHostPort(*listen)
			if err != nil {
				return err
			}
			cfg.Inbounds[0].Listen, cfg.Inbounds[0].Port = host, port
		}

		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return err
		}
		tmp, err := os.CreateTemp("", "xray-client-*.json")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.Write(data); err != nil {
			tmp.Close()
			return err
		}
		tmp.Close()
		cfgPath = tmp.Name()
	}

	slog.Info("reality client started",
		"server", cfg.Outbounds[0].Settings.Vnext[0].Address,
		"listen", net.JoinHostPort(cfg.Inbounds[0].Listen, strconv.Itoa(cfg.Inbounds[0].Port)))

	cmd := exec.Command(orDefault(*bin, "xray"), "run", "-c", cfgPath)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

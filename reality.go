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
	"net/http"
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
	// Links are the clients that are billed to a SOCKS user, keyed by UUID.
	// Without one, a client's traffic lands on the shared credentials and no
	// tier applies to it.
	Links      map[string]realityLinkedClient
	ServerName string
}

// realityLinkedClient is one client with a SOCKS user behind it. The password is
// derived rather than stored, so it can be put in an xray config without keeping
// a readable one anywhere.
type realityLinkedClient struct {
	ID       int64
	Username string
	Password string
}

// vlessClientEmail is the name xray knows a client by, and what a routing rule
// matches on. It has to stay stable across re-renders: a client whose email
// moved would lose its route without anything looking wrong.
func vlessClientEmail(id int64) string { return fmt.Sprintf("vless-%d", id) }

// vlessOutboundTag names the per-client socks outbound.
func vlessOutboundTag(id int64) string { return fmt.Sprintf("proxy-%d", id) }

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
	User        []string `json:"user,omitempty"`
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

	// A client linked to a SOCKS user gets an email, and xray routes its
	// sessions by that email to an outbound carrying that user's credentials.
	// An unlinked client falls through to the shared outbound, exactly as before.
	clients := make([]realityClient, 0, len(k.ClientIDs))
	perUserOutbounds := make([]realityOutbound, 0, len(k.Links))
	rules := make([]realityRoutingRule, 0, len(k.Links)+1)
	for _, id := range k.ClientIDs {
		entry := realityClient{ID: id}
		link, linked := k.Links[id]
		if linked {
			entry.Email = vlessClientEmail(link.ID)
			perUserOutbounds = append(perUserOutbounds, realityOutbound{
				Tag:      vlessOutboundTag(link.ID),
				Protocol: "socks",
				Settings: &realityOutboundSettings{
					Servers: []realitySocksServer{{
						Address: "127.0.0.1",
						Port:    cfg.ProxyPort,
						Users:   []realityUser{{User: link.Username, Pass: link.Password}},
					}},
				},
			})
			rules = append(rules, realityRoutingRule{
				Type:        "field",
				User:        []string{entry.Email},
				OutboundTag: vlessOutboundTag(link.ID),
			})
		}
		clients = append(clients, entry)
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

	out.Outbounds = append([]realityOutbound{socksOut}, perUserOutbounds...)
	out.Outbounds = append(out.Outbounds, realityOutbound{Tag: realityDirectTag, Protocol: "freedom"})

	// The shared outbound stays the fallback, so a client that is not linked
	// keeps working rather than being refused.
	rules = append(rules, realityRoutingRule{
		Type:        "field",
		InboundTag:  []string{realityInboundTag},
		OutboundTag: realitySocksTag,
	})
	out.Routing = realityRoutingConfig{Rules: rules}

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
		Settings: realitySocksInboundConfig{Auth: "noauth", UDP: true},
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

	// Client UUIDs, in precedence order:
	//
	// 1. REALITY_CLIENT_IDS. Configuration pinning always wins, which is the
	//    same promise the rest of the environment handling makes.
	// 2. The vless_clients table, which the dashboard manages.
	// 3. The legacy comma-joined config value, adopted into the table on first
	//    run so an upgrade does not revoke anyone's UUID.
	// 4. A generated one, which becomes a table row so it survives a restart.
	keys.ClientIDs = nonEmpty(cfg.RealityClientIDs)
	if len(keys.ClientIDs) == 0 && store != nil {
		keys.ClientIDs, _ = store.EnabledVlessClientUUIDs()
		if len(keys.ClientIDs) == 0 && persisted[dbRealityClientIDs] != "" {
			keys.ClientIDs = adoptLegacyClientIDs(store, splitList(persisted[dbRealityClientIDs]), logger)
		}
	}
	if len(keys.ClientIDs) == 0 {
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
		if store != nil {
			// A UUID that changes on every restart would silently break every
			// saved client profile, so the generated one is stored.
			if _, err := store.CreateVlessClient(keys.ClientIDs[0], "generated"); err != nil {
				logger.Warn("could not store the generated VLESS id; it will change on restart", "error", err)
			}
		}
	}

	if keys.ServerName = firstNonEmpty(cfg.RealityServerNames...); keys.ServerName == "" {
		// The camouflage host is the only SNI guaranteed to match the
		// certificate REALITY serves, so it is the default.
		if host, _, err := splitHostPort(cfg.RealityDest); err == nil {
			keys.ServerName = host
		}
	}

	keys.Links = loadRealityLinks(store, logger)

	if store != nil {
		if generatedKey {
			saveRealitySetting(store, logger, dbRealityPrivateKey, keys.PrivateKey)
		}
		if generatedShortID {
			saveRealitySetting(store, logger, dbRealityShortID, keys.ShortID)
		}
	}

	return keys, nil
}

// loadRealityLinks reads which clients are billed to a SOCKS user, and derives
// the password xray needs to authenticate as them.
func loadRealityLinks(store *Store, logger *slog.Logger) map[string]realityLinkedClient {
	out := map[string]realityLinkedClient{}
	if store == nil {
		return out
	}
	links, err := store.ListVlessLinks()
	if err != nil {
		logger.Warn("could not read the REALITY client links", "error", err)
		return out
	}
	secret, err := store.EnsureVlessLinkSecret()
	if err != nil {
		logger.Warn("could not read the link secret", "error", err)
		return out
	}

	clients, err := store.ListVlessClients()
	if err != nil {
		logger.Warn("could not read the managed VLESS clients", "error", err)
		return out
	}
	byID := map[int64]VlessClient{}
	for _, c := range clients {
		byID[c.ID] = c
	}

	for clientID, username := range links {
		client, ok := byID[clientID]
		if !ok || !client.Enabled {
			continue
		}
		_, password := VlessLinkCredentials(secret, clientID)
		out[client.UUID] = realityLinkedClient{
			ID:       clientID,
			Username: username,
			Password: password,
		}
	}
	return out
}

// adoptLegacyClientIDs moves an id list from the old comma-joined config value
// into the table. Without this, the first dashboard change would drop the ids
// that upgrade brought with it, because the table would then shadow the config.
func adoptLegacyClientIDs(store *Store, ids []string, logger *slog.Logger) []string {
	for _, id := range ids {
		if !IsUUID(id) {
			continue
		}
		if _, err := store.CreateVlessClient(id, "migrated"); err != nil {
			logger.Warn("could not migrate a REALITY client id; it will be dropped from the managed list", "error", err)
			continue
		}
	}
	kept, err := store.EnabledVlessClientUUIDs()
	if err != nil {
		logger.Warn("could not read the migrated VLESS ids", "error", err)
		return nil
	}
	return kept
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
	bin    string
	logger *slog.Logger
	host   string
	port   int

	mu      sync.Mutex
	cfgFile string // owned by supervise() once running; read under mu elsewhere
	cmd     *exec.Cmd
	stopped bool

	reload chan realityReload
	stop   chan struct{}
	exited chan struct{}
}

// realityReload asks the supervisor to swap in a new, already validated config
// file. The supervisor replies on done; a nil error means xray is running on the
// new file.
type realityReload struct {
	cfgFile string
	done    chan error
}

// startReality validates the rendered config before serving, so a broken setup
// fails loudly at startup instead of leaving a silent dead front door.
func startReality(cfg Config, k realityKeys, logger *slog.Logger) (*realityRunner, error) {
	bin := cfg.RealityXrayBin
	if bin == "" {
		bin = "xray"
	}
	cfgFile, err := renderValidatedServerConfig(bin, cfg, k)
	if err != nil {
		return nil, err
	}

	pruneStaleRealityConfigs(24 * time.Hour)

	r := &realityRunner{
		bin:     bin,
		cfgFile: cfgFile,
		logger:  logger,
		reload:  make(chan realityReload, 1),
		stop:    make(chan struct{}),
		exited:  make(chan struct{}),
	}
	if host, port, err := splitHostPort(cfg.RealityBind); err == nil {
		r.host, r.port = host, port
	}
	go r.supervise()

	r.waitReady()
	return r, nil
}

// renderValidatedServerConfig writes the config to a private temp file and asks
// xray to parse it. A config that does not validate is deleted and reported, so
// a bad change never takes a working front door down.
func renderValidatedServerConfig(bin string, cfg Config, k realityKeys) (string, error) {
	data, err := renderRealityServerConfig(cfg, k)
	if err != nil {
		return "", err
	}

	file, err := os.CreateTemp("", "xray-reality-*.json")
	if err != nil {
		return "", fmt.Errorf("write xray config: %w", err)
	}
	cfgFile := file.Name()
	if _, err := file.Write(data); err != nil {
		file.Close()
		os.Remove(cfgFile)
		return "", fmt.Errorf("write xray config: %w", err)
	}
	file.Close()
	// CreateTemp already opens 0600, which matters: the file holds the REALITY
	// private key and the proxy credentials.

	if _, err := runXray(bin, "run", "-c", cfgFile, "--test"); err != nil {
		// runXray already carries xray's own complaint, which is the part worth
		// reading ("failed to listen...", "invalid private key", and so on).
		os.Remove(cfgFile)
		return "", err
	}
	return cfgFile, nil
}

// waitReady logs whether the REALITY port started answering. A failure here is
// not fatal: xray may still be retrying, and its own log carries the reason.
func (r *realityRunner) waitReady() {
	if r.host == "" {
		return
	}
	target := net.JoinHostPort(r.host, strconv.Itoa(r.port))
	deadline := time.Now().Add(10 * time.Second)
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
//
// It is also the only place the child is started, stopped and re-pointed, which
// is what makes a config swap safe: the new file is validated by the caller
// before it is ever offered here, and this goroutine does the stop-then-start
// with nothing else touching the process.
func (r *realityRunner) supervise() {
	defer close(r.exited)

	// A reload waiting for its new child to come up. It is answered once the
	// child is running, so the dashboard's reply means "xray is serving the new
	// list", not "xray was asked to".
	var answered *realityReload

	delay := 5 * time.Second
	for {
		if r.isStopped() {
			return
		}

		w := &xrayLogWriter{logger: r.logger}
		cmd := exec.Command(r.bin, "run", "-c", r.configFile())
		cmd.Stdout, cmd.Stderr = w, w

		if err := cmd.Start(); err != nil {
			r.logger.Error("reality: cannot start xray", "error", err)
			if answered != nil {
				answered.done <- fmt.Errorf("xray did not start: %w", err)
				answered = nil
			}
		} else {
			r.setCmd(cmd)
			if answered != nil {
				r.waitReady()
				answered.done <- nil
				answered = nil
			}
			// Wait runs in its own goroutine so the loop can still act on a
			// reload or a stop while the child is running.
			exited := make(chan error, 1)
			go func() { exited <- cmd.Wait() }()

			select {
			case waitErr := <-exited:
				r.setCmd(nil)
				if r.isStopped() {
					return
				}
				r.logger.Error("reality: xray exited, restarting", "error", waitErr)
			case req := <-r.reload:
				r.logger.Info("reality: reloading client list")
				r.stopChild(exited)
				r.swapConfig(req.cfgFile)
				answered = &req
				// A deliberate reload is not a crash: start the new child at
				// once instead of serving the backoff first.
				continue
			case <-r.stop:
				r.setCmd(nil)
				r.stopChild(exited)
				return
			}
		}

		select {
		case <-time.After(delay):
		case <-r.stop:
			return
		case req := <-r.reload:
			// No child is running here, so the reply waits for the next
			// successful start. Claiming it is applied now would be a lie the
			// dashboard would show as "live".
			r.swapConfig(req.cfgFile)
			answered = &req
			continue
		}
		if delay < time.Minute {
			delay *= 2
			if delay > time.Minute {
				delay = time.Minute
			}
		}
	}
}

// stopChild ends the running child and waits for the process to actually be
// gone, so the port is free before its replacement starts.
func (r *realityRunner) stopChild(exited chan error) {
	r.mu.Lock()
	cmd := r.cmd
	r.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-exited
	}
}

// swapConfig installs a new config file and deletes the one it replaces.
func (r *realityRunner) swapConfig(next string) {
	r.mu.Lock()
	old := r.cfgFile
	r.cfgFile = next
	r.mu.Unlock()
	if old != "" && old != next {
		_ = os.Remove(old)
	}
}

func (r *realityRunner) configFile() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfgFile
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

// Reload renders a new config and swaps it in. The config is validated by xray
// first, so an invalid change is refused and the running front door keeps
// serving; the previous file is removed only once the new one is accepted.
func (r *realityRunner) Reload(cfg Config, k realityKeys) error {
	bin := cfg.RealityXrayBin
	if bin == "" {
		bin = r.bin
	}
	next, err := renderValidatedServerConfig(bin, cfg, k)
	if err != nil {
		return err
	}

	req := realityReload{cfgFile: next, done: make(chan error, 1)}
	select {
	case r.reload <- req:
	case <-time.After(10 * time.Second):
		_ = os.Remove(next)
		return errors.New("xray supervisor is not responding")
	}
	select {
	case err := <-req.done:
		return err
	case <-time.After(15 * time.Second):
		return errors.New("timed out waiting for xray to reload")
	}
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
	_ = os.Remove(r.configFile())
}

// ─── Wiring ─────────────────────────────────────────────────────────────────

// startRealityForServer resolves keys, starts the child and writes the client
// config operators copy to their own devices.
func startRealityForServer(cfg Config, persisted map[string]string, store *Store, logger *slog.Logger) (*realityRunner, realityKeys, error) {
	if _, err := exec.LookPath(orDefault(cfg.RealityXrayBin, "xray")); err != nil {
		if _, statErr := os.Stat(orDefault(cfg.RealityXrayBin, "xray")); statErr != nil {
			return nil, realityKeys{}, fmt.Errorf("reality_enabled is set but the xray binary is missing: set XRAY_BIN or install it (Docker images ship it at /usr/local/bin/xray)")
		}
	}

	keys, err := resolveRealityKeys(cfg, persisted, store, logger)
	if err != nil {
		return nil, keys, err
	}

	if _, port, err := splitHostPort(cfg.RealityBind); err == nil && port == cfg.SinglePort && cfg.SinglePort != 0 {
		logger.Warn("reality port and SINGLE_PORT are the same; xray will fail to bind", "port", port)
	}

	runner, err := startReality(cfg, keys, logger)
	if err != nil {
		return nil, keys, err
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
	return runner, keys, nil
}

// ─── Live client-list management ───────────────────────────────────────────

// generateVlessUUID asks xray for an id, which is the same generator that
// produced the first one. It runs a subprocess because the binary is already a
// dependency of this feature and rolling our own UUID would be one more thing
// to get wrong.
func generateVlessUUID(bin string) (string, error) {
	out, err := runXray(orDefault(bin, "xray"), "uuid")
	if err != nil {
		return "", err
	}
	fields := strings.Fields(out)
	if len(fields) == 0 || !IsUUID(fields[0]) {
		return "", fmt.Errorf("xray uuid returned %q", strings.TrimSpace(out))
	}
	return fields[0], nil
}

// realityManager returns the runner and keys when the dashboard is allowed to
// change the client list.
func (s *ProxyServer) realityManager() (*realityRunner, realityKeys, error) {
	s.realityMu.Lock()
	defer s.realityMu.Unlock()

	if s.reality == nil {
		return nil, realityKeys{}, errors.New("REALITY is not enabled, so there is no xray client list to manage")
	}
	// REALITY_CLIENT_IDS pins the list from configuration, which outranks the
	// database everywhere else in this program. Editing the table would then
	// look like it worked and change nothing.
	s.configMu.RLock()
	pinned := len(s.cfg.RealityClientIDs) > 0
	s.configMu.RUnlock()
	if pinned {
		return nil, realityKeys{}, errors.New("REALITY_CLIENT_IDS is set, which pins the client list; unset it to manage clients here")
	}
	return s.reality, s.realityKeys, nil
}

// requireRealityManager is the handler-side guard for the mutating routes.
func (s *ProxyServer) requireRealityManager(w http.ResponseWriter) error {
	if _, _, err := s.realityManager(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return err
	}
	return nil
}

// applyVlessClients re-renders the xray config from the enabled rows and swaps
// it into the running child. The config is validated before xray is restarted,
// so a rejected change leaves the front door serving what it was serving.
func (s *ProxyServer) applyVlessClients() error {
	runner, keys, err := s.realityManager()
	if err != nil {
		return err
	}
	s.realityMu.Lock()
	keys.ClientIDs, err = s.store.EnabledVlessClientUUIDs()
	keys.Links = loadRealityLinks(s.store, s.logger)
	s.realityMu.Unlock()
	if err != nil {
		return err
	}
	if len(keys.ClientIDs) == 0 {
		return errors.New("this would leave xray with no clients, so the front door would refuse every connection; add one first")
	}

	s.configMu.RLock()
	cfg := s.cfg
	s.configMu.RUnlock()

	if err := runner.Reload(cfg, keys); err != nil {
		return err
	}
	s.realityMu.Lock()
	s.realityKeys = keys
	s.realityMu.Unlock()
	s.logger.Info("reality client list applied", "clients", len(keys.ClientIDs))
	return nil
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

// linkVlessClient bills a REALITY client's traffic to a SOCKS user of its own,
// or stops doing so.
//
// The username and password xray needs are derived from this install's link
// secret rather than stored: only the hash goes into the users table, the
// plaintext is recomputed on every render, and nothing readable is ever kept.
func (s *ProxyServer) linkVlessClient(clientID int64, link bool, tier *string) error {
	if !link {
		if err := s.store.UnlinkVlessClient(clientID); err != nil {
			return err
		}
	} else {
		secret, err := s.store.EnsureVlessLinkSecret()
		if err != nil {
			return err
		}
		derived, password := VlessLinkCredentials(secret, clientID)

		// An existing user keeps its own tier; a new one is created at the tier
		// asked for, defaulting to the shared credentials' behaviour.
		existing, err := s.store.GetUser(derived)
		switch {
		case err == nil && existing != nil:
			// Already created on a previous link.
		case s.store != nil && tier != nil && *tier != "":
			if _, err := s.store.CreateUser(derived, password, *tier); err != nil {
				return err
			}
		default:
			if _, err := s.store.CreateUser(derived, password, defaultLinkedUserTier); err != nil {
				return err
			}
		}
		if err := s.store.LinkVlessClient(clientID, derived); err != nil {
			return err
		}
		s.logger.Info("reality client linked to a socks user",
			"client", clientID, "username", derived, "tier", tierName(tier))
	}

	// Put it in front of xray straight away, the same as any other client change.
	return s.applyVlessClients()
}

// defaultLinkedUserTier is what a linked client gets when no tier is named: the
// service's own credentials, so linking does not quietly change what someone
// gets until an operator says so.
const defaultLinkedUserTier = "unlimited"

// tierName names the tier for a log line, without dereferencing a nil pointer.
func tierName(tier *string) string {
	if tier == nil || *tier == "" {
		return defaultLinkedUserTier
	}
	return *tier
}

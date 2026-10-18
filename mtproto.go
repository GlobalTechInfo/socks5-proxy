package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ─── MTProto obfuscated2 ───────────────────────────────────────────────────
//
// Telegram clients do not speak SOCKS5 or HTTP. They speak MTProto, wrapped in
// the "obfuscated2" transport, and they expect to be able to carry that stream
// to Telegram unchanged. So unlike REALITY -- where xray in front of this
// service speaks VLESS and hands us plain SOCKS5 -- MTProto has to be spoken
// here: the client's obfuscated stream is unwrapped, and a second one is wrapped
// onto the connection to the real Telegram datacenter.
//
// The transport is a stream cipher keyed by the client's opening 64 bytes, mixed
// with a shared 16-byte secret. That secret is the whole of the access control:
// whoever knows it can use the proxy, and the protocol tag riding inside the
// encrypted tail is what proves the reader knew the secret too.
//
// The primitives are AES-256-CTR and SHA-256, both standard library. The layout
// is the one Telegram documents; gotd/td's obfuscated2 package is the
// independent implementation this is tested against, byte for byte, because a
// proxy that is merely self-consistent connects to nothing.

const (
	mtprotoInitLen   = 64
	mtprotoSecretLen = 16

	// defaultMTProtoBind avoids 443, which belongs to REALITY on a host that has
	// both, and avoids 80 for the same reason.
	defaultMTProtoBind = "0.0.0.0:8443"

	// abridgedIntermediate is what we announce to the datacenter. It is the
	// transport Telegram clients use through a proxy, so the datacenter behaves
	// towards us exactly as it would towards a client.
	abridgedIntermediate = 0xdddd516d
)

// mtprotoProtocolOK reports whether p is a transport tag a Telegram client can
// actually be using. A stream decrypted with the wrong secret yields 32 random
// bytes, so a recognisable tag is what distinguishes "this is the right secret"
// from "this is noise" when several secrets are configured.
func mtprotoProtocolOK(p [4]byte) bool {
	// The tag travels as four literal bytes, so it is compared as bytes rather
	// than as the little-endian integer the datacenter id is.
	switch p {
	case [4]byte{0xee, 0xee, 0xee, 0xee}: // intermediate
		return true
	case [4]byte{0xdd, 0xdd, 0x51, 0x6d}: // abridged intermediate
		return true
	case [4]byte{0xdd, 0xdd, 0x51, 0x6e}: // padded intermediate
		return true
	case [4]byte{0x02, 0x01, 0x03, 0x16}: // used by some clients
		return true
	}
	return false
}

// mtprotoStreams derives the two directions from the client's opening bytes and
// the shared secret. fromPeer reads what the peer sends, toPeer writes what we
// send.
//
// The reversed copy of the client's bytes is the other direction's key material,
// which is why a stream can be read and written by two peers that never
// exchanged anything else.
func mtprotoStreams(init []byte, secret []byte) (toPeer, fromPeer cipher.Stream, err error) {
	if len(init) < mtprotoInitLen {
		return nil, nil, fmt.Errorf("mtproto init is %d bytes, want %d", len(init), mtprotoInitLen)
	}

	toKey := append([]byte(nil), init[8:40]...)
	toIV := append([]byte(nil), init[40:56]...)

	fromRev := make([]byte, 48)
	copy(fromRev, init[8:56])
	reverse(fromRev)
	fromKey := append([]byte(nil), fromRev[:32]...)
	fromIV := append([]byte(nil), fromRev[32:48]...)

	if len(secret) > 0 {
		if len(secret) < mtprotoSecretLen {
			return nil, nil, fmt.Errorf("mtproto secret is %d bytes, want %d", len(secret), mtprotoSecretLen)
		}
		shared := secret[:mtprotoSecretLen]
		toKey = sha256Concat(toKey, shared)
		fromKey = sha256Concat(fromKey, shared)
	}

	toStream, err := aesCTR(toKey, toIV)
	if err != nil {
		return nil, nil, err
	}
	fromStream, err := aesCTR(fromKey, fromIV)
	if err != nil {
		return nil, nil, err
	}
	return toStream, fromStream, nil
}

func aesCTR(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func sha256Concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	joined := make([]byte, 0, n)
	for _, p := range parts {
		joined = append(joined, p...)
	}
	sum := sha256.Sum256(joined)
	return sum[:]
}

func reverse(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

// prefixConn puts already-read bytes back in front of a connection, so a single
// byte peeked to tell the transports apart does not cost the handshake the byte
// it was looking at.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// mtprotoConn is what a session needs from whatever carries it: a socket for
// obfuscated2, or the record layer of fake TLS.
type mtprotoConn interface {
	io.Reader
	io.Writer
	Close() error
}

// mtprotoSession is one leg of a proxied conversation: an obfuscated stream in
// each direction.
type mtprotoSession struct {
	conn   mtprotoConn
	toPeer cipher.Stream
	from   cipher.Stream
}

// Close ends the underlying connection. The session is not reused, so closing
// twice is harmless.
func (s *mtprotoSession) Close() error { return s.conn.Close() }

func (s *mtprotoSession) Read(p []byte) (int, error) {
	n, err := s.conn.Read(p)
	if n > 0 {
		s.from.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

func (s *mtprotoSession) Write(p []byte) (int, error) {
	buf := make([]byte, len(p))
	s.toPeer.XORKeyStream(buf, p)

	// TCP is free to accept less than it was given, and a short write here means
	// the tail of a message is lost with no error reported anywhere -- which
	// looks to Telegram like a broken proxy rather than a busy socket.
	written := 0
	for written < len(buf) {
		n, err := s.conn.Write(buf[written:])
		written += n
		if err != nil {
			return written, err
		}
	}
	return len(p), nil
}

// mtprotoAccept performs the server half of the handshake: it reads the client's
// opening 64 bytes, derives the streams from them and the shared secret, and
// returns the deobfuscated connection plus the datacenter the client asked for.
//
// With several secrets configured, a stream whose decrypted tag is not one a
// Telegram client uses means the secret was wrong, and the caller should try the
// next one.
func mtprotoAccept(conn mtprotoConn, secret []byte, strictTag bool) (*mtprotoSession, int, error) {
	init := make([]byte, mtprotoInitLen)
	if _, err := io.ReadFull(conn, init); err != nil {
		return nil, 0, fmt.Errorf("read mtproto init: %w", err)
	}

	toPeer, fromPeer, err := mtprotoStreams(init, secret)
	if err != nil {
		return nil, 0, err
	}

	// The reader's view is the mirror image of the writer's.
	toPeer, fromPeer = fromPeer, toPeer

	// Decrypting all 64 bytes advances the stream to the same offset the client
	// reached, which is what lets the next read line up.
	decrypted := make([]byte, mtprotoInitLen)
	fromPeer.XORKeyStream(decrypted, init)

	var protocol [4]byte
	copy(protocol[:], decrypted[56:60])
	dc := int(binary.LittleEndian.Uint16(decrypted[60:62]))

	if strictTag && !mtprotoProtocolOK(protocol) {
		return nil, 0, fmt.Errorf("not a Telegram transport tag (%x): wrong secret?", protocol)
	}

	return &mtprotoSession{conn: conn, toPeer: toPeer, from: fromPeer}, dc, nil
}

// mtprotoDial performs the client half towards a Telegram datacenter: send the
// opening bytes, then return the session to relay over.
func mtprotoDial(dc int, dialTimeout time.Duration, overrides map[int]string) (*mtprotoSession, error) {
	addr := mtprotoDCAddress(dc, overrides)
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial dc %d (%s): %w", dc, addr, err)
	}

	init := make([]byte, mtprotoInitLen)
	if _, err := io.ReadFull(rand.Reader, init); err != nil {
		conn.Close()
		return nil, err
	}
	toPeer, fromPeer, err := mtprotoStreams(init, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// The transport tag is four literal bytes; the datacenter id is a
	// little-endian integer. Getting that backwards still produces a stream that
	// looks random, so it is worth saying which is which.
	copy(init[56:60], []byte{0xdd, 0xdd, 0x51, 0x6d})
	binary.LittleEndian.PutUint16(init[60:62], uint16(dc))

	encrypted := make([]byte, mtprotoInitLen)
	toPeer.XORKeyStream(encrypted, init)

	// First 56 bytes travel as sent; the last 8 carry the transport tag and the
	// datacenter, and only make sense to a holder of the keys.
	header := append(append([]byte(nil), init[:56]...), encrypted[56:]...)
	if _, err := conn.Write(header); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write mtproto init: %w", err)
	}
	return &mtprotoSession{conn: conn, toPeer: toPeer, from: fromPeer}, nil
}

// ─── Telegram datacenters ──────────────────────────────────────────────────
//
// The addresses below are the production datacenters, which are stable and
// documented rather than discovered. MTPROTO_DCS overrides them for anyone whose
// network cannot reach these directly; the format is dc=address,dc=address.
var mtprotoDefaultDCs = map[int]string{
	1: "149.154.175.50:443",
	2: "149.154.167.51:443",
	3: "149.154.175.100:443",
	4: "149.154.167.91:443",
	5: "91.108.56.130:443",
}

// parseMTProtoDCOverrides reads dc=address,dc=address, letting an operator whose
// network cannot reach Telegram directly point at a mirror. Parsed once at
// startup rather than per connection: reading the environment from several
// connection goroutines at once is a data race, and the answer cannot change
// without a restart anyway.
func parseMTProtoDCOverrides(raw string) map[int]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parsed := map[int]string{}
	var ignored []string
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		dcText, addr, found := strings.Cut(entry, "=")
		if !found {
			ignored = append(ignored, entry)
			continue
		}
		dc, err := strconv.Atoi(strings.TrimSpace(dcText))
		if err != nil || dc < 1 || dc > 20 {
			ignored = append(ignored, entry)
			continue
		}
		parsed[dc] = strings.TrimSpace(addr)
	}
	if len(ignored) > 0 {
		slog.Warn("ignoring unreadable MTPROTO_DCS entries", "entries", ignored)
	}
	if len(parsed) == 0 {
		return nil
	}
	return parsed
}

// mtprotoDCAddress returns where to reach a datacenter, preferring an override.
func mtprotoDCAddress(dc int, overrides map[int]string) string {
	if addr, ok := overrides[dc]; ok {
		return addr
	}
	if addr, ok := mtprotoDefaultDCs[dc]; ok {
		return addr
	}
	// An unknown id is almost always a client asking for a datacenter that does
	// not exist; DC2 is the documented fallback and is reachable everywhere.
	return mtprotoDefaultDCs[2]
}

// ─── The proxy ──────────────────────────────────────────────────────────────

// mtprotoSecrets is the set of shared secrets the listener will accept, keyed by
// their hex form so the dashboard and the database speak the same identifier.
type mtprotoSecrets map[string][]byte

// mtprotoServer accepts Telegram clients and relays them to a datacenter.
type mtprotoServer struct {
	cfg Config
	// secrets is a getter, not a map: the set is replaced when the dashboard
	// changes it, and a copy taken at startup would keep serving secrets that
	// have since been revoked.
	secrets   func() mtprotoSecrets
	overrides map[int]string
	// cloakHost is the domain the fake TLS reply is built around when a client
	// does not name one of its own.
	cloakHost string
	log       *slog.Logger
	track     func(net.Conn)
	untrack   func(net.Conn)
	listener  net.Listener
}

// serveMTProto runs until the listener is closed. Each connection is handed to
// handleMTProto.
func (m *mtprotoServer) serve() {
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			if isTemporary(err) {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			// The listener was closed, which is how this loop ends.
			return
		}
		go m.handle(conn)
	}
}

func isTemporary(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (m *mtprotoServer) handle(conn net.Conn) {
	log := m.log.With("client", remoteIP(conn))
	m.track(conn)
	defer m.untrack(conn)

	idle := time.Duration(m.cfg.IdleTimeout) * time.Second
	if idle <= 0 {
		idle = 300 * time.Second
	}
	dialTimeout := time.Duration(m.cfg.ReadTimeout) * time.Second
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}

	session, dc, err := m.accept(conn)
	if err != nil {
		log.Debug("mtproto handshake refused", "error", err)
		return
	}

	upstream, err := mtprotoDial(dc, dialTimeout, m.overrides)
	if err != nil {
		log.Warn("cannot reach the datacenter", "dc", dc, "error", err)
		return
	}
	defer upstream.Close()

	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			session.Close()
			upstream.Close()
		})
	}
	// Telegram holds connections open, so neither leg closes on its own; the
	// first side to go takes the other with it.
	go func() {
		defer closeBoth()
		copyStream(upstream, session, log)
	}()
	go func() {
		defer closeBoth()
		copyStream(session, upstream, log)
	}()

	log.Info("mtproto session relayed", "dc", dc, "address", mtprotoDCAddress(dc, m.overrides))
	<-time.After(idle)
	closeBoth()
}

// accept reads the client's opening and works out which transport it speaks.
// A TLS handshake starts 0x16; anything else is obfuscated2. The choice comes
// from the first byte, which is what lets one port serve both.
func (m *mtprotoServer) accept(conn net.Conn) (*mtprotoSession, int, error) {
	secrets := m.secrets()

	peek := make([]byte, 1)
	if _, err := io.ReadFull(conn, peek); err != nil {
		return nil, 0, err
	}

	// The peeked byte is the first byte of whichever handshake follows, so it is
	// pushed back in front of the stream rather than consumed.
	conn = &prefixConn{Conn: conn, prefix: peek}

	if peek[0] == fakeTLSRecordHandshake {
		// The hello itself carries the HMAC, so the secret is settled before
		// anything else is read.
		wrapped, hello, err := fakeTLSHandshake(conn, secrets, time.Now(), m.cloakHost)
		if err != nil {
			return nil, 0, err
		}
		m.log.Info("fake tls hello accepted", "domain", hello.Domain)
		session, dc, err := m.acceptWithSecret(wrapped, hello.Secret)
		return session, dc, err
	}

	return m.acceptWithAnySecret(conn, secrets)
}

// acceptWithSecret runs the obfuscated2 handshake with a secret already known,
// which is the case after a fake TLS hello proved it.
func (m *mtprotoServer) acceptWithSecret(conn mtprotoConn, secret []byte) (*mtprotoSession, int, error) {
	init := make([]byte, mtprotoInitLen)
	if _, err := io.ReadFull(conn, init); err != nil {
		return nil, 0, err
	}
	toPeer, fromPeer, err := mtprotoStreams(init, secret)
	if err != nil {
		return nil, 0, err
	}
	toPeer, fromPeer = fromPeer, toPeer

	probe := make([]byte, mtprotoInitLen)
	fromPeer.XORKeyStream(probe, init)
	dc := int(binary.LittleEndian.Uint16(probe[60:62]))
	return &mtprotoSession{conn: conn, toPeer: toPeer, from: fromPeer}, dc, nil
}

// acceptWithAnySecret finds the secret the client is using. Each attempt reads
// from the same connection, so a wrong secret only costs the client opening
// bytes: the server has consumed exactly the same 64 bytes either way, and the
// stream is discarded between attempts.
func (m *mtprotoServer) acceptWithAnySecret(conn mtprotoConn, secrets mtprotoSecrets) (*mtprotoSession, int, error) {
	if len(secrets) == 0 {
		return nil, 0, errors.New("no MTProto secret is configured")
	}
	init := make([]byte, mtprotoInitLen)
	if _, err := io.ReadFull(conn, init); err != nil {
		return nil, 0, err
	}

	var lastErr error
	for _, secret := range secrets {
		toPeer, fromPeer, err := mtprotoStreams(init, secret)
		if err != nil {
			lastErr = err
			continue
		}
		toPeer, fromPeer = fromPeer, toPeer

		// Decrypt a copy, never the opening bytes themselves: a wrong secret must
		// not consume the stream the next attempt needs.
		probe := make([]byte, mtprotoInitLen)
		fromPeer.XORKeyStream(probe, init)

		// Only a reader who knows the secret gets a recognisable tag out of the
		// encrypted tail, so this rejects a wrong secret rather than a valid one.
		var protocol [4]byte
		copy(protocol[:], probe[56:60])
		if !mtprotoProtocolOK(protocol) {
			lastErr = fmt.Errorf("no configured secret matched (decrypted tag %x)", protocol)
			continue
		}
		dc := int(binary.LittleEndian.Uint16(probe[60:62]))
		return &mtprotoSession{conn: conn, toPeer: toPeer, from: fromPeer}, dc, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no configured secret matched")
	}
	return nil, 0, lastErr
}

// copyStream moves bytes until one side stops or the idle window closes.
func copyStream(dst io.Writer, src io.Reader, log *slog.Logger) {
	// io.Copy rather than a hand-rolled loop: it deals with short writes, which
	// a relay that drops them turns into silent truncation.
	if _, err := io.CopyBuffer(dst, src, make([]byte, 32*1024)); err != nil {
		log.Debug("mtproto relay ended", "error", err)
	}
}

// ─── Secrets ────────────────────────────────────────────────────────────────

// A secret says which transport it belongs to: the dd prefix is obfuscated2,
// the ee prefix is the same stream wearing a TLS handshake. Telegram clients
// choose the transport from the prefix, so the server must too.
func mtprotoSecretKind(stored string) string {
	if strings.HasPrefix(stored, "ee") {
		return "ee"
	}
	return "dd"
}

// generateMTProtoSecret returns a shareable proxy secret. The prefix is
// Telegram's: dd for obfuscated2, ee for the same stream inside a TLS handshake,
// and the client picks the transport from it.
func generateMTProtoSecret(kind string) (string, error) {
	return generateMTProtoSecretOfKind(newSecretKind(kind))
}

// newSecretKind picks the kind of secret to generate, for a network where plain
// obfuscated2 is blocked and fake TLS is wanted instead.
func newSecretKind(configured string) string {
	if strings.EqualFold(strings.TrimSpace(configured), "ee") {
		return "ee"
	}
	return "dd"
}

func generateMTProtoSecretOfKind(kind string) (string, error) {
	raw := make([]byte, mtprotoSecretLen)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	if kind != "ee" {
		kind = "dd"
	}
	return kind + hex.EncodeToString(raw), nil
}

// parseMTProtoSecret turns a stored secret into its 16 key bytes. The dd prefix
// is Telegram's, not ours, and takes no part in the cryptography.
func parseMTProtoSecret(stored string) ([]byte, error) {
	stored = strings.ToLower(strings.TrimSpace(stored))
	// Both prefixes are Telegram's markers, not part of the key.
	trimmed := strings.TrimPrefix(stored, "dd")
	if trimmed == stored {
		trimmed = strings.TrimPrefix(stored, "ee")
	}
	key, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%q is not a hex secret", stored)
	}
	if len(key) != mtprotoSecretLen {
		return nil, fmt.Errorf("secret is %d bytes, want %d", len(key), mtprotoSecretLen)
	}
	return key, nil
}

// startMTProto brings up the Telegram front door. Secrets come from the
// database, so a fresh install gets one generated and can start serving
// immediately rather than refusing to start and waiting to be configured.
func (s *ProxyServer) startMTProto(secrets mtprotoSecrets) error {
	secrets = s.loadMTProtoSecrets(secrets, true)
	if len(secrets) == 0 {
		return errors.New("no MTProto secret is configured; add one in the dashboard")
	}

	listener, err := net.Listen("tcp", s.cfg.MTProtoBind)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.MTProtoBind, err)
	}

	s.mtprotoMu.Lock()
	s.mtprotoSecrets = secrets
	s.mtprotoListener = listener
	s.mtprotoMu.Unlock()

	server := &mtprotoServer{
		cfg:       s.cfg,
		secrets:   s.mtprotoLiveSecrets,
		overrides: parseMTProtoDCOverrides(s.cfg.MTProtoDCs),
		cloakHost: orDefault(s.cfg.MTProtoFakeHost, "www.cloudflare.com"),
		log:       s.logger,
		track:     s.trackConn,
		untrack:   s.untrackConn,
		listener:  listener,
	}
	go server.serve()

	s.logger.Info("MTProto enabled", "bind", s.cfg.MTProtoBind, "secrets", len(secrets),
		"edit", "in the dashboard, or Telegram: Settings -> Data and Storage -> Proxy")
	return nil
}

// loadMTProtoSecrets rebuilds the live set from the database.
//
// generateIfEmpty is only ever true at startup. After a dashboard change it must
// be false: revoking the last secret has to leave the proxy refusing everyone,
// because quietly minting a replacement would undo the operator's decision and
// hand out a working credential they never asked for.
func (s *ProxyServer) loadMTProtoSecrets(fallback mtprotoSecrets, generateIfEmpty bool) mtprotoSecrets {
	out := mtprotoSecrets{}
	if s.store != nil {
		if stored, err := s.store.ListMtprotoSecrets(); err != nil {
			s.logger.Warn("could not read MTProto secrets", "error", err)
		} else {
			for _, sec := range stored {
				if !sec.Enabled {
					continue
				}
				if key, err := parseMTProtoSecret(sec.Secret); err == nil {
					out[sec.Secret] = key
				}
			}
		}
	}
	if len(out) == 0 {
		for name, key := range fallback {
			out[name] = key
		}
	}
	if len(out) == 0 && generateIfEmpty && s.store != nil {
		secret, err := generateMTProtoSecret(s.cfg.MTProtoSecretKind)
		if err == nil {
			if _, err := s.store.CreateMtprotoSecret(secret, "generated"); err == nil {
				if key, kerr := parseMTProtoSecret(secret); kerr == nil {
					out[secret] = key
				}
				s.logger.Info("generated the first MTProto secret", "secret", secret)
			}
		}
	}
	return out
}

// setMTProtoSecrets replaces the live set after a dashboard change. Nothing has
// to be restarted: the set is consulted on every connection.
func (s *ProxyServer) setMTProtoSecrets(secrets mtprotoSecrets) {
	s.mtprotoMu.Lock()
	s.mtprotoSecrets = secrets
	s.mtprotoMu.Unlock()
}

// mtprotoLiveSecrets is the set currently being served.
func (s *ProxyServer) mtprotoLiveSecrets() mtprotoSecrets {
	s.mtprotoMu.RLock()
	defer s.mtprotoMu.RUnlock()
	return s.mtprotoSecrets
}

// stopMTProto closes the listener, which ends the accept loop.
func (s *ProxyServer) stopMTProto() {
	s.mtprotoMu.Lock()
	listener := s.mtprotoListener
	s.mtprotoListener = nil
	s.mtprotoMu.Unlock()
	if listener != nil {
		listener.Close()
	}
}

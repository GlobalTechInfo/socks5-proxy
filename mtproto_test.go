package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gotd/td/mtproxy"
	"github.com/gotd/td/mtproxy/obfuscated2"
)

// These tests check our obfuscated2 implementation against gotd/td, an
// independent one. A proxy that is only self-consistent connects to nothing, so
// every handshake here has the peer on the other side written by somebody else.

// The real proof: a client that speaks gotd's obfuscated2 connects to our
// listener, and every byte either way survives.
func TestMTProtoAcceptInteropWithGotdClient(t *testing.T) {
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("rand: %v", err)
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	const dc = 2
	clientObf := obfuscated2.NewObfuscated2(rand.Reader, client)
	go func() {
		_ = clientObf.Handshake([4]byte{0xdd, 0xdd, 0x51, 0x6d}, dc, mtproxy.Secret{Secret: secret})
	}()

	if err := server.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}

	session, gotDC, err := mtprotoAccept(server, secret, true)
	if err != nil {
		t.Fatalf("our server handshake refused a gotd client: %v", err)
	}
	if gotDC != dc {
		t.Errorf("datacenter = %d, want %d", gotDC, dc)
	}

	payloads := [][]byte{[]byte("hello from the client"), bytes.Repeat([]byte{0xAB}, 4096), []byte("tail")}
	go func() {
		for _, p := range payloads {
			if _, err := clientObf.Write(p); err != nil {
				return
			}
		}
	}()

	for i, want := range payloads {
		got := make([]byte, len(want))
		if _, err := io.ReadFull(session, got); err != nil {
			t.Fatalf("payload %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("payload %d = %x, want %x", i, got, want)
		}
	}
}

// And the other direction: when we are the client to a datacenter, a peer running
// gotd's server side must be able to read what we write.
func TestMTProtoDialInteropWithGotdServer(t *testing.T) {
	const dc = 4
	const fromProxy, fromDC = "from our dial", "from the dc"

	// Stand in for the datacenter: gotd's server-side Accept with no secret.
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer tcp.Close()

	served := make(chan error, 1)
	go func() {
		conn, aerr := tcp.Accept()
		if aerr != nil {
			served <- aerr
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		session, meta, aerr := obfuscated2.Accept(conn, nil)
		if aerr != nil {
			served <- aerr
			return
		}
		if meta.DC != dc {
			served <- errUnexpectedDC{int(meta.DC)}
			return
		}
		buf := make([]byte, len(fromProxy))
		if _, rerr := io.ReadFull(session, buf); rerr != nil {
			served <- rerr
			return
		}
		if string(buf) != fromProxy {
			served <- fmt.Errorf("payload came back as %q", buf)
			return
		}
		_, werr := session.Write([]byte("from the dc"))
		served <- werr
	}()

	// Point the dialer at our stand-in rather than a real datacenter.
	overrides := map[int]string{dc: "127.0.0.1:" + strconv.Itoa(tcp.Addr().(*net.TCPAddr).Port)}
	session, err := mtprotoDial(dc, 5*time.Second, overrides)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer session.conn.Close()

	if _, err := session.Write([]byte(fromProxy)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(fromDC))
	if _, err := io.ReadFull(session, got); err != nil {
		t.Fatalf("read: %v (stand-in said: %v)", err, <-served)
	}
	if string(got) != fromDC {
		t.Errorf("read %q, want %q", got, fromDC)
	}
	if err := <-served; err != nil {
		t.Errorf("the stand-in datacenter reported: %v", err)
	}
}

// A client that does not know the secret must be refused, and a stream decrypted
// with the wrong secret must not look like a real transport.
func TestMTProtoWrongSecretIsRefused(t *testing.T) {
	secret := make([]byte, 16)
	other := make([]byte, 16)
	rand.Read(secret)
	rand.Read(other)
	secret[0], other[0] = secret[0]^0xff, secret[0]^0xff

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	obf := obfuscated2.NewObfuscated2(rand.Reader, client)
	go func() {
		_ = obf.Handshake([4]byte{0xdd, 0xdd, 0x51, 0x6d}, 2, mtproxy.Secret{Secret: secret})
	}()
	server.SetDeadline(time.Now().Add(5 * time.Second))

	if _, _, err := mtprotoAccept(server, other, true); err == nil {
		t.Fatal("a client with the wrong secret was accepted")
	}
}

// The tag check is the only thing standing between a single-secret proxy and
// serving anyone at all, so it runs even when there is just one secret.
func TestMTProtoSingleSecretStillChecksTheTag(t *testing.T) {
	secret := make([]byte, 16)
	rand.Read(secret)

	// A real transport tag is accepted, and the datacenter comes through.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	obf := obfuscated2.NewObfuscated2(rand.Reader, client)
	go func() {
		_ = obf.Handshake([4]byte{0xee, 0xee, 0xee, 0xee}, 1, mtproxy.Secret{Secret: secret})
	}()
	server.SetDeadline(time.Now().Add(5 * time.Second))
	if _, dc, err := mtprotoAccept(server, secret, true); err != nil {
		t.Fatalf("a client using a real transport tag was refused: %v", err)
	} else if dc != 1 {
		t.Errorf("dc = %d, want 1", dc)
	}

	// Junk in the same position is not.
	client2, server2 := net.Pipe()
	defer client2.Close()
	defer server2.Close()
	go func() {
		_, _ = client2.Write(make([]byte, 64))
	}()
	server2.SetDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := mtprotoAccept(server2, secret, true); err == nil {
		t.Error("random bytes were accepted as a client")
	}
}

func TestMTProtoProtocolTags(t *testing.T) {
	for _, tag := range [][4]byte{{0xee, 0xee, 0xee, 0xee}, {0xdd, 0xdd, 0x51, 0x6d}, {0xdd, 0xdd, 0x51, 0x6e}, {0x02, 0x01, 0x03, 0x16}} {
		if !mtprotoProtocolOK(tag) {
			t.Errorf("transport tag %x was rejected", tag)
		}
	}
	for _, tag := range [][4]byte{{0xde, 0xad, 0xbe, 0xef}, {0, 0, 0, 0}, {0x48, 0x45, 0x41, 0x44}} { // HEAD
		if mtprotoProtocolOK(tag) {
			t.Errorf("junk tag %x was accepted", tag)
		}
	}
}

func TestMTProtoDCOverrides(t *testing.T) {
	overrides := parseMTProtoDCOverrides("4=127.0.0.1:9999, 2=127.0.0.1:8888, nonsense, x=127.0.0.1:1")

	if got := mtprotoDCAddress(4, overrides); got != "127.0.0.1:9999" {
		t.Errorf("dc 4 = %q, want the override", got)
	}
	if got := mtprotoDCAddress(2, overrides); got != "127.0.0.1:8888" {
		t.Errorf("dc 2 = %q, want the override", got)
	}
	if got := mtprotoDCAddress(1, overrides); got != mtprotoDefaultDCs[1] {
		t.Errorf("dc 1 = %q, want the default", got)
	}
	// An unknown datacenter must still produce a dialable address.
	if got := mtprotoDCAddress(77, overrides); got == "" {
		t.Error("an unknown datacenter produced no address")
	}
	if parseMTProtoDCOverrides("") != nil {
		t.Error("an empty setting should produce no overrides")
	}
}

// ─── helpers ────────────────────────────────────────────────────────────────

type errUnexpectedDC struct{ dc int }

func (e errUnexpectedDC) Error() string { return "unexpected datacenter " + strconv.Itoa(e.dc) }

// TestMTProtoRelayEndToEnd runs the whole feature: a client speaking gotd's
// obfuscated2 connects to our listener with a secret from the database, and the
// bytes arrive at the datacenter it asked for.
func TestMTProtoRelayEndToEnd(t *testing.T) {
	secret, err := generateMTProtoSecret("dd")
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	key, err := parseMTProtoSecret(secret)
	if err != nil {
		t.Fatalf("parse secret: %v", err)
	}

	// A datacenter that echoes whatever it is sent, so the test can prove the
	// payload crossed both obfuscation layers intact.
	dcListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dc: %v", err)
	}
	defer dcListener.Close()
	go func() {
		for {
			conn, aerr := dcListener.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer conn.Close()
				// The datacenter side is stood in for with our own handshake: the
				// independent implementation is already on the client side, which
				// is where the compatibility claim actually is.
				session, _, herr := mtprotoAccept(conn, nil, false)
				if herr != nil {
					return
				}
				buf := make([]byte, 4096)
				for {
					n, rerr := session.Read(buf)
					if n > 0 {
						if _, werr := session.Write(buf[:n]); werr != nil {
							return
						}
					}
					if rerr != nil {
						return
					}
				}
			}()
		}
	}()

	cfg := DefaultConfig()
	cfg.MTProtoEnabled = true
	cfg.MTProtoBind = "127.0.0.1:" + strconv.Itoa(freePort(t))
	cfg.MTProtoDCs = "3=127.0.0.1:" + strconv.Itoa(dcListener.Addr().(*net.TCPAddr).Port)

	s := NewProxyServer(cfg)
	s.store = newTestStore(t)
	if _, err := s.store.CreateMtprotoSecret(secret, "test phone"); err != nil {
		t.Fatalf("store secret: %v", err)
	}
	if err := s.startMTProto(nil); err != nil {
		t.Fatalf("start mtproto: %v", err)
	}
	defer s.stopMTProto()

	client, err := net.Dial("tcp", s.mtprotoListener.Addr().String())
	if err != nil {
		t.Fatalf("dial mtproto: %v", err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(15 * time.Second))

	obf := obfuscated2.NewObfuscated2(rand.Reader, client)
	if err := obf.Handshake([4]byte{0xdd, 0xdd, 0x51, 0x6d}, 3, mtproxy.Secret{Secret: key}); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	payload := []byte("a message that has to survive two obfuscation layers")
	if _, err := obf.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(obf, echoed); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Errorf("echoed %q, want %q", echoed, payload)
	}

	// Several chunks in a row, to exercise the relay the way a session does.
	// Sent in modest pieces because the reference client writes a whole buffer
	// in one call and would short-write a large one, which is a property of the
	// harness rather than of this relay.
	for round := 0; round < 8; round++ {
		chunk := bytes.Repeat([]byte{byte('A' + round)}, 4096)
		if _, err := obf.Write(chunk); err != nil {
			t.Fatalf("write round %d: %v", round, err)
		}
		echo := make([]byte, len(chunk))
		if _, err := io.ReadFull(obf, echo); err != nil {
			t.Fatalf("read round %d: %v", round, err)
		}
		if !bytes.Equal(echo, chunk) {
			for i := range chunk {
				if echo[i] != chunk[i] {
					t.Fatalf("round %d diverges at byte %d: got %02x want %02x (first 40: %q)", round, i, echo[i], chunk[i], string(echo[:min(40, len(echo))]))
				}
			}
			t.Fatalf("round %d differs but not byte-wise", round)
		}
	}
}

// A session must not lose the tail of a write when the socket takes less than
// it was offered. Telegram traffic is far larger than a socket buffer, so this
// is the difference between working and appearing intermittently broken.
func TestMTProtoWriteSurvivesShortWrites(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	toPeer, fromPeer, err := mtprotoStreams(make([]byte, 64), nil)
	if err != nil {
		t.Fatalf("streams: %v", err)
	}
	session := &mtprotoSession{conn: server, toPeer: toPeer, from: fromPeer}

	payload := bytes.Repeat([]byte{0x7E}, 200_000)
	go func() { _, _ = session.Write(payload) }()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	// Decrypt what the peer received and compare.
	peerTo, peerFrom, err := mtprotoStreams(make([]byte, 64), nil)
	if err != nil {
		t.Fatalf("streams: %v", err)
	}
	peerFrom.XORKeyStream(got, got)
	_ = peerTo
	if !bytes.Equal(got, payload) {
		t.Errorf("a short-writing socket lost data: %d bytes back, %d sent", len(got), len(payload))
	}
}

// A client without a configured secret must get nowhere, and the listener must
// stay up for the next one.
func TestMTProtoUnknownSecretRefused(t *testing.T) {
	secret, err := generateMTProtoSecret("dd")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	stranger := make([]byte, 16)
	rand.Read(stranger)

	cfg := DefaultConfig()
	cfg.MTProtoEnabled = true
	cfg.MTProtoBind = "127.0.0.1:" + strconv.Itoa(freePort(t))
	cfg.MTProtoDCs = "2=127.0.0.1:1" // unreachable: the handshake is what is under test

	s := NewProxyServer(cfg)
	s.store = newTestStore(t)
	if _, err := s.store.CreateMtprotoSecret(secret, "the only one"); err != nil {
		t.Fatalf("store secret: %v", err)
	}
	if err := s.startMTProto(nil); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.stopMTProto()

	client, err := net.Dial("tcp", s.mtprotoListener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))

	obf := obfuscated2.NewObfuscated2(rand.Reader, client)
	_ = obf.Handshake([4]byte{0xdd, 0xdd, 0x51, 0x6d}, 2, mtproxy.Secret{Secret: stranger})
	_, _ = obf.Write([]byte("let me in"))

	// Dropped rather than answered, and quickly: a served client would be
	// waiting on the unreachable datacenter.
	buf := make([]byte, 32)
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	if _, err := obf.Read(buf); err == nil {
		t.Error("a client with an unknown secret got a reply")
	}
	if waited := time.Since(start); waited > time.Second {
		t.Errorf("the refusal took %v, so the connection was being relayed", waited)
	}
}

func TestMTProtoSecretFormat(t *testing.T) {
	secret, err := generateMTProtoSecret("dd")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.HasPrefix(secret, "dd") {
		t.Errorf("secret %q does not carry the dd prefix the Telegram apps expect", secret)
	}
	if len(secret) != 34 {
		t.Errorf("secret %q is %d characters, want 34", secret, len(secret))
	}
	if key, err := parseMTProtoSecret(secret); err != nil || len(key) != 16 {
		t.Errorf("parse(%q) = %v, %v", secret, key, err)
	}
	// The prefix is Telegram's, so a secret without it must still work.
	if key, err := parseMTProtoSecret(secret[2:]); err != nil || len(key) != 16 {
		t.Errorf("a secret without the prefix did not parse: %v, %v", key, err)
	}
	for _, bad := range []string{"", "zz", "dd", "ddzz", "dd" + strings.Repeat("00", 15)} {
		if _, err := parseMTProtoSecret(bad); err == nil {
			t.Errorf("parse(%q) was accepted", bad)
		}
	}
	// Two secrets must differ, or one would be shared by everyone.
	other, _ := generateMTProtoSecret("dd")
	if other == secret {
		t.Error("generated the same secret twice")
	}
}

// Revoking the last secret must leave the proxy refusing everyone. Quietly
// minting a replacement would undo the decision and hand out a credential the
// operator never asked for -- and the dashboard change would look like it worked.
func TestMTProtoRevokingLastSecretDoesNotMintOne(t *testing.T) {
	secret, err := generateMTProtoSecret("dd")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	key, _ := parseMTProtoSecret(secret)

	cfg := DefaultConfig()
	cfg.MTProtoEnabled = true
	cfg.MTProtoBind = "127.0.0.1:" + strconv.Itoa(freePort(t))
	cfg.MTProtoDCs = "2=127.0.0.1:1"

	s := NewProxyServer(cfg)
	s.store = newTestStore(t)
	row, err := s.store.CreateMtprotoSecret(secret, "the only phone")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := s.startMTProto(nil); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.stopMTProto()

	if live := s.mtprotoLiveSecrets(); len(live) != 1 {
		t.Fatalf("live secrets = %d, want 1", len(live))
	}

	if err := s.store.DeleteMtprotoSecret(row.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	s.setMTProtoSecrets(s.loadMTProtoSecrets(nil, false))

	if live := s.mtprotoLiveSecrets(); len(live) != 0 {
		t.Fatalf("live secrets = %d after revoking the last one; a new one was minted", len(live))
	}
	if stored, _ := s.store.ListMtprotoSecrets(); len(stored) != 0 {
		t.Errorf("stored secrets = %d, want 0", len(stored))
	}

	// And the listener now turns a client away.
	client, err := net.Dial("tcp", s.mtprotoListener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	obf := obfuscated2.NewObfuscated2(rand.Reader, client)
	_ = obf.Handshake([4]byte{0xdd, 0xdd, 0x51, 0x6d}, 2, mtproxy.Secret{Secret: key})
	_, _ = obf.Write([]byte("let me in"))

	// A served client would sit waiting for an unreachable datacenter, so the
	// connection being closed quickly is what proves it was turned away. Merely
	// "some error eventually" would not distinguish the two.
	buf := make([]byte, 16)
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	if _, err := obf.Read(buf); err == nil {
		t.Fatal("a client was served after every secret was revoked")
	}
	if waited := time.Since(start); waited > time.Second {
		t.Errorf("the refusal took %v, so the connection was being relayed rather than refused", waited)
	}
}

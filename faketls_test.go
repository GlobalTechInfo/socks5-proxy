package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/gotd/td/mtproxy"
	"github.com/gotd/td/mtproxy/faketls"
	"github.com/gotd/td/mtproxy/obfuscated2"
)

// gotd ships the client half of fake TLS, so the handshake can be checked
// against an independent implementation rather than against itself.
func TestFakeTLSHandshakeWithGotdClient(t *testing.T) {
	secret, err := generateMTProtoSecret("dd")
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	key, err := parseMTProtoSecret(secret)
	if err != nil {
		t.Fatalf("parse secret: %v", err)
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	secrets := mtprotoSecrets{secret: key}
	done := make(chan error, 1)
	go func() {
		_, info, herr := fakeTLSHandshake(server, secrets, time.Now(), "www.cloudflare.com")
		if herr != nil {
			done <- herr
			return
		}
		if info.Domain != "example.com" {
			done <- errUnexpected{info.Domain}
			return
		}
		done <- nil
	}()

	clientObf := faketls.NewFakeTLS(rand.Reader, client)
	if err := clientObf.Handshake([4]byte{0xdd, 0xdd, 0x51, 0x6d}, 2, mtproxy.Secret{
		Secret:    key,
		CloakHost: "example.com",
	}); err != nil {
		t.Fatalf("the reference client refused our server hello: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("our server refused the reference client: %v", err)
	}
}

// After the handshake, the MTProto stream runs inside TLS records, so bytes
// must survive the record layer in both directions.
func TestFakeTLSCarriesAPayloadBothWays(t *testing.T) {
	secret, _ := generateMTProtoSecret("dd")
	key, _ := parseMTProtoSecret(secret)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	serverSide := make(chan *fakeTLSRecordConn, 1)
	go func() {
		wrapped, _, err := fakeTLSHandshake(server, mtprotoSecrets{secret: key}, time.Now(), "www.cloudflare.com")
		if err != nil {
			serverSide <- nil
			return
		}
		serverSide <- wrapped
	}()

	clientObf := faketls.NewFakeTLS(rand.Reader, client)
	if err := clientObf.Handshake([4]byte{0xdd, 0xdd, 0x51, 0x6d}, 2, mtproxy.Secret{
		Secret: key, CloakHost: "example.com",
	}); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	wrapped := <-serverSide
	if wrapped == nil {
		t.Fatal("the server handshake failed")
	}
	client.SetDeadline(time.Now().Add(10 * time.Second))
	server.SetDeadline(time.Now().Add(10 * time.Second))

	up := []byte("bytes inside TLS application records")
	go func() { _, _ = clientObf.Write(up) }()
	got := make([]byte, len(up))
	if _, err := io.ReadFull(wrapped, got); err != nil {
		t.Fatalf("client to server: %v", err)
	}
	if !bytes.Equal(got, up) {
		t.Errorf("server read %q, want %q", got, up)
	}

	down := bytes.Repeat([]byte{0x7E}, 9000) // more than one record's worth
	go func() { _, _ = wrapped.Write(down) }()
	back := make([]byte, len(down))
	if _, err := io.ReadFull(clientObf, back); err != nil {
		t.Fatalf("server to client: %v", err)
	}
	if !bytes.Equal(back, down) {
		for i := range down {
			if back[i] != down[i] {
				t.Fatalf("payload diverges at %d of %d: got %02x want %02x (head % x)", i, len(down), back[i], down[i], back[:8])
			}
		}
		t.Fatal("payload differs but not byte-wise")
	}
}

// A prober, or a client with the wrong secret, must not get through.
func TestFakeTLSRefusesWrongSecret(t *testing.T) {
	secret, _ := generateMTProtoSecret("dd")
	key, _ := parseMTProtoSecret(secret)
	stranger := make([]byte, 16)
	rand.Read(stranger)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	server.SetDeadline(time.Now().Add(5 * time.Second))
	// A refused client gets no reply at all, so without a deadline it waits
	// forever rather than reporting the refusal.
	client.SetDeadline(time.Now().Add(5 * time.Second))

	go func() {
		_, _, _ = fakeTLSHandshake(server, mtprotoSecrets{secret: key}, time.Now(), "www.cloudflare.com")
	}()

	clientObf := faketls.NewFakeTLS(rand.Reader, client)
	err := clientObf.Handshake([4]byte{0xdd, 0xdd, 0x51, 0x6d}, 2, mtproxy.Secret{
		Secret: stranger, CloakHost: "example.com",
	})
	if err == nil {
		t.Error("a client with the wrong secret completed the fake TLS handshake")
	}
}

// The timestamp in the hello exists so a recorded handshake cannot be replayed
// days later.
func TestFakeTLSRefusesAStaleHello(t *testing.T) {
	secret, _ := generateMTProtoSecret("dd")
	key, _ := parseMTProtoSecret(secret)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	server.SetDeadline(time.Now().Add(5 * time.Second))
	client.SetDeadline(time.Now().Add(5 * time.Second))

	// A server a day ahead of the client treats a fresh hello as stale.
	future := time.Now().Add(24 * time.Hour)
	go func() {
		_, _, _ = fakeTLSHandshake(server, mtprotoSecrets{secret: key}, future, "www.cloudflare.com")
	}()

	clientObf := faketls.NewFakeTLS(rand.Reader, client)
	if err := clientObf.Handshake([4]byte{0xdd, 0xdd, 0x51, 0x6d}, 2, mtproxy.Secret{
		Secret: key, CloakHost: "example.com",
	}); err == nil {
		t.Error("a hello outside the allowed clock skew was accepted")
	}
}

func TestFakeTLSHelloDomainParsing(t *testing.T) {
	secret, _ := generateMTProtoSecret("dd")
	key, _ := parseMTProtoSecret(secret)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	secrets := mtprotoSecrets{secret: key}
	domains := make(chan string, 1)
	go func() {
		_, info, err := fakeTLSHandshake(server, secrets, time.Now(), "www.cloudflare.com")
		if err != nil {
			domains <- ""
			return
		}
		domains <- info.Domain
	}()

	const want = "camouflage.example.org"
	clientObf := faketls.NewFakeTLS(rand.Reader, client)
	if err := clientObf.Handshake([4]byte{0xdd, 0xdd, 0x51, 0x6d}, 2, mtproxy.Secret{
		Secret: key, CloakHost: want,
	}); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if got := <-domains; got != want {
		t.Errorf("server read domain %q, want %q", got, want)
	}
}

type errUnexpected struct{ got string }

func (e errUnexpected) Error() string { return "unexpected domain " + e.got }

// A fake TLS secret has to work through the real listener, not just in
// isolation: one port serving both transports is the whole design.
func TestFakeTLSThroughTheListener(t *testing.T) {
	secret, err := generateMTProtoSecretOfKind("ee")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	key, err := parseMTProtoSecret(secret)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if mtprotoSecretKind(secret) != "ee" {
		t.Fatalf("secret %q is not recognised as fake TLS", secret)
	}

	// A datacenter that echoes, so the relay can be checked end to end.
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
				session, _, herr := mtprotoAccept(conn, nil, true)
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
	if _, err := s.store.CreateMtprotoSecret(secret, "ee phone"); err != nil {
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
	client.SetDeadline(time.Now().Add(15 * time.Second))

	// The two layers nest the way a Telegram client builds them: obfuscated2 on
	// the inside, fake TLS on the outside.
	tlsLayer := faketls.NewFakeTLS(rand.Reader, client)
	if err := tlsLayer.Handshake([4]byte{0xdd, 0xdd, 0x51, 0x6d}, 3, mtproxy.Secret{
		Secret: key, CloakHost: "www.cloudflare.com",
	}); err != nil {
		t.Fatalf("fake tls handshake against the listener: %v", err)
	}
	obf := obfuscated2.NewObfuscated2(rand.Reader, tlsLayer)
	if err := obf.Handshake([4]byte{0xdd, 0xdd, 0x51, 0x6d}, 3, mtproxy.Secret{Secret: key}); err != nil {
		t.Fatalf("obfuscated2 handshake inside the tls records: %v", err)
	}

	payload := []byte("telegram traffic inside a tls-looking handshake")
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
}

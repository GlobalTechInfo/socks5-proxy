package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"
)

// ─── MTProto fake TLS ───────────────────────────────────────────────────────
//
// obfuscated2 traffic looks like random bytes, which is what every Telegram
// proxy looks like. Fake TLS wraps the same stream in TLS records so that
// someone scanning the port sees a TLS handshake instead -- indistinguishable
// from a web request, at the cost of a handshake that never went anywhere.
//
// The scheme is Telegram's, not ours, and it is verified here against an
// independent client: gotd/td's mtproxy/faketls package, which implements the
// other side of exactly this exchange.
//
// How it fits together:
//   - The client opens with a ClientHello whose 32-byte random is an HMAC of the
//     hello under the shared secret, with the last four bytes carrying a
//     timestamp. That is the whole authentication: a prober with no secret gets
//     32 bytes of nonsense back.
//   - The server answers with a ServerHello, a ChangeCipherSpec and a
//     certificate record. Its own random must satisfy a second HMAC, this time
//     over the client's random plus the whole reply, so a client can tell a
//     real proxy from a mirror that just replays bytes.
//   - After that the MTProto stream runs inside TLS application records.

const (
	// Record types, from the TLS record layer.
	fakeTLSRecordChangeCipherSpec = 0x14
	fakeTLSRecordAlert            = 0x15
	fakeTLSRecordHandshake        = 0x16
	fakeTLSRecordApplication      = 0x17

	// Handshake message types.
	fakeTLSClientHelloMsg = 0x01
	fakeTLSServerHelloMsg = 0x02

	// A ClientHello is at most 16KB plus overhead; anything larger is not one.
	fakeTLSMaxRecord = 16384 + 24

	// The offsets below are fixed by the layout: a record header is 5 bytes, a
	// handshake header is 4, and the random follows 2 bytes of protocol version.
	fakeTLSServerRandomOffset = 11

	// fakeTLSTimeSkew is how far the client's clock is allowed to be off before
	// the hello is treated as a replay rather than a live client.
	fakeTLSTimeSkew = 8 * time.Hour
)

// fakeTLSRecord is one TLS record.
type fakeTLSRecord struct {
	Type byte
	Data []byte
}

func writeFakeTLSRecord(w io.Writer, recType byte, data []byte) error {
	header := [5]byte{recType, fakeTLSVersion3[0], fakeTLSVersion3[1], 0, 0}
	binary.BigEndian.PutUint16(header[3:], uint16(len(data)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func readFakeTLSRecord(r io.Reader) (fakeTLSRecord, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return fakeTLSRecord{}, err
	}
	length := binary.BigEndian.Uint16(header[3:])
	if length > fakeTLSMaxRecord {
		return fakeTLSRecord{}, fmt.Errorf("fake tls record is %d bytes, too big", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return fakeTLSRecord{}, err
	}
	return fakeTLSRecord{Type: header[0], Data: data}, nil
}

// fakeTLSClientHello is what the handshake yields: the shared secret that
// matched, and the domain the client claimed to be visiting.
type fakeTLSClientHello struct {
	Secret []byte
	Domain string
	Random [32]byte
}

// fakeTLSHandshake performs the server half and returns the connection wrapped
// in the record layer, ready to carry the obfuscated2 stream.
//
// secrets is tried in turn: the client's random is the HMAC of its own hello
// under the secret it was given, so only the right key produces a match.
func fakeTLSHandshake(conn net.Conn, secrets mtprotoSecrets, now time.Time) (*fakeTLSRecordConn, *fakeTLSClientHello, error) {
	record, err := readFakeTLSRecord(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("read fake tls hello: %w", err)
	}
	if record.Type != fakeTLSRecordHandshake {
		return nil, nil, fmt.Errorf("expected a handshake record, got type %#x", record.Type)
	}
	if len(record.Data) < 4 || record.Data[0] != fakeTLSClientHelloMsg {
		return nil, nil, fmt.Errorf("expected a ClientHello, got message type %#x", record.Data[0])
	}

	// The HMAC covers the record exactly as it arrived, so the bytes are kept
	// intact and only a copy is modified for the comparison.
	hello := record.Data[4:]

	domain, err := fakeTLSHelloDomain(hello)
	if err != nil {
		return nil, nil, err
	}

	matched, err := fakeTLSMatchSecret(hello, secrets, now)
	if err != nil {
		return nil, nil, err
	}

	info := &fakeTLSClientHello{
		Secret: matched,
		Domain: domain,
	}
	copy(info.Random[:], hello[2:34])

	if err := writeFakeTLSServerResponse(conn, info, matched); err != nil {
		return nil, nil, fmt.Errorf("write fake tls response: %w", err)
	}
	return newFakeTLSRecordConn(conn), info, nil
}

// fakeTLSMatchSecret finds the secret a hello was made with. The random is an
// HMAC over the hello with itself zeroed, so a mismatch is simply "no match" --
// there is nothing to give up on, and nothing leaks beyond the timing.
func fakeTLSMatchSecret(hello []byte, secrets mtprotoSecrets, now time.Time) ([]byte, error) {
	if len(hello) < 34 {
		return nil, fmt.Errorf("ClientHello is %d bytes, too short to carry a random", len(hello))
	}
	var presented [32]byte
	copy(presented[:], hello[2:34])

	// Zero the random in place for the HMAC, then put it back.
	original := append([]byte(nil), hello[2:34]...)
	defer copy(hello[2:34], original)

	for _, secret := range secrets {
		for i := 2; i < 34; i++ {
			hello[i] = 0
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write(hello)
		want := mac.Sum(nil)

		if !hmac.Equal(want[:28], presented[:28]) {
			continue
		}
		// The last four bytes carry the client's clock, so a hello replayed
		// hours later is refused rather than served.
		got := binary.LittleEndian.Uint32(presented[28:32]) ^ binary.LittleEndian.Uint32(want[28:32])
		if skew := now.Sub(time.Unix(int64(got), 0)); skew > fakeTLSTimeSkew || skew < -fakeTLSTimeSkew {
			continue
		}
		return secret, nil
	}
	return nil, errors.New("no configured secret matched this fake TLS hello")
}

// fakeTLSHelloDomain pulls the server name out of the ClientHello's extensions.
// It is what the client claims to be visiting, which is also what a prober would
// believe it was reaching, so the reply has to look like it belongs to it.
func fakeTLSHelloDomain(hello []byte) (string, error) {
	pos := 2 + 32 // client version and random

	if pos >= len(hello) {
		return "", errors.New("ClientHello ended before the session id")
	}
	sessionLen := int(hello[pos])
	pos += 1 + sessionLen

	if pos+2 > len(hello) {
		return "", errors.New("ClientHello ended before the cipher suites")
	}
	suitesLen := int(binary.BigEndian.Uint16(hello[pos:]))
	pos += 2 + suitesLen

	if pos >= len(hello) {
		return "", errors.New("ClientHello ended before the compression methods")
	}
	compressionLen := int(hello[pos])
	pos += 1 + compressionLen

	if pos+2 > len(hello) {
		// No extensions at all: the client will not care, and neither does a
		// prober reading a site that speaks no extensions.
		return "", nil
	}
	extensionsLen := int(binary.BigEndian.Uint16(hello[pos:]))
	pos += 2
	end := pos + extensionsLen
	if end > len(hello) {
		return "", errors.New("ClientHello extensions overrun the message")
	}

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(hello[pos:])
		extLen := int(binary.BigEndian.Uint16(hello[pos+2:]))
		body := pos + 4
		if body+extLen > end {
			return "", errors.New("ClientHello extension overruns the message")
		}
		// 0x0000 is server_name.
		if extType == 0x0000 && extLen > 5 {
			nameLen := int(binary.BigEndian.Uint16(hello[body+3:]))
			if 5+nameLen <= extLen {
				return string(hello[body+5 : body+5+nameLen]), nil
			}
		}
		pos = body + extLen
	}
	return "", nil
}

// writeFakeTLSServerResponse sends the three records a client expects: the
// ServerHello, the ChangeCipherSpec, and a certificate record carrying the
// domain the client asked for.
func writeFakeTLSServerResponse(w io.Writer, info *fakeTLSClientHello, secret []byte) error {
	records := buildFakeTLSResponse(info, secret)

	// The client's random goes into the digest so that a mirror replaying
	// recorded bytes cannot pass as the real thing.
	var digestInput bytes.Buffer
	digestInput.Write(info.Random[:])
	digestInput.Write(records)

	// The server's random is at a fixed offset; it is zero while the HMAC is
	// taken over the rest of the reply.
	mac := hmac.New(sha256.New, secret)
	mac.Write(digestInput.Bytes())
	sum := mac.Sum(nil)
	copy(records[fakeTLSServerRandomOffset:fakeTLSServerRandomOffset+32], sum)

	_, err := w.Write(records)
	return err
}

// buildFakeTLSResponse assembles the reply records with the server's random
// left as zeros for the caller to fill in.
func buildFakeTLSResponse(info *fakeTLSClientHello, secret []byte) []byte {
	domain := info.Domain
	if domain == "" {
		domain = "example.com"
	}

	var body bytes.Buffer
	// ServerHello body: version, random (zeros here), session id, cipher
	// suite, compression, and a certificate extension naming the domain.
	body.Write(fakeTLSVersion3[:])
	body.Write(make([]byte, 32))
	body.WriteByte(32)             // session id length
	body.Write(info.Random[:])     // session id, echoing the client's
	body.Write([]byte{0xc0, 0x2f}) // cipher suite
	body.WriteByte(0x00)           // compression: none

	var extensions bytes.Buffer
	// A certificate extension, carrying the domain the client asked for. The
	// client does not validate the chain in this mode, but a prober reading the
	// bytes expects to find a name in here.
	cert := fakeTLSCertificateExtension(domain)
	extensions.Write([]byte{0x00, 0x00})                            // extension type: certificate
	extensions.Write([]byte{byte(len(cert) >> 8), byte(len(cert))}) // length
	extensions.Write(cert)

	body.Write([]byte{byte(len(extensions.Bytes()) >> 8), byte(len(extensions.Bytes()))})
	body.Write(extensions.Bytes())

	var handshake bytes.Buffer
	handshake.WriteByte(fakeTLSServerHelloMsg)
	handshake.Write([]byte{byte(len(body.Bytes()) >> 16), byte(len(body.Bytes()) >> 8), byte(len(body.Bytes()))})
	handshake.Write(body.Bytes())

	var records bytes.Buffer
	writeFakeTLSRecord(&records, fakeTLSRecordHandshake, handshake.Bytes())
	// ChangeCipherSpec, then a certificate record. Both are part of what a real
	// handshake looks like from the outside.
	writeFakeTLSRecord(&records, fakeTLSRecordChangeCipherSpec, []byte{0x01})
	writeFakeTLSRecord(&records, fakeTLSRecordApplication, fakeTLSCertificate(domain))

	return records.Bytes()
}

// fakeTLSCertificateExtension is the body of the extension that makes the reply
// name the domain the client asked for.
func fakeTLSCertificateExtension(domain string) []byte {
	cert := fakeTLSCertificate(domain)
	var ext bytes.Buffer
	// Certificate chain length, certificate length, then the DER.
	ext.Write([]byte{byte(len(cert) >> 16), byte(len(cert) >> 8), byte(len(cert))})
	ext.Write(cert)
	// Pad the structure out to the shape of a real one; the client skips over it.
	ext.Write(make([]byte, 16))
	return ext.Bytes()
}

// fakeTLSConn is the record layer after the handshake: MTProto bytes in and out,
// TLS records on the wire.
type fakeTLSRecordConn struct {
	conn       net.Conn
	buf        []byte
	sentCipher bool
}

func newFakeTLSRecordConn(conn net.Conn) *fakeTLSRecordConn {
	return &fakeTLSRecordConn{conn: conn}
}

func (c *fakeTLSRecordConn) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		record, err := readFakeTLSRecord(c.conn)
		if err != nil {
			return 0, err
		}
		switch record.Type {
		case fakeTLSRecordApplication:
			c.buf = record.Data
		case fakeTLSRecordChangeCipherSpec:
			// Part of the handshake, nothing to carry.
		case fakeTLSRecordAlert:
			return 0, fmt.Errorf("peer sent a TLS alert")
		default:
			return 0, fmt.Errorf("unexpected TLS record type %#x after the handshake", record.Type)
		}
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *fakeTLSRecordConn) Write(p []byte) (int, error) {
	// A real client sends ChangeCipherSpec before its first application record,
	// so the server does too: this is a camouflage, and the shape of the traffic
	// is the point.
	if !c.sentCipher {
		if err := writeFakeTLSRecord(c.conn, fakeTLSRecordChangeCipherSpec, []byte{0x01}); err != nil {
			return 0, err
		}
		c.sentCipher = true
	}
	// Records are limited in size, so a large write becomes several records.
	written := 0
	for written < len(p) {
		end := written + fakeTLSMaxRecord
		if end > len(p) {
			end = len(p)
		}
		if err := writeFakeTLSRecord(c.conn, fakeTLSRecordApplication, p[written:end]); err != nil {
			return written, err
		}
		written = end
	}
	return len(p), nil
}

func (c *fakeTLSRecordConn) Close() error { return c.conn.Close() }

// ─── The camouflage certificate ─────────────────────────────────────────────

var (
	fakeTLSCertsMu sync.Mutex
	fakeTLSCerts   = map[string][]byte{}
)

// fakeTLSCertificate returns a self-signed certificate for the domain the client
// claimed to be visiting.
//
// Generated per domain rather than shipped as a constant: a hardcoded
// certificate is a key everybody shares, and the client does not validate the
// chain in this mode, so there is nothing to gain from shipping one. It is
// generated once per domain and cached, because a prober that connects twice
// must not see two different certificates for the same site.
func fakeTLSCertificate(domain string) []byte {
	fakeTLSCertsMu.Lock()
	defer fakeTLSCertsMu.Unlock()

	if der, ok := fakeTLSCerts[domain]; ok {
		return der
	}

	der := generateFakeTLSCertificate(domain)
	fakeTLSCerts[domain] = der
	return der
}

func generateFakeTLSCertificate(domain string) []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		// A certificate is decoration here; the stream works without one, so
		// fall back to a minimal structure rather than refusing the client.
		return []byte{0x30, 0x00}
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		serial = big.NewInt(1)
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: domain, Organization: []string{"Cloudflare Inc."}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return []byte{0x30, 0x00}
	}
	return der
}

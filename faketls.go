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

// fakeTLSVersion3 is what both sides announce. Matching the version the
// reference client uses is part of looking ordinary.
var fakeTLSVersion3 = [2]byte{0x03, 0x03}

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
	rec, _, err := readFakeTLSRecordRaw(r)
	return rec, err
}

// readFakeTLSRecordRaw also returns the bytes exactly as they arrived, header
// included. The client's HMAC is taken over those precise bytes, so anything
// that re-serialises the record first computes a different digest and rejects
// every real client.
func readFakeTLSRecordRaw(r io.Reader) (fakeTLSRecord, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return fakeTLSRecord{}, nil, err
	}
	length := binary.BigEndian.Uint16(header[3:])
	if length > fakeTLSMaxRecord {
		return fakeTLSRecord{}, nil, fmt.Errorf("fake tls record is %d bytes, too big", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return fakeTLSRecord{}, nil, err
	}
	raw := make([]byte, 0, len(header)+len(data))
	raw = append(raw, header[:]...)
	raw = append(raw, data...)
	return fakeTLSRecord{Type: header[0], Data: data}, raw, nil
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
func fakeTLSHandshake(conn net.Conn, secrets mtprotoGrants, now time.Time, cloakHost string) (*fakeTLSRecordConn, *fakeTLSClientHello, error) {
	record, raw, err := readFakeTLSRecordRaw(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("read fake tls hello: %w", err)
	}
	if record.Type != fakeTLSRecordHandshake {
		return nil, nil, fmt.Errorf("expected a handshake record, got type %#x", record.Type)
	}
	if len(record.Data) < 4 || record.Data[0] != fakeTLSClientHelloMsg {
		return nil, nil, fmt.Errorf("expected a ClientHello, got message type %#x", record.Data[0])
	}

	// The HMAC is taken over the record as it arrived, header included, with the
	// random zeroed. Everything after the handshake is parsed from the same
	// bytes, so the offsets stay in one place.
	domain := fakeTLSHelloDomain(record.Data[4:])

	matched, err := fakeTLSMatchSecret(raw, secrets, now)
	if err != nil {
		return nil, nil, err
	}

	info := &fakeTLSClientHello{
		Secret: matched,
		Domain: domain,
	}
	copy(info.Random[:], raw[fakeTLSServerRandomOffset:fakeTLSServerRandomOffset+32])

	if err := writeFakeTLSServerResponse(conn, info, matched, cloakHost); err != nil {
		return nil, nil, fmt.Errorf("write fake tls response: %w", err)
	}
	return newFakeTLSRecordConn(conn), info, nil
}

// fakeTLSMatchSecret finds the secret a hello was made with. The random is an
// HMAC over the hello with itself zeroed, so a mismatch is simply "no match" --
// there is nothing to give up on, and nothing leaks beyond the timing.
func fakeTLSMatchSecret(raw []byte, secrets mtprotoGrants, now time.Time) ([]byte, error) {
	const randomAt = fakeTLSServerRandomOffset
	if len(raw) < randomAt+32 {
		return nil, fmt.Errorf("ClientHello is %d bytes, too short to carry a random", len(raw))
	}
	var presented [32]byte
	copy(presented[:], raw[randomAt:randomAt+32])

	// Zero the random for the HMAC, then put the client's bytes back.
	original := append([]byte(nil), raw[randomAt:randomAt+32]...)
	defer copy(raw[randomAt:randomAt+32], original)

	for _, grant := range secrets {
		for i := randomAt; i < randomAt+32; i++ {
			raw[i] = 0
		}
		mac := hmac.New(sha256.New, grant.key)
		mac.Write(raw)
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
		return grant.key, nil
	}
	return nil, errors.New("no configured secret matched this fake TLS hello")
}

// fakeTLSHelloDomain pulls the server name out of the ClientHello.
//
// It scans for a well-formed server_name extension rather than walking the
// message field by field, because the hellos these clients send are built by
// hand and do not always agree with their own length fields. A prober reading
// the reply expects a name in there; nothing depends on it being right, so a
// hello that does not contain one is not an error -- the caller falls back to a
// domain of its own.
func fakeTLSHelloDomain(hello []byte) string {
	for i := 0; i+5 < len(hello); i++ {
		// Extension type 0x0000 is server_name.
		if hello[i] != 0x00 || hello[i+1] != 0x00 {
			continue
		}
		extLen := int(binary.BigEndian.Uint16(hello[i+2:]))
		body := i + 4
		if extLen < 5 || body+extLen > len(hello) {
			continue
		}
		nameLen := int(binary.BigEndian.Uint16(hello[body+3:]))
		if 5+nameLen > extLen || nameLen == 0 || nameLen > 253 {
			continue
		}
		name := string(hello[body+5 : body+5+nameLen])
		if looksLikeHostname(name) {
			return name
		}
	}
	return ""
}

func looksLikeHostname(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == '_':
		default:
			return false
		}
	}
	return name != ""
}

// writeFakeTLSServerResponse sends the three records a client expects: the
// ServerHello, the ChangeCipherSpec, and a certificate record carrying the
// domain the client asked for.
func writeFakeTLSServerResponse(w io.Writer, info *fakeTLSClientHello, secret []byte, cloakHost string) error {
	records := buildFakeTLSResponse(info, secret, cloakHost)

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
func buildFakeTLSResponse(info *fakeTLSClientHello, secret []byte, cloakHost string) []byte {
	domain := info.Domain
	if domain == "" {
		// No usable name in the hello, so answer with the one this proxy is
		// configured to look like. Either way the bytes on the wire are a name.
		domain = cloakHost
	}
	if domain == "" {
		domain = "www.cloudflare.com"
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
	conn net.Conn
	buf  []byte
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
	// No ChangeCipherSpec is sent before the first application record. It looks
	// more like a TLS handshake without it, but the reference client treats a
	// ChangeCipherSpec as stream content rather than as handshake framing, so
	// sending one injects a stray 0x01 at the head of the MTProto stream and
	// desynchronises everything after it. The camouflage is not worth corrupting
	// the stream it is supposed to be hiding.
	//
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

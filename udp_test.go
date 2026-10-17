package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// ─── A minimal SOCKS5 UDP client ────────────────────────────────────────────
//
// There is no SOCKS5 UDP client in the standard library and adding one as a
// dependency for a test would be silly: the wire format is five fields, and
// writing them out here is also the clearest statement of what the relay is
// expected to understand.

type udpClient struct {
	t       *testing.T
	control net.Conn
	socket  *net.UDPConn
}

// associate performs the TCP handshake and UDP ASSOCIATE, returning the relay
// address the server chose.
func newUDPClient(t *testing.T, proxyAddr string) *udpClient {
	t.Helper()

	control, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { control.Close() })

	// Greeting: no-auth, for the tests that do not care about credentials.
	if _, err := control.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(control, sel); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	if sel[1] != 0x00 {
		t.Fatalf("server selected method 0x%02x, want no-auth", sel[1])
	}

	// UDP ASSOCIATE, with 0.0.0.0:0 as the suggestion.
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := control.Write(req); err != nil {
		t.Fatalf("associate: %v", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(control, head); err != nil {
		t.Fatalf("associate reply: %v", err)
	}
	if head[1] != replySucceeded {
		t.Fatalf("associate reply = 0x%02x, want success", head[1])
	}

	var host net.IP
	var port uint16
	switch head[3] {
	case addrTypeIPv4:
		buf := make([]byte, 6)
		io.ReadFull(control, buf)
		host, port = net.IP(buf[:4]), binary.BigEndian.Uint16(buf[4:])
	case addrTypeIPv6:
		buf := make([]byte, 18)
		io.ReadFull(control, buf)
		host, port = net.IP(buf[:16]), binary.BigEndian.Uint16(buf[16:])
	default:
		t.Fatalf("associate reply used address type %d", head[3])
	}
	if host.IsUnspecified() {
		host = net.IPv4(127, 0, 0, 1)
	}

	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host.String(), fmt.Sprint(port)))
	if err != nil {
		t.Fatalf("resolve relay socket: %v", err)
	}
	socket, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatalf("dial relay socket: %v", err)
	}
	t.Cleanup(func() { socket.Close() })

	return &udpClient{t: t, control: control, socket: socket}
}

// send wraps a payload and sends it to the destination through the relay.
func (c *udpClient) send(dest string, payload []byte) error {
	datagram, err := buildUDPDatagram(dest, payload)
	if err != nil {
		return err
	}
	_, err = c.socket.Write(datagram)
	return err
}

// receive reads one relayed datagram and returns its payload.
func (c *udpClient) receive(timeout time.Duration) ([]byte, error) {
	c.socket.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 65535)
	n, err := c.socket.Read(buf)
	if err != nil {
		return nil, err
	}
	_, payload, err := parseUDPDatagram(buf[:n])
	return payload, err
}

// echoServer answers every datagram with an uppercased copy.
func echoServer(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, rerr := conn.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			conn.WriteToUDP(bytes.ToUpper(buf[:n]), from)
		}
	}()
	return conn.LocalAddr().String()
}

// startUDPProxy runs a proxy with a fixed proxy port and returns its address.
func startUDPProxy(t *testing.T, mutate func(*Config)) string {
	t.Helper()
	cfg := DefaultConfig()
	cfg.AuthEnabled = false
	cfg.AdminEnabled = false
	cfg.SecurityHeadersEnabled = false
	cfg.RateLimitEnabled = false
	if mutate != nil {
		mutate(&cfg)
	}
	cfg.ProxyPort = freePort(t)

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.ProxyPort))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	server := NewProxyServer(cfg)
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go server.handleClient(conn, "")
		}
	}()
	return ln.Addr().String()
}

// ─── Tests ──────────────────────────────────────────────────────────────────

func TestUDPAssociateRoundTrip(t *testing.T) {
	proxy := startUDPProxy(t, nil)
	echo := echoServer(t)

	client := newUDPClient(t, proxy)
	if err := client.send(echo, []byte("hello dns")); err != nil {
		t.Fatalf("send: %v", err)
	}
	got, err := client.receive(5 * time.Second)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if string(got) != "HELLO DNS" {
		t.Errorf("relayed %q, want %q", got, "HELLO DNS")
	}
}

// Several destinations in one association, each on its own socket, replies
// routed back to the right one.
func TestUDPAssociationHandlesManyDestinations(t *testing.T) {
	proxy := startUDPProxy(t, nil)
	echo1 := echoServer(t)
	echo2 := echoServer(t)

	client := newUDPClient(t, proxy)
	for i, dest := range []string{echo1, echo2, echo1, echo2} {
		payload := []byte(fmt.Sprintf("packet-%d", i))
		if err := client.send(dest, payload); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		got, err := client.receive(5 * time.Second)
		if err != nil {
			t.Fatalf("receive %d: %v", i, err)
		}
		want := strings.ToUpper(string(payload))
		if string(got) != want {
			t.Errorf("destination %s: got %q, want %q", dest, got, want)
		}
	}
}

// UDP accounting must reach the same counters TCP does, or the dashboard shows
// a proxy that is carrying traffic nobody can see.
func TestUDPAssociationIsAccounted(t *testing.T) {
	echo := echoServer(t)
	cfg := DefaultConfig()
	cfg.AuthEnabled = false
	cfg.AdminEnabled = false
	cfg.SecurityHeadersEnabled = false
	cfg.RateLimitEnabled = false
	cfg.ProxyPort = freePort(t)

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.ProxyPort))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	server := NewProxyServer(cfg)
	before := server.totalConns.Load()
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go server.handleClient(conn, "")
		}
	}()

	client := newUDPClient(t, ln.Addr().String())
	if err := client.send(echo, []byte("counted")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if _, err := client.receive(5 * time.Second); err != nil {
		t.Fatalf("receive: %v", err)
	}
	if got := server.totalConns.Load(); got <= before {
		t.Errorf("total connections = %d, want more than %d: the UDP session was not accounted", got, before)
	}
}

// Fragmented datagrams are dropped rather than reassembled; the RFC allows a
// client to send them and says nothing about what a server should do, and
// guessing would mean unbounded buffering.
func TestUDPFragmentedDatagramIsDropped(t *testing.T) {
	proxy := startUDPProxy(t, nil)
	echo := echoServer(t)
	client := newUDPClient(t, proxy)

	datagram, err := buildUDPDatagram(echo, []byte("fragment"))
	if err != nil {
		t.Fatal(err)
	}
	datagram[2] = 1 // FRAG = 1: more fragments follow

	if _, err := client.socket.Write(datagram); err != nil {
		t.Fatal(err)
	}
	if _, err := client.receive(700 * time.Millisecond); err == nil {
		t.Error("a fragmented datagram was relayed; it must be dropped")
	}

	// The association must still work afterwards.
	if err := client.send(echo, []byte("after")); err != nil {
		t.Fatalf("send after fragment: %v", err)
	}
	if _, err := client.receive(5 * time.Second); err != nil {
		t.Fatalf("association unusable after a dropped fragment: %v", err)
	}
}

func TestUDPMalformedDatagramIsDropped(t *testing.T) {
	proxy := startUDPProxy(t, nil)
	echo := echoServer(t)
	client := newUDPClient(t, proxy)

	for _, bad := range [][]byte{
		{0x05},
		{0x00, 0x00, 0x00, 0x01, 1, 2, 3}, // truncated
		{0x01, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}, // RSV not zero
	} {
		if _, err := client.socket.Write(bad); err != nil {
			t.Fatalf("write malformed datagram: %v", err)
		}
	}
	if _, err := client.receive(700 * time.Millisecond); err == nil {
		t.Error("a malformed datagram was relayed")
	}
	if err := client.send(echo, []byte("still-alive")); err != nil {
		t.Fatalf("send after malformed datagrams: %v", err)
	}
	if got, err := client.receive(5 * time.Second); err != nil || string(got) != "STILL-ALIVE" {
		t.Errorf("after malformed datagrams: got %q, err %v", got, err)
	}
}

// The operator can turn UDP off, and then the client is told so rather than
// being left waiting for an address that never comes.
func TestUDPAssociateRefusedWhenDisabled(t *testing.T) {
	proxy := startUDPProxy(t, func(c *Config) { c.UDPEnabled = false })

	control, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer control.Close()
	control.Write([]byte{0x05, 0x01, 0x00})
	sel := make([]byte, 2)
	io.ReadFull(control, sel)
	control.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	head := make([]byte, 4)
	if _, err := io.ReadFull(control, head); err != nil {
		t.Fatalf("reply: %v", err)
	}
	if head[1] == replySucceeded {
		t.Error("UDP ASSOCIATE succeeded with udp_enabled=false")
	}
	if head[1] != replyCmdNotSupported {
		t.Errorf("reply = 0x%02x, want 0x%02x (command not supported)", head[1], replyCmdNotSupported)
	}
}

// Closing the control connection ends the association, which is how a client
// tells the server it is finished.
func TestUDPAssociationEndsWithControlConnection(t *testing.T) {
	proxy := startUDPProxy(t, nil)
	echo := echoServer(t)

	client := newUDPClient(t, proxy)
	if err := client.send(echo, []byte("alive")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if _, err := client.receive(5 * time.Second); err != nil {
		t.Fatalf("receive: %v", err)
	}

	client.control.Close()

	// After the control connection dies the relay socket stops answering. Give
	// the teardown a moment, then send into the void.
	time.Sleep(300 * time.Millisecond)
	if err := client.send(echo, []byte("after-close")); err == nil {
		if _, err := client.receive(time.Second); err == nil {
			t.Error("the relay socket still answers after the control connection closed")
		}
	}
}

// TCP is unaffected: an ordinary CONNECT still works on a proxy that also
// offers UDP.
func TestTCPConnectStillWorksAlongsideUDP(t *testing.T) {
	proxy := startUDPProxy(t, nil)

	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	defer origin.Close()
	go func() {
		conn, aerr := origin.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		io.WriteString(conn, "tcp-still-works")
	}()

	conn := socks5Connect(t, proxy, "127.0.0.1", origin.Addr().(*net.TCPAddr).Port)
	defer conn.Close()
	body := make([]byte, len("tcp-still-works"))
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != "tcp-still-works" {
		t.Errorf("got %q", body)
	}
}

// ─── Header encoding ────────────────────────────────────────────────────────

func TestUDPDatagramRoundTrip(t *testing.T) {
	for _, dest := range []string{
		"1.2.3.4:53",
		"[2001:db8::1]:5353",
		"dns.example.com:853",
	} {
		payload := []byte("payload for " + dest)
		datagram, err := buildUDPDatagram(dest, payload)
		if err != nil {
			t.Fatalf("build %s: %v", dest, err)
		}
		gotDest, gotPayload, err := parseUDPDatagram(datagram)
		if err != nil {
			t.Fatalf("parse %s: %v", dest, err)
		}
		if gotDest != dest {
			t.Errorf("destination %q round-tripped to %q", dest, gotDest)
		}
		if !bytes.Equal(gotPayload, payload) {
			t.Errorf("payload %q round-tripped to %q", payload, gotPayload)
		}
	}
}

func TestUDPDatagramRejectsGarbage(t *testing.T) {
	cases := map[string][]byte{
		"empty":            {},
		"short header":     {0, 0, 0, 1},
		"fragmented":       {0, 0, 1, 1, 127, 0, 0, 1, 0, 53, 1},
		"bad address type": {0, 0, 0, 9, 1, 2, 3, 4, 0, 53, 1},
		"truncated v4":     {0, 0, 0, 1, 127, 0},
		"reserved set":     {0, 9, 0, 1, 127, 0, 0, 1, 0, 53, 1},
	}
	for name, b := range cases {
		if _, _, err := parseUDPDatagram(b); err == nil {
			t.Errorf("%s: parseUDPDatagram accepted % x", name, b)
		}
	}
}

// A single control connection must not be able to ask for an unbounded number of
// destination sockets, because the TCP connection limit cannot see them.
func TestUDPDestinationCap(t *testing.T) {
	proxy := startUDPProxy(t, nil)
	client := newUDPClient(t, proxy)

	// Every destination answers, so each one stays open and the cap is the only
	// thing that can stop the association from opening more.
	answering := func(i int) string {
		conn, lerr := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if lerr != nil {
			t.Fatalf("echo listen %d: %v", i, lerr)
		}
		t.Cleanup(func() { conn.Close() })
		go func() {
			buf := make([]byte, 2048)
			for {
				n, from, rerr := conn.ReadFromUDP(buf)
				if rerr != nil {
					return
				}
				conn.WriteToUDP(buf[:n], from)
			}
		}()
		return conn.LocalAddr().String()
	}

	for i := 0; i < udpMaxTargets; i++ {
		if err := client.send(answering(i), []byte("fill")); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		if _, err := client.receive(5 * time.Second); err != nil {
			t.Fatalf("first udpMaxTargets destinations must all work, %d failed: %v", i, err)
		}
	}

	// The one past the cap is dropped. Nothing to wait for: silence is the
	// contract.
	if err := client.send(answering(udpMaxTargets), []byte("over")); err != nil {
		t.Fatalf("send past cap: %v", err)
	}
	client.socket.SetReadDeadline(time.Now().Add(750 * time.Millisecond))
	if _, err := client.socket.Read(make([]byte, 65535)); err == nil {
		t.Error("datagram past the destination cap was relayed")
	}
}

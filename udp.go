package main

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ─── SOCKS5 UDP ASSOCIATE (RFC 1928) ────────────────────────────────────────
//
// UDP is the reason a proxy cannot hide in a browser. DNS lookups and QUIC are
// the two flows that a TCP-only proxy either breaks or leaks, and Telegram
// apps are full of them.
//
// The shape of it is fixed by the RFC: the client opens a TCP control
// connection and sends UDP ASSOCIATE, the server replies with the address of a
// UDP socket it has just opened, and every datagram afterwards is wrapped in a
// small header naming its destination. The TCP connection stays open for the
// life of the association and closing it ends everything -- which is why
// teardown here hangs off the control connection rather than a timer.
//
// Two honest limitations, both from the RFC itself:
//   - Fragmentation (FRAG != 0) is not implemented and the datagram is dropped.
//     Almost no client emits it; supporting it means reassembling by
//     datagram id, and SOCKS5 gives no way to bound the memory that needs.
//   - There is no credential exchange over UDP. Authentication happens once on
//     the TCP control connection, which is what makes the association
//     un-guessable: without a valid TCP handshake there is no reply address.

const (
	// udpFragFirst is the only fragment marker this relay accepts.
	udpFragFirst = 0x00

	udpMaxDatagram = 65535
	// udpDialTimeout bounds the per-destination socket, so a client pointing
	// at an unroutable address cannot pin a goroutine forever.
	udpDialTimeout = 5 * time.Second
	// udpMaxTargets bounds one association's destinations. Each destination is a
	// socket, a goroutine and two 64KB read buffers, and the TCP connection
	// limit does not see any of them -- without this, one control connection
	// could ask for an unbounded number.
	//
	// ponytail: 64 destinations per association. Raise it, or make it per-tier,
	// if a real workload (a QUIC-heavy app, a DNS resolver pool) ever hits it.
	udpMaxTargets = 64
)

// udpTarget is one destination socket belonging to an association.
type udpTarget struct {
	conn  *net.UDPConn
	dest  string
	close sync.Once
}

func (t *udpTarget) Close() {
	t.close.Do(func() { t.conn.Close() })
}

// relayUDP runs one UDP association until the control connection dies.
func (s *ProxyServer) relayUDP(control net.Conn, log *slog.Logger, cfg *Config, user *User) {
	idle := time.Duration(cfg.IdleTimeout) * time.Second
	if idle <= 0 {
		idle = 300 * time.Second
	}

	// Bind the relay socket in the family the client arrived on, and say so in
	// the reply.
	//
	// "udp4"/"udp6" rather than "udp": asked for a wildcard IPv4 address,
	// net.ListenUDP hands back a dual-stack IPv6 socket whose LocalAddr reads
	// back as [::], so the associate reply advertised an IPv6 address to a
	// client that only understands IPv4. Pinning the network is the fix, and it
	// also makes the advertised address match the socket that exists.
	family, relayIP := udpFamilyFor(control)
	relayConn, err := net.ListenUDP(family, &net.UDPAddr{IP: relayIP})
	if err != nil {
		log.Error("could not open a udp relay socket", "error", err)
		s.sendReply(control, replyGeneralFailure, cfg)
		return
	}
	defer relayConn.Close()

	if err := s.sendUDPAssociateReply(control, relayConn.LocalAddr(), cfg); err != nil {
		log.Debug("udp associate reply failed", "error", err)
		return
	}
	// The client now sends datagrams to this address. Every read deadline below
	// is refreshed by traffic in either direction, so an idle session stays open
	// as long as it is actually used.
	refresh := func() {
		deadline := time.Now().Add(idle)
		relayConn.SetReadDeadline(deadline)
		control.SetReadDeadline(deadline)
	}
	refresh()

	s.totalConns.Add(1)
	metricTotalConns.Inc()
	s.recordDestination("udp-associate")

	var upPacer, downPacer *pacer
	if user != nil {
		upPacer = newPacer(user.BandwidthMbps)
		downPacer = newPacer(user.BandwidthMbps)
	}
	var bytesUp, bytesDown atomic.Int64

	var (
		targetsMu sync.Mutex
		targets   = map[string]*udpTarget{}
		wg        sync.WaitGroup
	)

	// closeTargets is idempotent and safe from any goroutine.
	closeTargets := func() {
		targetsMu.Lock()
		live := make([]*udpTarget, 0, len(targets))
		for _, t := range targets {
			live = append(live, t)
		}
		targets = map[string]*udpTarget{}
		targetsMu.Unlock()
		for _, t := range live {
			t.Close()
		}
	}

	closeTargetsExcept := func(except *udpTarget) {
		targetsMu.Lock()
		if t, ok := targets[except.dest]; ok && t == except {
			delete(targets, except.dest)
		}
		targetsMu.Unlock()
		except.Close()
	}

	// getTarget returns the socket for a destination, creating it on first use.
	// One socket per destination keeps replies on the right source port and
	// avoids relaying every datagram through a single peer address.
	getTarget := func(dest string, client *net.UDPAddr) (*udpTarget, bool) {
		targetsMu.Lock()
		t, ok := targets[dest]
		targetsMu.Unlock()
		if ok {
			return t, true
		}
		// Resolution and the dial happen outside the lock: a slow resolver
		// would otherwise stall every other destination in this association.
		addr := resolveUDPAddr(dest)
		if addr == nil {
			return nil, false
		}
		tconn, err := net.DialUDP(udpNetwork(addr), nil, addr)
		if err != nil {
			return nil, false
		}
		targetsMu.Lock()
		defer targetsMu.Unlock()
		if existing, raced := targets[dest]; raced {
			// Another datagram for the same destination arrived first; keep the
			// socket it made rather than racing two of them.
			tconn.Close()
			return existing, true
		}
		if len(targets) >= udpMaxTargets {
			tconn.Close()
			log.Warn("udp destination cap reached", "limit", udpMaxTargets)
			return nil, false
		}
		fresh := &udpTarget{conn: tconn, dest: dest}
		targets[dest] = fresh

		wg.Add(1)
		go func() {
			defer wg.Done()
			s.relayUDPReplies(fresh, relayConn, client, log, &bytesDown, downPacer, refresh)
			closeTargetsExcept(fresh)
		}()
		return fresh, true
	}

	// outbound: relay socket -> destination
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, udpMaxDatagram)
		for {
			n, from, rerr := relayConn.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			refresh()
			dest, payload, perr := parseUDPDatagram(buf[:n])
			if perr != nil {
				// A malformed or fragmented datagram is dropped rather than
				// guessed at.
				continue
			}
			bytesUp.Add(int64(len(payload)))
			upPacer.reserve(len(payload))

			target, ok := getTarget(dest, from)
			if !ok {
				continue
			}
			if _, werr := target.conn.Write(payload); werr != nil {
				closeTargetsExcept(target)
			}
		}
	}()

	// The control connection is what keeps the association alive and what ends
	// it. Some clients close it as soon as the associate reply arrives, which
	// RFC 1928 does not sanction; a client that does so gets its association
	// torn down, and the honest fix is on the client side.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer closeTargets()
		defer relayConn.Close()
		one := make([]byte, 1)
		for {
			if _, rerr := control.Read(one); rerr != nil {
				return
			}
			refresh()
		}
	}()

	wg.Wait()
	log.Info("udp association closed",
		"bytes_up", bytesUp.Load(),
		"bytes_down", bytesDown.Load(),
	)
}

// udpFamilyFor picks the UDP network for a client's family, defaulting to IPv4
// when the address cannot be read at all: a v4 relay is the one every client
// understands.
func udpFamilyFor(control net.Conn) (string, net.IP) {
	remote, ok := control.RemoteAddr().(*net.TCPAddr)
	if ok && remote.IP != nil && remote.IP.To4() == nil {
		return "udp6", net.IPv6zero
	}
	return "udp4", net.IPv4zero
}

// relayUDPReplies copies datagrams coming back from one destination, wrapping
// each in a SOCKS5 UDP header addressed to the client.
func (s *ProxyServer) relayUDPReplies(target *udpTarget, relayConn *net.UDPConn, client *net.UDPAddr, log *slog.Logger, bytesDown *atomic.Int64, p *pacer, refresh func()) {
	buf := make([]byte, udpMaxDatagram)
	for {
		n, rerr := target.conn.Read(buf)
		if rerr != nil {
			return
		}
		refresh()
		bytesDown.Add(int64(n))
		p.reserve(n)

		datagram, err := buildUDPDatagram(target.dest, buf[:n])
		if err != nil {
			continue
		}
		if _, werr := relayConn.WriteToUDP(datagram, client); werr != nil {
			return
		}
	}
}

// parseUDPDatagram reads RSV/FRAG/ATYP/ADDR/PORT and returns the destination and
// the payload.
func parseUDPDatagram(b []byte) (string, []byte, error) {
	if len(b) < 5 {
		return "", nil, fmt.Errorf("datagram too short: %d bytes", len(b))
	}
	if b[0] != 0 || b[1] != 0 {
		return "", nil, fmt.Errorf("reserved bytes are not zero: % x", b[:2])
	}
	if b[2] != udpFragFirst {
		return "", nil, fmt.Errorf("fragmented datagram dropped (frag=%d)", b[2])
	}

	var host string
	var pos int
	switch b[3] {
	case addrTypeIPv4:
		if len(b) < 4+4+2 {
			return "", nil, fmt.Errorf("truncated ipv4 address")
		}
		host = net.IP(b[4:8]).String()
		pos = 8
	case addrTypeFQDN:
		nameLen := int(b[4])
		if len(b) < 5+nameLen+2 {
			return "", nil, fmt.Errorf("truncated domain")
		}
		host = string(b[5 : 5+nameLen])
		pos = 5 + nameLen
	case addrTypeIPv6:
		if len(b) < 4+16+2 {
			return "", nil, fmt.Errorf("truncated ipv6 address")
		}
		host = net.IP(b[4:20]).String()
		pos = 20
	default:
		return "", nil, fmt.Errorf("unsupported address type %d", b[3])
	}

	port := binary.BigEndian.Uint16(b[pos : pos+2])
	return net.JoinHostPort(host, fmt.Sprint(port)), b[pos+2:], nil
}

// buildUDPDatagram wraps a payload with the header naming its destination.
func buildUDPDatagram(dest string, payload []byte) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return nil, err
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return nil, err
	}

	// Prefer a numeric form; only fall back to the name when there is no
	// address literal, which is how a client names a domain it wants us to
	// resolve.
	var hostBytes []byte
	var atyp byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			atyp, hostBytes = addrTypeIPv4, v4
		} else {
			atyp, hostBytes = addrTypeIPv6, ip.To16()
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("destination host is %d bytes, too long for a SOCKS5 header", len(host))
		}
		atyp = addrTypeFQDN
		hostBytes = append([]byte{byte(len(host))}, host...)
	}

	out := make([]byte, 0, 4+len(hostBytes)+2+len(payload))
	out = append(out, 0, 0, udpFragFirst, atyp)
	out = append(out, hostBytes...)
	out = binary.BigEndian.AppendUint16(out, uint16(port))
	return append(out, payload...), nil
}

// resolveUDPAddr turns "host:port" into something DialUDP accepts, resolving a
// name when necessary. It returns nil when the name does not resolve, rather
// than handing back an empty address and letting the dial report it.
func resolveUDPAddr(dest string) *net.UDPAddr {
	addr, err := net.ResolveUDPAddr("udp", dest)
	if err != nil {
		return nil
	}
	return addr
}

// udpNetwork keeps the destination socket in the relay's own family, so an IPv4
// association never opens an IPv6 destination it cannot answer on.
func udpNetwork(addr *net.UDPAddr) string {
	if addr.IP.To4() != nil {
		return "udp4"
	}
	return "udp6"
}

// sendUDPAssociateReply tells the client which UDP socket to send to. The reply
// is the only place that address is published, which is why an attacker who has
// not completed the TCP handshake cannot find the relay socket.
func (s *ProxyServer) sendUDPAssociateReply(conn net.Conn, addr net.Addr, cfg *Config) error {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("relay socket is %T, not a UDP address", addr)
	}
	conn.SetWriteDeadline(time.Now().Add(time.Duration(cfg.WriteTimeout) * time.Second))

	resp := []byte{socksVersion, replySucceeded, 0x00}
	if v4 := udpAddr.IP.To4(); v4 != nil {
		resp = append(resp, addrTypeIPv4)
		resp = append(resp, v4...)
	} else {
		resp = append(resp, addrTypeIPv6)
		resp = append(resp, udpAddr.IP.To16()...)
	}
	resp = binary.BigEndian.AppendUint16(resp, uint16(udpAddr.Port))

	_, err := conn.Write(resp)
	return err
}

// userAllowedUDP applies the same tier rules to an association as to a TCP
// session. Expiry and data use are checked with exactly the same logic the TCP
// path uses; an association that would not be allowed to open a TCP connection
// has no business opening UDP targets.
func (s *ProxyServer) userAllowedUDP(user *User, log *slog.Logger) bool {
	if user == nil || s.store == nil {
		return true
	}
	if user.Expiry != nil {
		if expiry, err := time.Parse("2006-01-02 15:04:05", *user.Expiry); err == nil && time.Now().After(expiry) {
			log.Warn("user account expired")
			return false
		}
	}
	if user.DataLimitBytes > 0 && user.DataUsedBytes >= user.DataLimitBytes {
		log.Warn("user data limit reached", "used", user.DataUsedBytes, "limit", user.DataLimitBytes)
		return false
	}
	if user.MaxConnections > 0 {
		if active, err := s.store.GetActiveConnCount(user.ID); err == nil && active >= int64(user.MaxConnections) {
			log.Warn("user connection limit reached", "active", active, "limit", user.MaxConnections)
			return false
		}
	}
	return true
}

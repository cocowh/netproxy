package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	nctx "github.com/cocowh/netproxy/internal/core/context"
	"github.com/cocowh/netproxy/pkg/transport"
)

// UDPSession represents an active UDP forwarding session
type UDPSession struct {
	dialer transport.ProxyDialer
}

// NATSession represents an active NAT mapping
type NATSession struct {
	upstream   net.PacketConn
	clientAddr net.Addr
	targetAddr string
	lastUse    time.Time
}

const (
	udpIdleTimeout = 60 * time.Second
	udpBufferSize  = 65535
)

// establishUDPAssociate sets up a UDP relay for the client (TCP control channel)
func (h *socks5Handler) establishUDPAssociate(ctx context.Context, conn net.Conn) error {
	// 1. Determine Bind Address (BND.ADDR)
	var bndIP net.IP
	var bndPort int

	// Parse Local Address from TCP connection
	tcpLocalAddr, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("connection is not TCP")
	}

	if h.announceAddr != "" {
		// User configured specific announce address (e.g. public IP)
		host, portStr, err := net.SplitHostPort(h.announceAddr)
		if err == nil {
			bndIP = net.ParseIP(host)
			p, _ := strconv.Atoi(portStr)
			bndPort = p
		} else {
			bndIP = net.ParseIP(h.announceAddr)
			bndPort = tcpLocalAddr.Port
		}
	} else {
		// Use the address the client connected to
		bndIP = tcpLocalAddr.IP
		bndPort = tcpLocalAddr.Port
	}

	// 2. Send Reply
	reply := []byte{0x05, 0x00, 0x00, 0x01} // VER, REP, RSV, ATYP(IPv4)

	ip4 := bndIP.To4()
	if ip4 != nil {
		reply = append(reply, ip4...)
	} else {
		reply[3] = 0x04 // ATYP IPv6
		reply = append(reply, bndIP.To16()...)
	}

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(bndPort))
	reply = append(reply, portBuf...)

	if _, err := conn.Write(reply); err != nil {
		return err
	}

	// 3. Maintain Session
	tcpRemoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	clientKey := tcpRemoteAddr.IP.String()

	// Get Dialer from Context
	dialer, ok := ctx.Value(nctx.CtxKeyDialer).(transport.ProxyDialer)
	if !ok {
		dialer = &transport.DirectDialer{}
	}

	// Register Session
	session := &UDPSession{
		dialer: dialer,
	}
	h.sessions.Store(clientKey, session)
	defer h.sessions.Delete(clientKey)

	// Keep alive until TCP closes
	buf := make([]byte, 1)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			break
		}
	}
	return nil
}

// HandlePacket implements the PacketHandler interface.
func (h *socks5Handler) HandlePacket(ctx context.Context, conn net.PacketConn) error {
	// Create a child context to manage the lifecycle of the cleanup loop
	// When this function returns (connection closed), the cleanup loop should also stop.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start cleanup loop for NAT sessions
	go h.cleanupNATLoop(ctx)

	buf := make([]byte, udpBufferSize)

	for {
		n, clientAddr, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		// 1. Identify Client
		host, _, err := net.SplitHostPort(clientAddr.String())
		if err != nil {
			continue
		}

		// 2. Find Session
		var dialer transport.ProxyDialer
		if val, ok := h.sessions.Load(host); ok {
			dialer = val.(*UDPSession).dialer
		} else {
			// Strict SOCKS5: Drop packet if no TCP association from this IP
			// Optional: Allow if configured for "Implicit UDP"
			continue
		}

		// 3. Parse Header
		packet := buf[:n]
		if len(packet) < 10 || packet[0] != 0 || packet[1] != 0 {
			// Invalid SOCKS5 UDP header
			continue
		}

		// Extract Target
		atyp := packet[3]
		var targetAddr string
		var payload []byte

		switch atyp {
		case 1: // IPv4
			if len(packet) < 10 {
				continue
			}
			ip := net.IP(packet[4:8])
			port := binary.BigEndian.Uint16(packet[8:10])
			targetAddr = fmt.Sprintf("%s:%d", ip.String(), port)
			payload = packet[10:]
		case 3: // Domain
			if len(packet) < 5 {
				continue
			}
			domainLen := int(packet[4])
			if len(packet) < 5+domainLen+2 {
				continue
			}
			domain := string(packet[5 : 5+domainLen])
			port := binary.BigEndian.Uint16(packet[5+domainLen : 5+domainLen+2])
			targetAddr = fmt.Sprintf("%s:%d", domain, port)
			payload = packet[5+domainLen+2:]
		case 4: // IPv6
			if len(packet) < 22 {
				continue
			}
			ip := net.IP(packet[4:20])
			port := binary.BigEndian.Uint16(packet[20:22])
			targetAddr = fmt.Sprintf("[%s]:%d", ip.String(), port)
			payload = packet[22:]
		default:
			continue
		}

		// 4. Forwarding (NAT Logic)
		natKey := clientAddr.String() + "@" + targetAddr

		h.natMu.Lock()
		natSession, exists := h.natTable[natKey]
		if exists {
			natSession.lastUse = time.Now()
		}
		h.natMu.Unlock()

		if !exists {
			// Create new upstream
			upstream, err := dialer.DialPacket(ctx, "udp", targetAddr)
			if err != nil {
				continue
			}

			natSession = &NATSession{
				upstream:   upstream,
				clientAddr: clientAddr,
				targetAddr: targetAddr,
				lastUse:    time.Now(),
			}

			h.natMu.Lock()
			h.natTable[natKey] = natSession
			h.natMu.Unlock()

			// Start Response Loop for this NAT session
			go h.handleNATResponse(conn, natSession, natKey)
		}

		// Send to upstream
		// Try resolving if needed (for ListenPacket based PacketConns)
		if _, err := natSession.upstream.WriteTo(payload, nil); err != nil {
			// If error, maybe it needs an address?
			rAddr, rErr := net.ResolveUDPAddr("udp", targetAddr)
			if rErr == nil {
				natSession.upstream.WriteTo(payload, rAddr)
			}
		}
	}
}

func (h *socks5Handler) handleNATResponse(clientConn net.PacketConn, session *NATSession, key string) {
	defer func() {
		session.upstream.Close()
		h.natMu.Lock()
		delete(h.natTable, key)
		h.natMu.Unlock()
	}()

	buf := make([]byte, udpBufferSize)

	for {
		session.upstream.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, srcAddr, err := session.upstream.ReadFrom(buf)
		if err != nil {
			return
		}

		// Wrap in SOCKS5 UDP Header
		header := make([]byte, 0, 300)
		header = append(header, 0, 0, 0) // RSV, FRAG, ATYP placeholder

		// Determine Source Address to report to client
		// Ideally use srcAddr from upstream, or targetAddr of session
		var rAddr *net.UDPAddr
		if srcAddr != nil {
			if udpAddr, ok := srcAddr.(*net.UDPAddr); ok {
				rAddr = udpAddr
			}
		}

		if rAddr == nil {
			// Fallback to session target addr
			if resolved, err := net.ResolveUDPAddr("udp", session.targetAddr); err == nil {
				rAddr = resolved
			}
		}

		if rAddr != nil {
			if ip4 := rAddr.IP.To4(); ip4 != nil {
				header = append(header, 1) // IPv4
				header = append(header, ip4...)
			} else {
				header = append(header, 4) // IPv6
				header = append(header, rAddr.IP.To16()...)
			}
			pBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(pBuf, uint16(rAddr.Port))
			header = append(header, pBuf...)
		} else {
			// Absolute fallback: 0.0.0.0:0 IPv4
			header = append(header, 1, 0, 0, 0, 0, 0, 0)
		}

		// Send back to client
		packet := append(header, buf[:n]...)
		clientConn.WriteTo(packet, session.clientAddr)
	}
}

func (h *socks5Handler) cleanupNATLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.natMu.Lock()
			now := time.Now()
			for k, session := range h.natTable {
				if now.Sub(session.lastUse) > udpIdleTimeout {
					// We can close the upstream here, which will cause ReadFrom in handleNATResponse to fail and exit
					session.upstream.Close()
					delete(h.natTable, k)
				}
			}
			h.natMu.Unlock()
		}
	}
}

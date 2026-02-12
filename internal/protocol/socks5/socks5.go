package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	nctx "github.com/cocowh/netproxy/internal/core/context"
	"github.com/cocowh/netproxy/internal/feature/auth"
	"github.com/cocowh/netproxy/pkg/protocol"
	"github.com/cocowh/netproxy/pkg/transport"
)

type socks5Handler struct {
	auth         auth.Authenticator
	announceAddr string
	sessions     sync.Map // Map[ClientIP]*UDPSession
	natTable     map[string]*NATSession
	natMu        sync.Mutex
}

// NewSOCKS5Handler creates a new SOCKS5 proxy handler
func NewSOCKS5Handler(authenticator auth.Authenticator, announceAddr string) (protocol.Handler, error) {
	return &socks5Handler{
		auth:         authenticator,
		announceAddr: announceAddr,
		natTable:     make(map[string]*NATSession),
	}, nil
}

func (h *socks5Handler) Handle(ctx context.Context, conn net.Conn) error {
	return h.handleSocks5(ctx, conn)
}

func (h *socks5Handler) handleSocks5(ctx context.Context, conn net.Conn) error {
	// 1. Version and Methods
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if buf[0] != 5 {
		return fmt.Errorf("unsupported version: %d", buf[0])
	}
	nMethods := int(buf[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	
	// 2. Select Method (We only support NoAuth (0) or UserPass (2) based on config)
	// We need to match what `go-socks5` would do.
	// If auth is enabled, we select 2. Else 0.
	selectedMethod := byte(0) // No Auth
	if h.auth != nil {
		selectedMethod = 2 // Username/ZINFOID_07Q
	}
	
	conn.Write([]byte{5, selectedMethod})
	
	// 3. Auth Handshake (if needed)
	if selectedMethod == 2 {
		// Expect: VER(1) ULEN USER PLEN PASS
		header := make([]byte, 2)
		if _, err := io.ReadFull(conn, header); err != nil { return err }
		if header[0] != 1 { return fmt.Errorf("unsupported auth version") }
		ulen := int(header[1])
		user := make([]byte, ulen)
		if _, err := io.ReadFull(conn, user); err != nil { return err }
		
		plenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, plenBuf); err != nil { return err }
		pass := make([]byte, int(plenBuf[0]))
		if _, err := io.ReadFull(conn, pass); err != nil { return err }
		
		// Verify
		if _, err := h.auth.Authenticate(ctx, string(user), string(pass)); err != nil {
			conn.Write([]byte{1, 1}) // Fail
			return err
		}
		conn.Write([]byte{1, 0}) // Success
	}
	
	// 4. Request
	// VER CMD RSV ATYP DST.ADDR DST.PORT
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil { return err }
	cmd := header[1]
	if cmd == 3 { // UDP ASSOCIATE
		return h.establishUDPAssociate(ctx, conn) // Implemented in udp.go
	} else if cmd == 1 { // CONNECT
		return h.handleConnect(ctx, conn, header[3])
	} else {
		return fmt.Errorf("unsupported command: %d", cmd)
	}
}

func (h *socks5Handler) handleConnect(ctx context.Context, conn net.Conn, atyp byte) error {
	// Parse Address
	targetAddr, isIPv6, err := h.parseAddress(conn, atyp)
	if err != nil {
		return err
	}

	// Dial Target
	dialer, ok := ctx.Value(nctx.CtxKeyDialer).(transport.ProxyDialer)
	if !ok {
		dialer = &transport.DirectDialer{}
	}

	destConn, err := dialer.Dial(ctx, "tcp", targetAddr)
	if err != nil {
		// Reply failure with appropriate address type
		if isIPv6 {
			// IPv6 failure response: VER REP RSV ATYP(4) ADDR(16) PORT(2)
			reply := make([]byte, 22)
			reply[0] = 5 // VER
			reply[1] = 4 // Host unreachable
			reply[2] = 0 // RSV
			reply[3] = 4 // ATYP IPv6
			// Rest is zeros (bind address)
			conn.Write(reply)
		} else {
			conn.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}) // Host unreachable (IPv4)
		}
		return err
	}
	defer destConn.Close()

	// Reply success with bound address
	reply := h.buildSuccessReply(destConn.LocalAddr())
	conn.Write(reply)

	// Relay
	return transport.Relay(conn, destConn)
}

// parseAddress parses the target address from SOCKS5 request.
// Returns the address string, whether it's IPv6, and any error.
func (h *socks5Handler) parseAddress(conn net.Conn, atyp byte) (string, bool, error) {
	switch atyp {
	case 1: // IPv4
		buf := make([]byte, 6) // IP(4) + Port(2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", false, err
		}
		ip := net.IP(buf[:4])
		port := int(buf[4])<<8 | int(buf[5])
		return fmt.Sprintf("%s:%d", ip, port), false, nil

	case 3: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", false, err
		}
		length := int(lenBuf[0])
		buf := make([]byte, length+2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", false, err
		}
		domain := string(buf[:length])
		port := int(buf[length])<<8 | int(buf[length+1])
		return fmt.Sprintf("%s:%d", domain, port), false, nil

	case 4: // IPv6
		buf := make([]byte, 18) // IP(16) + Port(2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", true, err
		}
		ip := net.IP(buf[:16])
		port := int(buf[16])<<8 | int(buf[17])
		return fmt.Sprintf("[%s]:%d", ip, port), true, nil

	default:
		// Send address type not supported error
		conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0}) // Address type not supported
		return "", false, fmt.Errorf("unsupported address type: %d", atyp)
	}
}

// buildSuccessReply builds a SOCKS5 success reply with the bound address.
func (h *socks5Handler) buildSuccessReply(localAddr net.Addr) []byte {
	// Default IPv4 reply
	reply := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}

	if localAddr == nil {
		return reply
	}

	tcpAddr, ok := localAddr.(*net.TCPAddr)
	if !ok {
		return reply
	}

	ip := tcpAddr.IP
	port := tcpAddr.Port

	// Check if IPv6
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4
		reply = make([]byte, 10)
		reply[0] = 5 // VER
		reply[1] = 0 // REP (success)
		reply[2] = 0 // RSV
		reply[3] = 1 // ATYP (IPv4)
		copy(reply[4:8], ip4)
		reply[8] = byte(port >> 8)
		reply[9] = byte(port)
	} else if len(ip) == net.IPv6len {
		// IPv6
		reply = make([]byte, 22)
		reply[0] = 5 // VER
		reply[1] = 0 // REP (success)
		reply[2] = 0 // RSV
		reply[3] = 4 // ATYP (IPv6)
		copy(reply[4:20], ip)
		reply[20] = byte(port >> 8)
		reply[21] = byte(port)
	}

	return reply
}

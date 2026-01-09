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
	var targetAddr string
	switch atyp {
	case 1: // IPv4
		buf := make([]byte, 6) // IP(4) + Port(2)
		if _, err := io.ReadFull(conn, buf); err != nil { return err }
		ip := net.IP(buf[:4])
		port := int(buf[4])<<8 | int(buf[5])
		targetAddr = fmt.Sprintf("%s:%d", ip, port)
	case 3: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil { return err }
		length := int(lenBuf[0])
		buf := make([]byte, length+2)
		if _, err := io.ReadFull(conn, buf); err != nil { return err }
		domain := string(buf[:length])
		port := int(buf[length])<<8 | int(buf[length+1])
		targetAddr = fmt.Sprintf("%s:%d", domain, port)
	default:
		return fmt.Errorf("unsupported address type: %d", atyp)
	}
	
	// Dial Target
	dialer, ok := ctx.Value(nctx.CtxKeyDialer).(transport.ProxyDialer)
	if !ok {
		dialer = &transport.DirectDialer{}
	}
	
	destConn, err := dialer.Dial(ctx, "tcp", targetAddr)
	if err != nil {
		// Reply failure
		conn.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}) // Host unreachable
		return err
	}
	defer destConn.Close()
	// Reply success
	// We should return bound address, but 0.0.0.0:0 is often accepted
	conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	
	// Relay
	return transport.Relay(conn, destConn)
}

package sps

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"

	"github.com/cocowh/netproxy/pkg/protocol"
)

type spsHandler struct {
	httpHandler    protocol.Handler
	socks5Handler  protocol.Handler
	defaultHandler protocol.Handler
}

// NewSPSHandler creates a new Smart Proxy Service handler
func NewSPSHandler(socks5, http, def protocol.Handler) protocol.Handler {
	return &spsHandler{
		httpHandler:    http,
		socks5Handler:  socks5,
		defaultHandler: def,
	}
}

func (h *spsHandler) HandlePacket(ctx context.Context, conn net.PacketConn) error {
	// SPS mode on UDP treats packets as SOCKS5 UDP Relay traffic.
	// We delegate directly to the SOCKS5 Handler's PacketHandler implementation.
	if ph, ok := h.socks5Handler.(protocol.PacketHandler); ok {
		return ph.HandlePacket(ctx, conn)
	}
	return errors.New("underlying SOCKS5 handler does not support packet handling")
}

func (h *spsHandler) Handle(ctx context.Context, conn net.Conn) error {
	// Check if this is a UDP connection
	// If it is, we cannot peek reliably or it might be single packet.
	// We should default to SOCKS5 (for UDP Associate) or just fail if not supported.
	// Note: conn.RemoteAddr().Network() might return "udp" or "udp4" or "udp6".
	network := conn.RemoteAddr().Network()
	if network == "udp" || network == "udp4" || network == "udp6" {
		return h.socks5Handler.Handle(ctx, conn)
	}

	// We need to peek at the first few bytes to determine protocol
	// Wrap conn in a buffered reader, but since we need to pass net.Conn to handlers,
	// we need a way to "put back" the peeked bytes or use a custom conn wrapper.
	
	peekedConn := newPeekedConn(conn)
	
	// Read first 3 bytes (SOCKS5 version is 1 byte, HTTP needs more to be sure)
	header, err := peekedConn.Peek(3)
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}

	// Check for SOCKS5 (Version 0x05)
	if header[0] == 0x05 {
		return h.socks5Handler.Handle(ctx, peekedConn)
	}

	// Check for HTTP
	// Methods: GET, POST, CONNECT, PUT, DELETE, HEAD, OPTIONS, TRACE, PATCH
	// We can check if it looks like an HTTP method
	if isHTTPMethod(header) {
		return h.httpHandler.Handle(ctx, peekedConn)
	}

	// Fallback
	// If it doesn't match known protocols, and we have a default handler, use it.
	// But check if we exhausted our checks.
	if h.defaultHandler != nil {
		return h.defaultHandler.Handle(ctx, peekedConn)
	}

	return errors.New("unknown protocol")
}

func isHTTPMethod(b []byte) bool {
	// We expect at least 3 bytes because we Peek(3)
	if len(b) < 3 {
		return false
	}

	// Check 3-byte prefixes for common HTTP methods
	prefix := string(b[:3])
	switch prefix {
	case "GET", "POS", "PUT", "DEL", "HEA", "OPT", "CON", "TRA", "PAT":
		return true
	}
	
	return false
}


// peekedConn implements net.Conn and allows peeking without consuming
type peekedConn struct {
	net.Conn
	br *bufio.Reader
}

func newPeekedConn(c net.Conn) *peekedConn {
	return &peekedConn{
		Conn: c,
		br:   bufio.NewReader(c),
	}
}

func (c *peekedConn) Peek(n int) ([]byte, error) {
	return c.br.Peek(n)
}

func (c *peekedConn) Read(b []byte) (int, error) {
	return c.br.Read(b)
}

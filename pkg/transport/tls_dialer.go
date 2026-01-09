package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"
)

// TLSDialer wraps a ProxyDialer with TLS
type TLSDialer struct {
	next   ProxyDialer
	config *tls.Config
}

// NewTLSDialer creates a new TLSDialer
func NewTLSDialer(next ProxyDialer, config *tls.Config) ProxyDialer {
	return &TLSDialer{
		next:   next,
		config: config,
	}
}

// Dial dials the address and performs TLS handshake
func (d *TLSDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.next.Dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	// Determine server name for SNI
	host, _, _ := net.SplitHostPort(addr)
	config := d.config.Clone()
	if config.ServerName == "" {
		config.ServerName = host
	}

	tlsConn := tls.Client(conn, config)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tls handshake failed: %w", err)
	}

	return tlsConn, nil
}

// DialPacket establishes a TLS connection and returns a PacketConn interface
// using length-prefixed protocol for UDP over TLS
func (d *TLSDialer) DialPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	// Establish TLS connection to the target (Relay)
	conn, err := d.Dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	return NewStreamPacketConn(conn), nil
}

// StreamPacketConn implements net.PacketConn over a stream (TCP/TLS/WS)
// utilizing a simple Length-Prefixed protocol: [Length: uint16][Body]
type StreamPacketConn struct {
	conn net.Conn
}

func NewStreamPacketConn(conn net.Conn) *StreamPacketConn {
	return &StreamPacketConn{conn: conn}
}

func (c *StreamPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// Read Length (2 bytes)
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.conn, lenBuf); err != nil {
		return 0, nil, err
	}
	length := int(lenBuf[0])<<8 | int(lenBuf[1])

	if length > len(p) {
		// Read full packet into temp buffer then copy.
		buf := make([]byte, length)
		if _, err := io.ReadFull(c.conn, buf); err != nil {
			return 0, nil, err
		}
		n = copy(p, buf)
		return n, c.conn.RemoteAddr(), nil
	}

	// Read Body
	if _, err := io.ReadFull(c.conn, p[:length]); err != nil {
		return 0, nil, err
	}
	
	return length, c.conn.RemoteAddr(), nil
}

func (c *StreamPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// Check max length
	if len(p) > 65535 {
		return 0, fmt.Errorf("packet too large")
	}
	
	// We ignore 'addr' because the stream is connected to a specific remote.
	buf := make([]byte, 2+len(p))
	buf[0] = byte(len(p) >> 8)
	buf[1] = byte(len(p))
	copy(buf[2:], p)
	
	if _, err := c.conn.Write(buf); err != nil {
		return 0, err
	}
	
	return len(p), nil
}

func (c *StreamPacketConn) Close() error {
	return c.conn.Close()
}

func (c *StreamPacketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *StreamPacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *StreamPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *StreamPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

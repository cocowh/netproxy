package udp

import (
	"context"
	"net"
	"time"

	"github.com/cocowh/netproxy/pkg/transport"
)

type udpTransport struct {
	timeout time.Duration
}

// NewUDPTransport creates a new UDP transporter
func NewUDPTransport(timeout time.Duration) transport.Transporter {
	return &udpTransport{
		timeout: timeout,
	}
}

func (t *udpTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{
		Timeout: t.timeout,
	}
	// Dialing UDP creates a connected UDP socket
	return d.DialContext(ctx, "udp", addr)
}

func (t *udpTransport) Listen(ctx context.Context, addr string) (net.Listener, error) {
	// UDP does not support stream Listener directly.
	// We could implement a wrapper if needed, but for now we return error.
	return nil, net.UnknownNetworkError("udp does not support Listen (use ListenPacket)")
}

func (t *udpTransport) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	lc := net.ListenConfig{}
	return lc.ListenPacket(ctx, "udp", addr)
}

func (t *udpTransport) DialPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	lc := net.ListenConfig{}
	// UDP usually dials by binding local port or just sending.
	// DialPacket usually implies returning a socket that CAN send to addr.
	// But PacketConn is connectionless.
	// If we want a PacketConn bound to a random port, ready to send to addr (via WriteTo),
	// we just ListenPacket("", ":0").
	return lc.ListenPacket(ctx, "udp", ":0")
}

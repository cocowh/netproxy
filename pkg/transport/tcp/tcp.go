package tcp

import (
	"context"
	"net"
	"time"

	"github.com/cocowh/netproxy/pkg/transport"
)

type tcpTransport struct {
	timeout   time.Duration
	keepAlive time.Duration
}

// NewTCPTransport creates a new TCP transporter
func NewTCPTransport(timeout, keepAlive time.Duration) transport.Transporter {
	return &tcpTransport{
		timeout:   timeout,
		keepAlive: keepAlive,
	}
}

func (t *tcpTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{
		Timeout:   t.timeout,
		KeepAlive: t.keepAlive,
	}
	return d.DialContext(ctx, "tcp", addr)
}

func (t *tcpTransport) Listen(ctx context.Context, addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		KeepAlive: t.keepAlive,
	}
	return lc.Listen(ctx, "tcp", addr)
}

func (t *tcpTransport) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	// TCP does not support PacketConn
	return nil, net.UnknownNetworkError("tcp does not support ListenPacket")
}

func (t *tcpTransport) DialPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	return nil, net.UnknownNetworkError("tcp does not support DialPacket")
}

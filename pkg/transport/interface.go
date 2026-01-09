package transport

import (
	"context"
	"net"
)

// Transporter defines the common behavior for transport layer
type Transporter interface {
	// Dial establishes a connection to a remote address
	Dial(ctx context.Context, addr string) (net.Conn, error)

	// DialPacket establishes a packet connection to a remote address
	DialPacket(ctx context.Context, addr string) (net.PacketConn, error)

	// Listen announces on the local network address
	Listen(ctx context.Context, addr string) (net.Listener, error)

	// ListenPacket announces on the local network address for packet-oriented protocols
	ListenPacket(ctx context.Context, addr string) (net.PacketConn, error)
}

// Factory is a function that creates a Transporter instance
type Factory func(options interface{}) Transporter

// ProxyDialer defines the interface for dialing through a proxy
type ProxyDialer interface {
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
	DialPacket(ctx context.Context, network, addr string) (net.PacketConn, error)
}

// DirectDialer implements ProxyDialer for direct connections
type DirectDialer struct{}

func (d *DirectDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

func (d *DirectDialer) DialPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	if network == "" {
		network = "udp"
	}
	conn, err := net.ListenPacket(network, "")
	if err != nil {
		return nil, err
	}
	return conn, nil
}

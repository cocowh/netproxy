// Package tproxy provides transparent proxy support for Linux and macOS.
package tproxy

import (
	"context"
	"net"

	"github.com/cocowh/netproxy/pkg/protocol"
)

// Handler defines the interface for transparent proxy handlers.
type Handler interface {
	protocol.Handler
	// GetOriginalDst returns the original destination address for a connection.
	GetOriginalDst(conn net.Conn) (net.Addr, error)
}

// Config holds configuration for transparent proxy.
type Config struct {
	// ListenAddr is the address to listen on for transparent proxy.
	ListenAddr string `json:"listen_addr"`

	// Mark is the fwmark value for routing (Linux only).
	Mark int `json:"mark"`

	// EnableIPv6 enables IPv6 support.
	EnableIPv6 bool `json:"enable_ipv6"`

	// TCPEnabled enables TCP transparent proxy.
	TCPEnabled bool `json:"tcp_enabled"`

	// UDPEnabled enables UDP transparent proxy.
	UDPEnabled bool `json:"udp_enabled"`
}

// DefaultConfig returns the default transparent proxy configuration.
func DefaultConfig() *Config {
	return &Config{
		ListenAddr: ":12345",
		Mark:       1,
		EnableIPv6: false,
		TCPEnabled: true,
		UDPEnabled: true,
	}
}

// Listener wraps a net.Listener with transparent proxy capabilities.
type Listener interface {
	net.Listener
	// GetOriginalDst returns the original destination for a connection.
	GetOriginalDst(conn net.Conn) (net.Addr, error)
}

// PacketListener wraps a net.PacketConn with transparent proxy capabilities.
type PacketListener interface {
	net.PacketConn
	// GetOriginalDst returns the original destination for a packet.
	GetOriginalDst(oob []byte) (net.Addr, error)
}

// NewHandler creates a new transparent proxy handler for the current platform.
func NewHandler(config *Config, dialer interface{}) (Handler, error) {
	return newPlatformHandler(config, dialer)
}

// NewListener creates a new transparent proxy listener for the current platform.
func NewListener(ctx context.Context, config *Config) (Listener, error) {
	return newPlatformListener(ctx, config)
}

// NewPacketListener creates a new transparent proxy packet listener.
func NewPacketListener(ctx context.Context, config *Config) (PacketListener, error) {
	return newPlatformPacketListener(ctx, config)
}

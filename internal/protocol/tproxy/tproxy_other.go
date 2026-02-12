//go:build !linux && !darwin

// Package tproxy provides transparent proxy support stub for unsupported platforms.
package tproxy

import (
	"context"
	"fmt"
	"net"
)

// tproxyHandler is a stub for unsupported platforms.
type tproxyHandler struct {
	config *Config
}

// newPlatformHandler returns an error on unsupported platforms.
func newPlatformHandler(config *Config, dialer interface{}) (Handler, error) {
	return nil, fmt.Errorf("transparent proxy is not supported on this platform")
}

// Handle is not implemented on unsupported platforms.
func (h *tproxyHandler) Handle(ctx context.Context, conn net.Conn) error {
	return fmt.Errorf("transparent proxy is not supported on this platform")
}

// GetOriginalDst is not implemented on unsupported platforms.
func (h *tproxyHandler) GetOriginalDst(conn net.Conn) (net.Addr, error) {
	return nil, fmt.Errorf("transparent proxy is not supported on this platform")
}

// tproxyListener is a stub for unsupported platforms.
type tproxyListener struct {
	net.Listener
}

// newPlatformListener returns an error on unsupported platforms.
func newPlatformListener(ctx context.Context, config *Config) (Listener, error) {
	return nil, fmt.Errorf("transparent proxy is not supported on this platform")
}

// GetOriginalDst is not implemented on unsupported platforms.
func (l *tproxyListener) GetOriginalDst(conn net.Conn) (net.Addr, error) {
	return nil, fmt.Errorf("transparent proxy is not supported on this platform")
}

// tproxyPacketListener is a stub for unsupported platforms.
type tproxyPacketListener struct {
	net.PacketConn
}

// newPlatformPacketListener returns an error on unsupported platforms.
func newPlatformPacketListener(ctx context.Context, config *Config) (PacketListener, error) {
	return nil, fmt.Errorf("transparent proxy is not supported on this platform")
}

// GetOriginalDst is not implemented on unsupported platforms.
func (l *tproxyPacketListener) GetOriginalDst(oob []byte) (net.Addr, error) {
	return nil, fmt.Errorf("transparent proxy is not supported on this platform")
}

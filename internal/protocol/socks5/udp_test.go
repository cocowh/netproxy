package socks5

import (
	"context"
	"net"
	"testing"
	"time"

	nctx "github.com/cocowh/netproxy/internal/core/context"
	"github.com/cocowh/netproxy/internal/transport"
)

// MockPacketConn for testing
type mockPacketConn struct {
	net.PacketConn
	readChan  chan []byte
	writeChan chan []byte
}

func newMockPacketConn() *mockPacketConn {
	return &mockPacketConn{
		readChan:  make(chan []byte, 100),
		writeChan: make(chan []byte, 100),
	}
}

func (c *mockPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case data := <-c.readChan:
		copy(b, data)
		return len(data), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}, nil
	case <-time.After(1 * time.Second):
		return 0, nil, net.ErrClosed
	}
}

func (c *mockPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	data := make([]byte, len(b))
	copy(data, b)
	c.writeChan <- data
	return len(b), nil
}

func (c *mockPacketConn) Close() error {
	close(c.readChan)
	close(c.writeChan)
	return nil
}

func (c *mockPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}
}

func (c *mockPacketConn) SetReadDeadline(t time.Time) error { return nil }

// MockProxyDialer
type mockProxyDialer struct {
	transport.ProxyDialer
	conn *mockPacketConn
}

func (d *mockProxyDialer) DialPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	return d.conn, nil
}

func TestSOCKS5UDP(t *testing.T) {
	// Setup Handler
	h, _ := NewSOCKS5Handler(nil, "")
	sHandler := h.(*socks5Handler)

	// Mock Connections
	clientConn := newMockPacketConn()
	upstreamConn := newMockPacketConn()
	dialer := &mockProxyDialer{conn: upstreamConn}

	// Context with Dialer
	ctx := context.WithValue(context.Background(), nctx.CtxKeyDialer, dialer)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start Relay in goroutine
	go sHandler.runUDPRelay(ctx, clientConn, dialer)

	// 1. Send SOCKS5 UDP Packet from Client
	// RSV(2) FRAG(1) ATYP(1) DST.ADDR(4) DST.PORT(2) DATA
	payload := []byte("hello")
	packet := []byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 80} // Target 127.0.0.1:80
	packet = append(packet, payload...)

	clientConn.readChan <- packet

	// 2. Expect Upstream Write
	select {
	case data := <-upstreamConn.writeChan:
		if string(data) != string(payload) {
			t.Errorf("Expected payload %s, got %s", payload, data)
		}
	case <-time.After(1 * time.Second):
		t.Errorf("Timeout waiting for upstream write")
	}

	// 3. Send Response from Upstream
	responsePayload := []byte("world")
	upstreamConn.readChan <- responsePayload

	// 4. Expect Client Write (Encapsulated)
	select {
	case data := <-clientConn.writeChan:
		// Check header
		if len(data) < 10 {
			t.Errorf("Response too short")
		}
		// Skip header check for brevity, check payload
		// Header is variable length, but we know upstream src addr logic.
		// It might use upstreamConn.ReadFrom addr which is 127.0.0.1:12345 (mock default)
		// 127.0.0.1 -> ATYP 1 (10 bytes total header)
		if string(data[10:]) != string(responsePayload) {
			t.Errorf("Expected response %s, got %s", responsePayload, data[10:])
		}
	case <-time.After(1 * time.Second):
		t.Errorf("Timeout waiting for client write")
	}
}

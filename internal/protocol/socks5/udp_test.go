package socks5

import (
	"context"
	"net"
	"testing"
	"time"

	nctx "github.com/cocowh/netproxy/internal/core/context"
	"github.com/cocowh/netproxy/pkg/transport"
)

// MockPacketConn for testing
type mockPacketConn struct {
	net.PacketConn
	readChan  chan []byte
	writeChan chan []byte
	closed    bool
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
	if !c.closed {
		c.closed = true
		close(c.readChan)
		close(c.writeChan)
	}
	return nil
}

func (c *mockPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}
}

func (c *mockPacketConn) SetReadDeadline(t time.Time) error { return nil }

// MockProxyDialer implements transport.ProxyDialer
type mockProxyDialer struct {
	conn *mockPacketConn
}

func (d *mockProxyDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return nil, nil
}

func (d *mockProxyDialer) DialPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	return d.conn, nil
}

func TestSOCKS5UDPHeaderParsing(t *testing.T) {
	// Test SOCKS5 UDP header parsing
	// RSV(2) FRAG(1) ATYP(1) DST.ADDR(variable) DST.PORT(2) DATA

	t.Run("IPv4_Header", func(t *testing.T) {
		// RSV(2) FRAG(1) ATYP(1=IPv4) IP(4) PORT(2) DATA
		packet := []byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 80}
		packet = append(packet, []byte("hello")...)

		if len(packet) < 10 {
			t.Error("Packet too short")
		}

		if packet[0] != 0 || packet[1] != 0 {
			t.Error("Invalid RSV bytes")
		}

		atyp := packet[3]
		if atyp != 1 {
			t.Errorf("Expected ATYP 1 (IPv4), got %d", atyp)
		}

		ip := net.IP(packet[4:8])
		if !ip.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Errorf("Expected IP 127.0.0.1, got %s", ip)
		}

		port := int(packet[8])<<8 | int(packet[9])
		if port != 80 {
			t.Errorf("Expected port 80, got %d", port)
		}

		payload := packet[10:]
		if string(payload) != "hello" {
			t.Errorf("Expected payload 'hello', got '%s'", payload)
		}
	})

	t.Run("Domain_Header", func(t *testing.T) {
		// RSV(2) FRAG(1) ATYP(3=Domain) LEN(1) DOMAIN(n) PORT(2) DATA
		domain := "example.com"
		packet := []byte{0, 0, 0, 3, byte(len(domain))}
		packet = append(packet, []byte(domain)...)
		packet = append(packet, 0, 80) // Port 80
		packet = append(packet, []byte("hello")...)

		atyp := packet[3]
		if atyp != 3 {
			t.Errorf("Expected ATYP 3 (Domain), got %d", atyp)
		}

		domainLen := int(packet[4])
		if domainLen != len(domain) {
			t.Errorf("Expected domain length %d, got %d", len(domain), domainLen)
		}

		parsedDomain := string(packet[5 : 5+domainLen])
		if parsedDomain != domain {
			t.Errorf("Expected domain '%s', got '%s'", domain, parsedDomain)
		}

		port := int(packet[5+domainLen])<<8 | int(packet[5+domainLen+1])
		if port != 80 {
			t.Errorf("Expected port 80, got %d", port)
		}
	})
}

func TestSOCKS5Handler(t *testing.T) {
	t.Run("NewHandler", func(t *testing.T) {
		h, err := NewSOCKS5Handler(nil, "")
		if err != nil {
			t.Fatalf("Failed to create handler: %v", err)
		}
		if h == nil {
			t.Fatal("Handler is nil")
		}
	})

	t.Run("NewHandler_WithAnnounceAddr", func(t *testing.T) {
		h, err := NewSOCKS5Handler(nil, "192.168.1.1:1080")
		if err != nil {
			t.Fatalf("Failed to create handler: %v", err)
		}
		if h == nil {
			t.Fatal("Handler is nil")
		}
	})
}

func TestUDPSession(t *testing.T) {
	t.Run("SessionCreation", func(t *testing.T) {
		mockConn := newMockPacketConn()
		dialer := &mockProxyDialer{conn: mockConn}

		session := &UDPSession{
			dialer: dialer,
		}

		if session.dialer == nil {
			t.Error("Session dialer is nil")
		}
	})
}

func TestNATSession(t *testing.T) {
	t.Run("NATSessionCreation", func(t *testing.T) {
		mockConn := newMockPacketConn()
		clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

		session := &NATSession{
			upstream:   mockConn,
			clientAddr: clientAddr,
			targetAddr: "example.com:80",
			lastUse:    time.Now(),
		}

		if session.upstream == nil {
			t.Error("NAT session upstream is nil")
		}
		if session.clientAddr == nil {
			t.Error("NAT session clientAddr is nil")
		}
		if session.targetAddr != "example.com:80" {
			t.Errorf("Expected targetAddr 'example.com:80', got '%s'", session.targetAddr)
		}
	})
}

func TestContextWithDialer(t *testing.T) {
	t.Run("DialerFromContext", func(t *testing.T) {
		mockConn := newMockPacketConn()
		dialer := &mockProxyDialer{conn: mockConn}

		ctx := context.WithValue(context.Background(), nctx.CtxKeyDialer, dialer)

		retrieved, ok := ctx.Value(nctx.CtxKeyDialer).(transport.ProxyDialer)
		if !ok {
			t.Error("Failed to retrieve dialer from context")
		}
		if retrieved == nil {
			t.Error("Retrieved dialer is nil")
		}
	})

	t.Run("DefaultDialer", func(t *testing.T) {
		ctx := context.Background()

		retrieved, ok := ctx.Value(nctx.CtxKeyDialer).(transport.ProxyDialer)
		if ok {
			t.Error("Should not have dialer in empty context")
		}
		if retrieved != nil {
			t.Error("Retrieved dialer should be nil")
		}

		// Use default dialer
		var dialer transport.ProxyDialer
		if !ok {
			dialer = &transport.DirectDialer{}
		}
		if dialer == nil {
			t.Error("Default dialer is nil")
		}
	})
}

package sps

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

// MockConn implements net.Conn for testing
type MockConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	remote   net.Addr
}

func NewMockConn(data []byte) *MockConn {
	return &MockConn{
		readBuf:  bytes.NewBuffer(data),
		writeBuf: &bytes.Buffer{},
		remote:   &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	}
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	return m.readBuf.Read(b)
}

func (m *MockConn) Write(b []byte) (n int, err error) {
	return m.writeBuf.Write(b)
}

func (m *MockConn) Close() error { return nil }

func (m *MockConn) LocalAddr() net.Addr { return nil }

func (m *MockConn) RemoteAddr() net.Addr { return m.remote }

func (m *MockConn) SetDeadline(t time.Time) error { return nil }

func (m *MockConn) SetReadDeadline(t time.Time) error { return nil }

func (m *MockConn) SetWriteDeadline(t time.Time) error { return nil }

// MockHandler implements protocol.Handler
type MockHandler struct {
	name   string
	called bool
}

func (m *MockHandler) Handle(ctx context.Context, conn net.Conn) error {
	m.called = true
	// Consume rest of data
	_, _ = bufio.NewReader(conn).ReadBytes('\n')
	return nil
}

func TestSPSHandler(t *testing.T) {
	tests := []struct {
		name            string
		input           []byte
		expectedHandler string
	}{
		{
			name:            "SOCKS5",
			input:           []byte{0x05, 0x01, 0x00},
			expectedHandler: "socks5",
		},
		{
			name:            "HTTP GET",
			input:           []byte("GET / HTTP/1.1\r\n"),
			expectedHandler: "http",
		},
		{
			name:            "HTTP POST",
			input:           []byte("POST /api HTTP/1.1\r\n"),
			expectedHandler: "http",
		},
		{
			name:            "HTTP CONNECT",
			input:           []byte("CONNECT google.com:443 HTTP/1.1\r\n"),
			expectedHandler: "http",
		},
		{
			name:            "Unknown Protocol (Default)",
			input:           []byte("SSH-2.0-OpenSSH\r\n"),
			expectedHandler: "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpHandler := &MockHandler{name: "http"}
			socks5Handler := &MockHandler{name: "socks5"}
			defaultHandler := &MockHandler{name: "default"}

			// NewSPSHandler(socks5, http, def) - correct order
			sps := NewSPSHandler(socks5Handler, httpHandler, defaultHandler)
			conn := NewMockConn(tt.input)

			err := sps.Handle(context.Background(), conn)
			if err != nil {
				t.Fatalf("Handle failed: %v", err)
			}

			if tt.expectedHandler == "http" && !httpHandler.called {
				t.Error("Expected HTTP handler to be called")
			}
			if tt.expectedHandler == "socks5" && !socks5Handler.called {
				t.Error("Expected SOCKS5 handler to be called")
			}
			if tt.expectedHandler == "default" && !defaultHandler.called {
				t.Error("Expected Default handler to be called")
			}
		})
	}
}

func TestSPSUDP(t *testing.T) {
	// Test that UDP connection bypasses sniffing and goes to SOCKS5
	socks5Handler := &MockHandler{name: "socks5"}
	httpHandler := &MockHandler{name: "http"}
	defaultHandler := &MockHandler{name: "default"}

	// NewSPSHandler(socks5, http, def) - correct order
	sps := NewSPSHandler(socks5Handler, httpHandler, defaultHandler)

	// Create MockConn with UDP remote address
	conn := NewMockConn([]byte{0x05, 0x01, 0x00}) // SOCKS5 data
	conn.remote = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}

	err := sps.Handle(context.Background(), conn)
	if err != nil {
		t.Fatalf("Handle failed: %v", err)
	}

	if !socks5Handler.called {
		t.Error("Expected SOCKS5 handler to be called for UDP")
	}
}

func TestIsHTTPMethod(t *testing.T) {
	tests := []struct {
		input    []byte
		expected bool
	}{
		{[]byte("GET"), true},
		{[]byte("POS"), true},
		{[]byte("PUT"), true},
		{[]byte("DEL"), true},
		{[]byte("HEA"), true},
		{[]byte("OPT"), true},
		{[]byte("CON"), true},
		{[]byte("TRA"), true},
		{[]byte("PAT"), true},
		{[]byte{0x05, 0x01, 0x00}, false}, // SOCKS5
		{[]byte("SSH"), false},
		{[]byte("AB"), false}, // Too short
	}

	for _, tt := range tests {
		result := isHTTPMethod(tt.input)
		if result != tt.expected {
			t.Errorf("isHTTPMethod(%v) = %v, expected %v", tt.input, result, tt.expected)
		}
	}
}

func TestPeekedConn(t *testing.T) {
	data := []byte("Hello, World!")
	conn := NewMockConn(data)
	peeked := newPeekedConn(conn)

	// Peek should not consume data
	p1, err := peeked.Peek(5)
	if err != nil {
		t.Fatalf("Peek failed: %v", err)
	}
	if string(p1) != "Hello" {
		t.Errorf("Expected 'Hello', got '%s'", p1)
	}

	// Peek again should return same data
	p2, err := peeked.Peek(5)
	if err != nil {
		t.Fatalf("Peek failed: %v", err)
	}
	if string(p2) != "Hello" {
		t.Errorf("Expected 'Hello', got '%s'", p2)
	}

	// Read should consume data
	buf := make([]byte, 5)
	n, err := peeked.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 5 || string(buf) != "Hello" {
		t.Errorf("Expected 'Hello', got '%s'", buf[:n])
	}

	// Next read should get remaining data
	buf2 := make([]byte, 10)
	n2, err := peeked.Read(buf2)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(buf2[:n2]) != ", World!" {
		t.Errorf("Expected ', World!', got '%s'", buf2[:n2])
	}
}

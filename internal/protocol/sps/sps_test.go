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
		name           string
		input          []byte
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

			sps := NewSPSHandler(httpHandler, socks5Handler, defaultHandler)
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
	sps := NewSPSHandler(nil, socks5Handler, nil)

	// Fix: Initialize MockConn fully using NewMockConn, then override remote
	conn := NewMockConn([]byte{})
	conn.remote = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}

	err := sps.Handle(context.Background(), conn)
	if err != nil {
		t.Fatalf("Handle failed: %v", err)
	}

	if !socks5Handler.called {
		t.Error("Expected SOCKS5 handler to be called for UDP")
	}
}

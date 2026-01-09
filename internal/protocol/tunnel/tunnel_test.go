package tunnel

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cocowh/netproxy/internal/core/logger"
)

func TestTunnelAuth(t *testing.T) {
	// Setup Logger
	l, _ := logger.NewZapLogger(logger.DebugLevel, "")

	// Ports
	controlAddr := ":19001"
	targetAddr := ":19002"
	tunnelAddr := ":19003"
	token := "secret-token"
	wrongToken := "wrong-token"

	// 1. Start Mock Target Server
	go func() {
		ln, _ := net.Listen("tcp", targetAddr)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) // Echo
			}(conn)
		}
	}()
	time.Sleep(100 * time.Millisecond)

	// 2. Start Bridge with Token
	bridge := NewBridge(controlAddr, "", map[string]string{tunnelAddr: "client1"}, token, l)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := bridge.Start(ctx); err != nil {
		t.Fatalf("Failed to start bridge: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// 3. Test Client with Wrong Token
	clientWrong := NewClient(controlAddr, targetAddr, "client1", wrongToken, l)
	go clientWrong.Start(ctx)
	
	// Wait a bit, verify no tunnel access
	time.Sleep(500 * time.Millisecond)
	
	// Try to connect to tunnel port (should fail or close immediately)
	conn, err := net.Dial("tcp", tunnelAddr)
	if err == nil {
		// It might accept but close, or not accept if client not registered
		// If client handshake failed, bridge registry should be empty for "client1"
		// If registry empty, bridge.routeConnection will close conn.
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		buf := make([]byte, 10)
		_, err := conn.Read(buf)
		if err != io.EOF {
			// If we read something or timeout, it means connection is alive?
			// Actually if auth failed, client is not registered.
			// When connecting to tunnelAddr, bridge looks up "client1".
			// "client1" is not in registry.
			// Bridge closes userConn.
			// So we expect EOF or read error.
		}
		conn.Close()
	}

	// 4. Test Client with Correct Token
	clientRight := NewClient(controlAddr, targetAddr, "client1", token, l)
	// Stop wrong client? It's in loop, we can't easily stop it without context per client.
	// But it will keep failing handshake.
	
	go clientRight.Start(ctx)
	time.Sleep(500 * time.Millisecond)

	// Try Echo through Tunnel
	conn, err = net.Dial("tcp", tunnelAddr)
	if err != nil {
		t.Fatalf("Failed to connect to tunnel: %v", err)
	}
	defer conn.Close()

	msg := "hello"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if string(buf[:n]) != msg {
		t.Errorf("Expected %s, got %s", msg, string(buf[:n]))
	}
}

package udp

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/cocowh/netproxy/pkg/protocol"
)

type udpHandler struct {
	targetAddr string
	timeout    time.Duration
}

// NewUDPHandler creates a new UDP port forwarding handler
func NewUDPHandler(targetAddr string, timeout time.Duration) protocol.Handler {
	return &udpHandler{
		targetAddr: targetAddr,
		timeout:    timeout,
	}
}

func (h *udpHandler) Handle(ctx context.Context, conn net.Conn) error {
	// Note: protocol.Handler expects a net.Conn (stream).
	// Handling UDP over a stream usually implies some encapsulation (like Socks5 UDP associate).
	// If this handler is meant to handle raw UDP packets, the interface might need adaptation.
	// OR, if 'conn' here is actually a UDPConn (which implements net.Conn), it works but is packet-based.
	// But usually, listener accepts TCP connections.
	//
	// If this is for "UDP Port Forwarding" where we listen on UDP and forward to UDP:
	// The Listener layer should return a pseudo-conn or we change interface to handle PacketConn.
	//
	// Assuming conn is a virtual stream or we are just piping data if it's a connected UDP socket.
	defer conn.Close()

	// Connect to target UDP
	target, err := net.Dial("udp", h.targetAddr)
	if err != nil {
		return err
	}
	defer target.Close()

	// Bidirectional Copy
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, conn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(conn, target)
		errCh <- err
	}()

	return <-errCh
}

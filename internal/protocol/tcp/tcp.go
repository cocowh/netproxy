package tcp

import (
	"context"
	"io"
	"net"

	"github.com/cocowh/netproxy/pkg/protocol"
)

type tcpHandler struct {
	targetAddr string
}

// NewTCPHandler creates a new TCP port forwarding handler
func NewTCPHandler(targetAddr string) protocol.Handler {
	return &tcpHandler{
		targetAddr: targetAddr,
	}
}

func (h *tcpHandler) Handle(ctx context.Context, conn net.Conn) error {
	defer conn.Close()

	// Connect to target
	target, err := net.Dial("tcp", h.targetAddr)
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

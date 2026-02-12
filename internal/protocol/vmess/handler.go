// Package vmess provides the VMess protocol handler for the proxy service.
package vmess

import (
	"context"
	"fmt"
	"io"
	"net"

	nctx "github.com/cocowh/netproxy/internal/core/context"
	"github.com/cocowh/netproxy/internal/feature/auth"
	"github.com/cocowh/netproxy/pkg/protocol"
	vmessproto "github.com/cocowh/netproxy/pkg/protocol/vmess"
	"github.com/cocowh/netproxy/pkg/transport"
)

// Handler implements the VMess protocol handler
type Handler struct {
	server *vmessproto.Server
	auth   auth.Authenticator
}

// Config holds VMess handler configuration
type Config struct {
	// Users is a list of allowed users (UUID -> AlterID)
	Users map[string]uint16
}

// NewHandler creates a new VMess protocol handler
func NewHandler(config *Config, authenticator auth.Authenticator) protocol.Handler {
	server := vmessproto.NewServer()

	// Add users from config
	if config != nil {
		for uuidStr, alterID := range config.Users {
			uuid, err := vmessproto.ParseUUID(uuidStr)
			if err != nil {
				continue
			}
			server.AddUser(uuid, alterID)
		}
	}

	return &Handler{
		server: server,
		auth:   authenticator,
	}
}

// Handle processes a VMess connection
func (h *Handler) Handle(ctx context.Context, conn net.Conn) error {
	// Parse VMess request
	req, vmessConn, err := h.server.HandleConnection(conn)
	if err != nil {
		return fmt.Errorf("vmess handshake failed: %w", err)
	}

	// Build target address
	targetAddr := fmt.Sprintf("%s:%d", req.Address, req.Port)

	// Dial target
	var targetConn net.Conn
	if dialer, ok := ctx.Value(nctx.CtxKeyDialer).(transport.ProxyDialer); ok {
		network := "tcp"
		if req.Command == vmessproto.CommandUDP {
			network = "udp"
		}
		targetConn, err = dialer.Dial(ctx, network, targetAddr)
	} else {
		targetConn, err = net.Dial("tcp", targetAddr)
	}

	if err != nil {
		return fmt.Errorf("dial target %s failed: %w", targetAddr, err)
	}
	defer targetConn.Close()

	// Relay data
	return relay(vmessConn, targetConn)
}

// AddUser adds a user to the handler
func (h *Handler) AddUser(uuid [16]byte, alterID uint16) {
	h.server.AddUser(uuid, alterID)
}

// RemoveUser removes a user from the handler
func (h *Handler) RemoveUser(uuid [16]byte) {
	h.server.RemoveUser(uuid)
}

// relay copies data between two connections
func relay(c1, c2 net.Conn) error {
	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(c1, c2)
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(c2, c1)
		errCh <- err
	}()

	// Wait for either direction to complete
	return <-errCh
}

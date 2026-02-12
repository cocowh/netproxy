// Package vless provides the VLESS protocol handler for the proxy service.
package vless

import (
	"context"
	"fmt"
	"io"
	"net"

	nctx "github.com/cocowh/netproxy/internal/core/context"
	"github.com/cocowh/netproxy/internal/feature/auth"
	"github.com/cocowh/netproxy/pkg/protocol"
	vlessproto "github.com/cocowh/netproxy/pkg/protocol/vless"
	"github.com/cocowh/netproxy/pkg/transport"
)

// Handler implements the VLESS protocol handler
type Handler struct {
	server *vlessproto.Server
	auth   auth.Authenticator
}

// Config holds VLESS handler configuration
type Config struct {
	// Users is a list of allowed users (UUID -> email)
	Users map[string]string
}

// NewHandler creates a new VLESS protocol handler
func NewHandler(config *Config, authenticator auth.Authenticator) protocol.Handler {
	server := vlessproto.NewServer()

	// Add users from config
	if config != nil {
		for uuidStr, email := range config.Users {
			uuid, err := vlessproto.ParseUUID(uuidStr)
			if err != nil {
				continue
			}
			server.AddUser(uuid, email, 0)
		}
	}

	return &Handler{
		server: server,
		auth:   authenticator,
	}
}

// Handle processes a VLESS connection
func (h *Handler) Handle(ctx context.Context, conn net.Conn) error {
	// Parse VLESS request
	req, user, vlessConn, err := h.server.HandleConnection(conn)
	if err != nil {
		return fmt.Errorf("vless handshake failed: %w", err)
	}

	_ = user // Can be used for logging or stats

	// Build target address
	targetAddr := fmt.Sprintf("%s:%d", req.Address, req.Port)

	// Dial target
	var targetConn net.Conn
	if dialer, ok := ctx.Value(nctx.CtxKeyDialer).(transport.ProxyDialer); ok {
		network := "tcp"
		if req.Command == vlessproto.CommandUDP {
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
	return relay(vlessConn, targetConn)
}

// AddUser adds a user to the handler
func (h *Handler) AddUser(uuid [16]byte, email string, level int) {
	h.server.AddUser(uuid, email, level)
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

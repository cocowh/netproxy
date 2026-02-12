// Package trojan provides the Trojan protocol handler for the proxy service.
package trojan

import (
	"context"
	"fmt"
	"io"
	"net"

	nctx "github.com/cocowh/netproxy/internal/core/context"
	"github.com/cocowh/netproxy/internal/feature/auth"
	"github.com/cocowh/netproxy/pkg/protocol"
	trojanproto "github.com/cocowh/netproxy/pkg/protocol/trojan"
	"github.com/cocowh/netproxy/pkg/transport"
)

// Handler implements the Trojan protocol handler
type Handler struct {
	server   *trojanproto.Server
	auth     auth.Authenticator
	fallback string // Fallback address for non-Trojan traffic
}

// Config holds Trojan handler configuration
type Config struct {
	// Users is a list of allowed users (password -> email)
	Users map[string]string
	// Fallback is the address to forward non-Trojan traffic
	Fallback string
}

// NewHandler creates a new Trojan protocol handler
func NewHandler(config *Config, authenticator auth.Authenticator) protocol.Handler {
	fallback := ""
	if config != nil {
		fallback = config.Fallback
	}

	server := trojanproto.NewServer(fallback)

	// Add users from config
	if config != nil {
		for password, email := range config.Users {
			server.AddUser(password, email, 0)
		}
	}

	return &Handler{
		server:   server,
		auth:     authenticator,
		fallback: fallback,
	}
}

// Handle processes a Trojan connection
func (h *Handler) Handle(ctx context.Context, conn net.Conn) error {
	// Parse Trojan request
	req, user, trojanConn, bufferedData, err := h.server.HandleConnection(conn)
	if err != nil {
		// If authentication failed and we have fallback, forward to fallback
		if h.fallback != "" && bufferedData != nil {
			return h.handleFallback(ctx, conn, bufferedData)
		}
		return fmt.Errorf("trojan handshake failed: %w", err)
	}

	_ = user // Can be used for logging or stats

	// Build target address
	targetAddr := fmt.Sprintf("%s:%d", req.Address, req.Port)

	// Dial target
	var targetConn net.Conn
	if dialer, ok := ctx.Value(nctx.CtxKeyDialer).(transport.ProxyDialer); ok {
		network := "tcp"
		if req.Command == trojanproto.CommandUDP {
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
	return relay(trojanConn, targetConn)
}

// handleFallback forwards traffic to the fallback server
func (h *Handler) handleFallback(ctx context.Context, conn net.Conn, bufferedData []byte) error {
	// Dial fallback
	var fallbackConn net.Conn
	var err error

	if dialer, ok := ctx.Value(nctx.CtxKeyDialer).(transport.ProxyDialer); ok {
		fallbackConn, err = dialer.Dial(ctx, "tcp", h.fallback)
	} else {
		fallbackConn, err = net.Dial("tcp", h.fallback)
	}

	if err != nil {
		return fmt.Errorf("dial fallback %s failed: %w", h.fallback, err)
	}
	defer fallbackConn.Close()

	// Write buffered data first
	if len(bufferedData) > 0 {
		if _, err := fallbackConn.Write(bufferedData); err != nil {
			return fmt.Errorf("write buffered data to fallback failed: %w", err)
		}
	}

	// Relay remaining data
	return relay(conn, fallbackConn)
}

// AddUser adds a user to the handler
func (h *Handler) AddUser(password, email string, level int) {
	h.server.AddUser(password, email, level)
}

// RemoveUser removes a user from the handler
func (h *Handler) RemoveUser(password string) {
	h.server.RemoveUser(password)
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

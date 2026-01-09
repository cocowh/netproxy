package instance

import (
	"context"
	"fmt"
	"net"
	"strings"

	nctx "github.com/cocowh/netproxy/internal/core/context"
	"github.com/cocowh/netproxy/internal/core/logger"
	"github.com/cocowh/netproxy/internal/feature/router"
	"github.com/cocowh/netproxy/pkg/transport"
)

// Helper function to build the dialer chain based on router result
func buildChainDialer(nextHops []string) (transport.ProxyDialer, error) {
	var dialer transport.ProxyDialer = &transport.DirectDialer{}
	var err error

	// Iterate in reverse order to build the chain (Target <- ProxyN <- ... <- Proxy1 <- Client)
	// But NextHops is usually ordered Client -> Proxy1 -> Proxy2 -> Target
	// So we need to wrap them:
	// Base: DirectDialer
	// Layer 1: Connect to Proxy1 (using DirectDialer)
	// Layer 2: Connect to Proxy2 (using Proxy1Dialer)

	// Example: NextHops = ["socks5://1.2.3.4:1080", "http://5.6.7.8:8080"]
	// 1. d = DirectDialer
	// 2. d = SOCKS5Dialer(next=d, addr="1.2.3.4:1080")
	// 3. d = HTTPDialer(next=d, addr="5.6.7.8:8080")
	// Result: HTTP(SOCKS5(Direct)) -> Meaning:
	// To dial X:
	//   HTTPDialer.Dial(X):
	//     conn = SOCKS5Dialer.Dial("5.6.7.8:8080"):
	//        conn = DirectDialer.Dial("1.2.3.4:1080") -> TCP to 1.2.3.4
	//        SOCKS5 Handshake to 1.2.3.4
	//        Ask SOCKS5 to connect to 5.6.7.8:8080
	//     HTTP CONNECT to X on the stream

	for _, hop := range nextHops {
		dialer, err = wrapDialer(dialer, hop)
		if err != nil {
			return nil, err
		}
	}
	return dialer, nil
}

func wrapDialer(next transport.ProxyDialer, hop string) (transport.ProxyDialer, error) {
	// Parse hop string: protocol://user:pass@host:port
	// Simple parsing for now
	// Expected format: scheme://[user:pass@]host:port

	parts := strings.Split(hop, "://")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid proxy address format: %s", hop)
	}
	scheme := parts[0]
	remainder := parts[1]

	var user, password, host string
	if idx := strings.LastIndex(remainder, "@"); idx != -1 {
		auth := remainder[:idx]
		host = remainder[idx+1:]
		if authParts := strings.SplitN(auth, ":", 2); len(authParts) == 2 {
			user = authParts[0]
			password = authParts[1]
		} else {
			user = auth
		}
	} else {
		host = remainder
	}

	switch scheme {
	case "socks5":
		return transport.NewSOCKS5Dialer(next, host, user, password), nil
	case "http":
		return transport.NewHTTPDialer(next, host, user, password), nil
	case "ss":
		// Format: ss://method:password@host:port
		// user field is used as method here for simplicity or need specific parsing
		return transport.NewSSDialer(next, host, user, password)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", scheme)
	}
}

// Extracted handleLogic to be used in HandleConn
func (s *serviceInstance) handleWithChain(ctx context.Context, conn net.Conn, routeRes router.RouteResult) {
	// 1. Build Chain
	dialer, err := buildChainDialer(routeRes.NextHops)
	if err != nil {
		s.logger.Error("Failed to build proxy chain", logger.Any("error", err))
		return
	}

	// 2. Pass dialer to Protocol Handler?
	// The Protocol Handler (e.g., SOCKS5 or HTTP) usually needs to Dial the final target.
	// Currently `protocol.Handler.Handle` takes `conn`. It doesn't take a Dialer.
	// Most handlers in `internal/protocol` currently just Read/Write or assume direct net.Dial.
	// We need to inject the Dialer into the context or modify the Handler interface/struct.

	// Option A: Context Injection
	ctx = context.WithValue(ctx, nctx.CtxKeyDialer, dialer)

	// Option B: If protocol handler is generic (like TCP forward), we do the dialing here?
	// But `protocol.Handler` encapsulates the protocol logic (e.g. read SOCKS5 request, THEN dial).
	// So the Handler needs to use *our* dialer.

	if err := s.protocolStack.Handle(ctx, conn); err != nil {
		s.logger.Error("Handler error", logger.Any("error", err))
	}
}

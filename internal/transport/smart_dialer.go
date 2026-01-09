package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/cocowh/netproxy/internal/feature/acl"
	"github.com/cocowh/netproxy/internal/feature/router"
	"github.com/cocowh/netproxy/internal/feature/stats"
	pkgtransport "github.com/cocowh/netproxy/pkg/transport"
)

// SmartDialer implements ProxyDialer and performs routing decision at Dial time
type SmartDialer struct {
	router         router.Router
	clientIP       net.IP
	statsCollector stats.StatsCollector
}

// NewSmartDialer creates a new SmartDialer
func NewSmartDialer(r router.Router, clientIP net.IP, stats stats.StatsCollector) pkgtransport.ProxyDialer {
	return &SmartDialer{
		router:         r,
		clientIP:       clientIP,
		statsCollector: stats,
	}
}

// Dial performs routing and then dials the target
func (d *SmartDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %s: %w", addr, err)
	}

	// 1. Prepare Metadata for Routing
	meta := acl.Metadata{
		ClientIP:   d.clientIP,
		TargetHost: host,
		TargetPort: port,
		Network:    network,
	}

	// 2. Ask Router
	routeRes, err := d.router.Route(ctx, meta)
	if err != nil {
		return nil, fmt.Errorf("routing failed: %w", err)
	}
	// 3. Act on Decision
	switch routeRes.Action {
	case acl.Block:
		return nil, fmt.Errorf("connection blocked by rule")
	case acl.Direct:
		// For UDP, we shouldn't be here in Dial?
		// Dial implies TCP/stream.
		// If network is "udp", we can't easily return net.Conn unless we DialUDP.
		conn, err := (&pkgtransport.DirectDialer{}).Dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return d.wrapWithStats(conn), nil
	case acl.Proxy:
		// Build proxy chain
		dialer, err := d.buildChainDialer(routeRes.NextHops)
		if err != nil {
			return nil, fmt.Errorf("failed to build proxy chain: %w", err)
		}
		conn, err := dialer.Dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return d.wrapWithStats(conn), nil
	default:
		return nil, fmt.Errorf("unknown routing action: %v", routeRes.Action)
	}
}

func (d *SmartDialer) wrapWithStats(conn net.Conn) net.Conn {
	if d.statsCollector != nil {
		return stats.NewStatsConn(conn, d.statsCollector)
	}
	return conn
}

// Helper function to build the dialer chain based on router result
// Duplicated from chain.go but modified to avoid import cycles if chain.go is moved
// or just kept here for SmartDialer's private use.
func (d *SmartDialer) buildChainDialer(nextHops []string) (pkgtransport.ProxyDialer, error) {
	var dialer pkgtransport.ProxyDialer = &pkgtransport.DirectDialer{}
	var err error

	for _, hop := range nextHops {
		dialer, err = d.wrapDialer(dialer, hop)
		if err != nil {
			return nil, err
		}
	}
	return dialer, nil
}

func (d *SmartDialer) wrapDialer(next pkgtransport.ProxyDialer, hop string) (pkgtransport.ProxyDialer, error) {
	parts := strings.Split(hop, "://")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid proxy address format: %s", hop)
	}
	scheme := parts[0]
	remainder := parts[1]

	var user, pass, host string
	if idx := strings.LastIndex(remainder, "@"); idx != -1 {
		auth := remainder[:idx]
		host = remainder[idx+1:]
		if authParts := strings.SplitN(auth, ":", 2); len(authParts) == 2 {
			user = authParts[0]
			pass = authParts[1]
		} else {
			user = auth
		}
	} else {
		host = remainder
	}

	// Parse query parameters for transport options
	// Format: scheme://user:pass@host:port?transport=ws&path=/ws&tls=true
	var transportType string
	var wsPath string
	var useTLS bool

	if strings.Contains(host, "?") {
		parts := strings.SplitN(host, "?", 2)
		host = parts[0]
		query := parts[1]

		// Simple query parser
		params := strings.Split(query, "&")
		for _, param := range params {
			kv := strings.SplitN(param, "=", 2)
			if len(kv) == 2 {
				switch kv[0] {
				case "transport":
					transportType = kv[1]
				case "path":
					wsPath = kv[1]
				case "tls":
					useTLS = kv[1] == "true"
				}
			}
		}
	}

	// Apply Transport Wrappers (Bottom-Up)

	// 1. TLS
	if useTLS || scheme == "wss" || scheme == "https" {
		next = pkgtransport.NewTLSDialer(next, &tls.Config{InsecureSkipVerify: true}) // Allow insecure for now or parse from query
	}

	// 2. WebSocket
	if transportType == "ws" || scheme == "ws" || scheme == "wss" {
		if wsPath == "" {
			wsPath = "/"
		}
		next = pkgtransport.NewWSDialer(next, wsPath, host)
	}

	switch scheme {
	case "socks5":
		return pkgtransport.NewSOCKS5Dialer(next, host, user, pass), nil
	case "http", "https":
		return pkgtransport.NewHTTPDialer(next, host, user, pass), nil
	case "ss":
		return pkgtransport.NewSSDialer(next, host, user, pass)
	case "ws", "wss":
		// Use the transport dialer directly
		return next, nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", scheme)
	}
}

// DialPacket performs routing and then dials the target (UDP)
func (d *SmartDialer) DialPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	// For UDP routing, we use the same Router.
	// But `router.Route` takes `Metadata`.
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// If addr is just IP or port?
		// SOCKS5 UDP relay might pass just IP?
		// For simplicity, assume host:port
		return nil, fmt.Errorf("invalid address %s: %w", addr, err)
	}

	meta := acl.Metadata{
		ClientIP:   d.clientIP,
		TargetHost: host,
		TargetPort: port,
		Network:    network,
	}

	routeRes, err := d.router.Route(ctx, meta)
	if err != nil {
		return nil, fmt.Errorf("routing failed: %w", err)
	}

	switch routeRes.Action {
	case acl.Block:
		return nil, fmt.Errorf("connection blocked by rule")
	case acl.Direct:
		// Direct UDP
		return (&pkgtransport.DirectDialer{}).DialPacket(ctx, network, addr)
	case acl.Proxy:
		// Proxy UDP
		// We need to build a ProxyDialer that supports DialPacket.
		// SOCKS5 Dialer should support it?
		// Currently SOCKS5Dialer (internal/transport/socks5_dialer.go) wraps `net.Conn`.
		// It doesn't implement `DialPacket`.
		// We need to update SOCKS5Dialer to support DialPacket (UDP Associate via proxy).
		// For this step, if SOCKS5Dialer doesn't support it, we fallback to Direct or Error?
		// Ideally we implement it.
		// For now, let's fallback to Direct if Proxy doesn't support Packet.
		// OR, since Step 9 requires full support, we should assume we will implement it.
		// But I haven't updated SOCKS5Dialer yet.
		// Let's check SOCKS5Dialer.

		dialer, err := d.buildChainDialer(routeRes.NextHops)
		if err != nil {
			return nil, err
		}

		return dialer.DialPacket(ctx, network, addr)

	default:
		return nil, fmt.Errorf("unknown routing action: %v", routeRes.Action)
	}
}

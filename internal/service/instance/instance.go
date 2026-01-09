package instance

import (
	"context"
	"net"

	nctx "github.com/cocowh/netproxy/internal/core/context"
	"github.com/cocowh/netproxy/internal/core/logger"
	"github.com/cocowh/netproxy/internal/feature/auth"
	"github.com/cocowh/netproxy/internal/feature/ratelimit"
	"github.com/cocowh/netproxy/internal/feature/router"
	"github.com/cocowh/netproxy/internal/feature/stats"
	"github.com/cocowh/netproxy/internal/transport"
	"github.com/cocowh/netproxy/pkg/protocol"
)

// Instance represents a service instance
type Instance interface {
	HandleConn(ctx context.Context, conn net.Conn)
	HandlePacket(ctx context.Context, conn net.PacketConn)
	SetRouter(r router.Router)
}

// Config defines configuration for a service instance
type Config struct {
	Protocol    string
	TargetAddr  string
	AuthEnabled bool
}

type serviceInstance struct {
	config        Config
	logger        logger.Logger
	auth          auth.Authenticator
	limiter       ratelimit.Limiter
	stats         stats.StatsCollector
	router        router.Router // Use full Router interface
	protocolStack protocol.Handler
}

// NewServiceInstance creates a new service instance
func NewServiceInstance(cfg Config, l logger.Logger, p protocol.Handler, s stats.StatsCollector, limiter ratelimit.Limiter) Instance {
	if s == nil {
		s = stats.NewSimpleCollector()
	}
	return &serviceInstance{
		config:        cfg,
		logger:        l,
		protocolStack: p,
		stats:         s,
		limiter:       limiter,
	}
}

func (s *serviceInstance) SetRouter(r router.Router) {
	s.router = r
}

func (s *serviceInstance) HandleConn(ctx context.Context, conn net.Conn) {
	// Wrap with stats
	conn = stats.NewStatsConn(conn, s.stats)
	defer conn.Close()

	// Rate Limit
	if s.limiter != nil {
		if !s.limiter.Allow() {
			s.logger.Warn("Connection rejected by rate limiter", logger.Any("remote_addr", conn.RemoteAddr()))
			return
		}
	}

	// Inject SmartDialer into Context
	// This allows protocol handlers (SOCKS5/HTTP/etc) to perform delayed routing decisions
	// when they attempt to Dial the target.
	if s.router != nil {
		// Extract ClientIP for GeoIP matching (still useful for pre-handshake checks if we wanted,
		// but primarily for the SmartDialer to have context)
		clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

		// Create SmartDialer
		smartDialer := transport.NewSmartDialer(s.router, net.ParseIP(clientIP), s.stats)

		// Inject into Context
		ctx = context.WithValue(ctx, nctx.CtxKeyDialer, smartDialer)
	}

	// Protocol Handshake & Handling
	if err := s.protocolStack.Handle(ctx, conn); err != nil {
		s.logger.Error("Handler error", logger.Any("error", err))
	}
}

func (s *serviceInstance) HandlePacket(ctx context.Context, conn net.PacketConn) {
	// Rate Limit
	if s.limiter != nil {
		if !s.limiter.Allow() {
			s.logger.Warn("Packet connection rejected by rate limiter", logger.Any("local_addr", conn.LocalAddr()))
			conn.Close()
			return
		}
	}

	// Inject SmartDialer into Context
	// Note: For PacketConn, we don't know RemoteAddr until ReadFrom.
	// But ListenerManager passes a PacketConn bound to a port (ListenPacket).
	// This connection is SHARED for all clients if it's UDP.
	// OR, it's a unique PacketConn if using some other mechanism.
	//
	// If it is a shared UDP socket (net.PacketConn), then `protocolStack.HandlePacket`
	// needs to handle the reading loop and per-packet logic.
	//
	// We CANNOT determine client IP here easily for SmartDialer context,
	// because we haven't read a packet yet.
	//
	// So we inject SmartDialer with nil ClientIP, and let the handler (SOCKS5)
	// potentially create a new context or use the dialer as is (less GeoIP accuracy for initial dial).
	//
	// Actually, SOCKS5 UDP handler does `ReadFrom`, gets `clientAddr`, then calls `DialPacket`.
	// Ideally, it should update the SmartDialer or create a new one with correct ClientIP.
	// But `transport.NewSmartDialer` is cheap. The handler can do it?
	// No, Handler receives `ctx`.
	//
	// Let's inject a "Generic" SmartDialer here.

	if s.router != nil {
		// Create SmartDialer with nil IP
		smartDialer := transport.NewSmartDialer(s.router, nil, s.stats)
		ctx = context.WithValue(ctx, nctx.CtxKeyDialer, smartDialer)
	}

	// Check if protocol stack supports PacketHandler
	if ph, ok := s.protocolStack.(protocol.PacketHandler); ok {
		if err := ph.HandlePacket(ctx, conn); err != nil {
			s.logger.Error("Packet Handler error", logger.Any("error", err))
		}
	} else {
		s.logger.Error("Protocol stack does not support PacketHandler")
		conn.Close()
	}
}

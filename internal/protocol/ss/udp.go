package ss

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cocowh/netproxy/internal/core/logger"
	"github.com/cocowh/netproxy/pkg/protocol"
	"github.com/shadowsocks/go-shadowsocks2/core"
)

// UDPHandler handles Shadowsocks UDP relay
type UDPHandler struct {
	cipher  core.Cipher
	logger  logger.Logger
	timeout time.Duration

	// NAT table for UDP session management
	natTable sync.Map // map[string]*udpSession
}

// udpSession represents a UDP relay session
type udpSession struct {
	clientAddr net.Addr
	targetConn *net.UDPConn
	lastActive time.Time
	mu         sync.Mutex
}

// NewUDPHandler creates a new Shadowsocks UDP handler
func NewUDPHandler(method, password string, log logger.Logger) (*UDPHandler, error) {
	cipher, err := core.PickCipher(method, []byte{}, password)
	if err != nil {
		return nil, fmt.Errorf("failed to pick cipher: %v", err)
	}

	return &UDPHandler{
		cipher:  cipher,
		logger:  log,
		timeout: 5 * time.Minute, // Default UDP session timeout
	}, nil
}

// HandlePacket implements protocol.PacketHandler interface
func (h *UDPHandler) HandlePacket(ctx context.Context, conn net.PacketConn) error {
	// Wrap the packet connection with cipher for encryption/decryption
	packetConn := h.cipher.PacketConn(conn)

	buf := make([]byte, 64*1024) // 64KB buffer for UDP packets

	// Start cleanup goroutine
	go h.cleanupSessions(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Read encrypted packet from client
		n, clientAddr, err := packetConn.ReadFrom(buf)
		if err != nil {
			h.logger.Error("Failed to read UDP packet", logger.Any("error", err))
			continue
		}

		// Process packet in goroutine
		go h.handlePacket(ctx, packetConn, buf[:n], clientAddr)
	}
}

// handlePacket processes a single UDP packet
func (h *UDPHandler) handlePacket(ctx context.Context, packetConn net.PacketConn, data []byte, clientAddr net.Addr) {
	// Parse target address from decrypted data
	// SS UDP packet format: [target address][payload]
	targetAddr, payload, err := h.parseUDPPacket(data)
	if err != nil {
		h.logger.Error("Failed to parse UDP packet", logger.Any("error", err))
		return
	}

	h.logger.Debug("UDP relay", logger.Any("client", clientAddr), logger.Any("target", targetAddr))

	// Get or create session
	sessionKey := clientAddr.String()
	session := h.getOrCreateSession(sessionKey, clientAddr, targetAddr)
	if session == nil {
		return
	}

	// Update last active time
	session.mu.Lock()
	session.lastActive = time.Now()
	session.mu.Unlock()

	// Send payload to target
	_, err = session.targetConn.Write(payload)
	if err != nil {
		h.logger.Error("Failed to send UDP to target", logger.Any("error", err))
		return
	}

	// Start response relay if not already running
	go h.relayResponse(ctx, packetConn, session, targetAddr)
}

// parseUDPPacket parses the SS UDP packet and extracts target address and payload
// SS UDP packet format: [1-byte type][variable address][2-byte port][payload]
func (h *UDPHandler) parseUDPPacket(data []byte) (net.Addr, []byte, error) {
	if len(data) < 4 {
		return nil, nil, fmt.Errorf("packet too short")
	}

	var addrLen int
	switch data[0] {
	case 1: // IPv4
		addrLen = 1 + 4 + 2 // type + IPv4 + port
	case 3: // Domain
		if len(data) < 2 {
			return nil, nil, fmt.Errorf("packet too short for domain")
		}
		addrLen = 1 + 1 + int(data[1]) + 2 // type + len + domain + port
	case 4: // IPv6
		addrLen = 1 + 16 + 2 // type + IPv6 + port
	default:
		return nil, nil, fmt.Errorf("unknown address type: %d", data[0])
	}

	if len(data) < addrLen {
		return nil, nil, fmt.Errorf("packet too short for address")
	}

	// Parse address
	var addr net.Addr
	switch data[0] {
	case 1: // IPv4
		ip := net.IP(data[1:5])
		port := int(data[5])<<8 | int(data[6])
		addr = &net.UDPAddr{IP: ip, Port: port}
	case 3: // Domain
		domainLen := int(data[1])
		host := string(data[2 : 2+domainLen])
		port := int(data[2+domainLen])<<8 | int(data[2+domainLen+1])
		addr = &udpAddr{host: host, port: port}
	case 4: // IPv6
		ip := net.IP(data[1:17])
		port := int(data[17])<<8 | int(data[18])
		addr = &net.UDPAddr{IP: ip, Port: port}
	}

	payload := data[addrLen:]
	return addr, payload, nil
}

// buildUDPPacket builds an SS UDP response packet
func (h *UDPHandler) buildUDPPacket(addr net.Addr, payload []byte) []byte {
	var addrBytes []byte

	switch a := addr.(type) {
	case *net.UDPAddr:
		if ip4 := a.IP.To4(); ip4 != nil {
			// IPv4
			addrBytes = make([]byte, 1+4+2)
			addrBytes[0] = 1
			copy(addrBytes[1:5], ip4)
			addrBytes[5] = byte(a.Port >> 8)
			addrBytes[6] = byte(a.Port)
		} else {
			// IPv6
			addrBytes = make([]byte, 1+16+2)
			addrBytes[0] = 4
			copy(addrBytes[1:17], a.IP.To16())
			addrBytes[17] = byte(a.Port >> 8)
			addrBytes[18] = byte(a.Port)
		}
	case *udpAddr:
		// Domain
		addrBytes = make([]byte, 1+1+len(a.host)+2)
		addrBytes[0] = 3
		addrBytes[1] = byte(len(a.host))
		copy(addrBytes[2:], a.host)
		addrBytes[2+len(a.host)] = byte(a.port >> 8)
		addrBytes[2+len(a.host)+1] = byte(a.port)
	}

	result := make([]byte, len(addrBytes)+len(payload))
	copy(result, addrBytes)
	copy(result[len(addrBytes):], payload)
	return result
}

// getOrCreateSession gets an existing session or creates a new one
func (h *UDPHandler) getOrCreateSession(key string, clientAddr net.Addr, targetAddr net.Addr) *udpSession {
	if val, ok := h.natTable.Load(key); ok {
		return val.(*udpSession)
	}

	// Resolve target address
	var targetUDPAddr *net.UDPAddr
	switch a := targetAddr.(type) {
	case *net.UDPAddr:
		targetUDPAddr = a
	case *udpAddr:
		// Resolve domain
		resolved, err := net.ResolveUDPAddr("udp", a.String())
		if err != nil {
			h.logger.Error("Failed to resolve target address", logger.Any("addr", a), logger.Any("error", err))
			return nil
		}
		targetUDPAddr = resolved
	}

	// Create new UDP connection to target
	targetConn, err := net.DialUDP("udp", nil, targetUDPAddr)
	if err != nil {
		h.logger.Error("Failed to dial target UDP", logger.Any("target", targetAddr), logger.Any("error", err))
		return nil
	}

	session := &udpSession{
		clientAddr: clientAddr,
		targetConn: targetConn,
		lastActive: time.Now(),
	}

	// Store session (handle race condition)
	actual, loaded := h.natTable.LoadOrStore(key, session)
	if loaded {
		// Another goroutine created the session first, close our connection
		targetConn.Close()
		return actual.(*udpSession)
	}

	h.logger.Debug("Created new UDP session", logger.Any("client", clientAddr), logger.Any("target", targetAddr))
	return session
}

// relayResponse relays responses from target back to client
func (h *UDPHandler) relayResponse(ctx context.Context, packetConn net.PacketConn, session *udpSession, targetAddr net.Addr) {
	buf := make([]byte, 64*1024)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Set read deadline
		session.targetConn.SetReadDeadline(time.Now().Add(h.timeout))

		n, _, err := session.targetConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout, check if session is still active
				session.mu.Lock()
				if time.Since(session.lastActive) > h.timeout {
					session.mu.Unlock()
					return
				}
				session.mu.Unlock()
				continue
			}
			h.logger.Debug("UDP relay response error", logger.Any("error", err))
			return
		}

		// Build response packet with target address header
		responsePacket := h.buildUDPPacket(targetAddr, buf[:n])

		// Send response back to client
		_, err = packetConn.WriteTo(responsePacket, session.clientAddr)
		if err != nil {
			h.logger.Error("Failed to send UDP response to client", logger.Any("error", err))
			return
		}

		// Update last active time
		session.mu.Lock()
		session.lastActive = time.Now()
		session.mu.Unlock()
	}
}

// cleanupSessions periodically cleans up expired sessions
func (h *UDPHandler) cleanupSessions(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.natTable.Range(func(key, value interface{}) bool {
				session := value.(*udpSession)
				session.mu.Lock()
				if time.Since(session.lastActive) > h.timeout {
					session.mu.Unlock()
					session.targetConn.Close()
					h.natTable.Delete(key)
					h.logger.Debug("Cleaned up expired UDP session", logger.Any("key", key))
				} else {
					session.mu.Unlock()
				}
				return true
			})
		}
	}
}

// udpAddr represents a UDP address with domain name
type udpAddr struct {
	host string
	port int
}

func (a *udpAddr) Network() string { return "udp" }
func (a *udpAddr) String() string  { return fmt.Sprintf("%s:%d", a.host, a.port) }

// Ensure UDPHandler implements PacketHandler
var _ protocol.PacketHandler = (*UDPHandler)(nil)

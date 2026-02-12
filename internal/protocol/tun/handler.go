// Package tun provides TUN device protocol handler for NetProxy.
package tun

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	pkgtun "github.com/cocowh/netproxy/pkg/tun"
)

// Config holds TUN handler configuration
type Config struct {
	// Enabled indicates whether TUN is enabled
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Name is the TUN device name
	Name string `yaml:"name" json:"name"`

	// MTU is the Maximum Transmission Unit
	MTU int `yaml:"mtu" json:"mtu"`

	// Address is the IP address for the TUN device (CIDR format)
	Address string `yaml:"address" json:"address"`

	// Gateway is the gateway address
	Gateway string `yaml:"gateway" json:"gateway"`

	// Routes are additional routes to add
	Routes []string `yaml:"routes" json:"routes"`

	// DNSServers are DNS servers to use
	DNSServers []string `yaml:"dns_servers" json:"dns_servers"`
}

// DefaultConfig returns default TUN configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled: false,
		Name:    "utun8",
		MTU:     1400,
		Address: "10.10.10.1/24",
		Gateway: "10.10.10.1",
	}
}

// Handler handles TUN device traffic
type Handler struct {
	config   *Config
	device   pkgtun.Device
	dialer   Dialer
	sessions sync.Map // map[string]*Session
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	mu       sync.RWMutex
	running  bool
}

// Dialer is the interface for dialing connections
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Session represents a TUN session
type Session struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Protocol int
	Conn     net.Conn
	Created  time.Time
}

// NewHandler creates a new TUN handler
func NewHandler(config *Config, dialer Dialer) *Handler {
	if config == nil {
		config = DefaultConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Handler{
		config: config,
		dialer: dialer,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start starts the TUN handler
func (h *Handler) Start() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return fmt.Errorf("TUN handler already running")
	}

	if !h.config.Enabled {
		log.Println("[TUN] handler disabled")
		return nil
	}

	// Create TUN device
	tunConfig := &pkgtun.Config{
		Name:    h.config.Name,
		MTU:     h.config.MTU,
		Address: h.config.Address,
		Gateway: h.config.Gateway,
		Routes:  h.config.Routes,
	}

	device, err := pkgtun.New(tunConfig)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %w", err)
	}

	h.device = device
	h.running = true

	// Start packet processing
	h.wg.Add(1)
	go h.processPackets()

	log.Printf("[TUN] handler started device=%s mtu=%d address=%s",
		device.Name(), device.MTU(), h.config.Address)

	return nil
}

// Stop stops the TUN handler
func (h *Handler) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return nil
	}

	h.cancel()
	h.running = false

	// Close all sessions
	h.sessions.Range(func(key, value interface{}) bool {
		if session, ok := value.(*Session); ok {
			if session.Conn != nil {
				session.Conn.Close()
			}
		}
		h.sessions.Delete(key)
		return true
	})

	// Close device
	if h.device != nil {
		if err := h.device.Close(); err != nil {
			log.Printf("[TUN] failed to close device: %v", err)
		}
	}

	h.wg.Wait()

	log.Println("[TUN] handler stopped")
	return nil
}

// processPackets reads and processes packets from the TUN device
func (h *Handler) processPackets() {
	defer h.wg.Done()

	buf := make([]byte, h.config.MTU+100)

	for {
		select {
		case <-h.ctx.Done():
			return
		default:
		}

		n, err := h.device.Read(buf)
		if err != nil {
			if err == io.EOF || h.ctx.Err() != nil {
				return
			}
			log.Printf("[TUN] failed to read: %v", err)
			continue
		}

		if n == 0 {
			continue
		}

		// Parse the IP packet
		pkt, err := pkgtun.ParseIPPacket(buf[:n])
		if err != nil {
			// Silently ignore parse errors for non-IP packets
			continue
		}

		// Handle the packet
		go h.handlePacket(pkt)
	}
}

// handlePacket handles a single IP packet
func (h *Handler) handlePacket(pkt *pkgtun.IPPacket) {
	if pkt.IsTCP() {
		h.handleTCP(pkt)
	} else if pkt.IsUDP() {
		h.handleUDP(pkt)
	} else if pkt.IsICMP() {
		h.handleICMP(pkt)
	}
}

// handleTCP handles TCP packets
func (h *Handler) handleTCP(pkt *pkgtun.IPPacket) {
	key := fmt.Sprintf("tcp:%s:%d->%s:%d", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort)

	// Check for existing session
	if _, ok := h.sessions.Load(key); ok {
		// Session exists, packet will be handled by the existing connection
		return
	}

	// Create new session
	addr := fmt.Sprintf("%s:%d", pkt.DstIP, pkt.DstPort)

	conn, err := h.dialer.DialContext(h.ctx, "tcp", addr)
	if err != nil {
		// Connection failed, silently ignore
		return
	}

	session := &Session{
		SrcIP:    pkt.SrcIP,
		DstIP:    pkt.DstIP,
		SrcPort:  pkt.SrcPort,
		DstPort:  pkt.DstPort,
		Protocol: 6,
		Conn:     conn,
		Created:  time.Now(),
	}

	h.sessions.Store(key, session)

	// Handle the connection in a goroutine
	go func() {
		defer func() {
			conn.Close()
			h.sessions.Delete(key)
		}()

		// For a real implementation, we would need to:
		// 1. Reconstruct TCP state machine
		// 2. Handle TCP handshake
		// 3. Forward data bidirectionally
		// This is a simplified version

		// Set timeout
		conn.SetDeadline(time.Now().Add(30 * time.Minute))

		// Read response and write back to TUN
		buf := make([]byte, 65535)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}

			// In a real implementation, we would construct proper IP/TCP packets
			// and write them back to the TUN device
			_ = n
		}
	}()
}

// handleUDP handles UDP packets
func (h *Handler) handleUDP(pkt *pkgtun.IPPacket) {
	key := fmt.Sprintf("udp:%s:%d->%s:%d", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort)

	addr := fmt.Sprintf("%s:%d", pkt.DstIP, pkt.DstPort)

	conn, err := h.dialer.DialContext(h.ctx, "udp", addr)
	if err != nil {
		return
	}

	session := &Session{
		SrcIP:    pkt.SrcIP,
		DstIP:    pkt.DstIP,
		SrcPort:  pkt.SrcPort,
		DstPort:  pkt.DstPort,
		Protocol: 17,
		Conn:     conn,
		Created:  time.Now(),
	}

	h.sessions.Store(key, session)

	// Handle UDP - simplified version
	go func() {
		defer func() {
			conn.Close()
			h.sessions.Delete(key)
		}()

		conn.SetDeadline(time.Now().Add(5 * time.Minute))

		buf := make([]byte, 65535)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			_ = n
		}
	}()
}

// handleICMP handles ICMP packets
func (h *Handler) handleICMP(pkt *pkgtun.IPPacket) {
	// ICMP handling is typically done at the kernel level
	// For now, we just ignore it
}

// Stats returns TUN handler statistics
func (h *Handler) Stats() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	stats := map[string]interface{}{
		"enabled": h.config.Enabled,
		"running": h.running,
	}

	if h.device != nil {
		stats["device"] = h.device.Name()
		stats["mtu"] = h.device.MTU()
	}

	// Count sessions
	var tcpSessions, udpSessions int
	h.sessions.Range(func(key, value interface{}) bool {
		if session, ok := value.(*Session); ok {
			if session.Protocol == 6 {
				tcpSessions++
			} else if session.Protocol == 17 {
				udpSessions++
			}
		}
		return true
	})

	stats["tcp_sessions"] = tcpSessions
	stats["udp_sessions"] = udpSessions

	return stats
}

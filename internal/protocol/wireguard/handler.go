// Package wireguard provides WireGuard protocol handler for netproxy.
package wireguard

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cocowh/netproxy/internal/core/logger"
	"github.com/cocowh/netproxy/pkg/protocol/wireguard"
)

// Config represents WireGuard handler configuration.
type Config struct {
	// PrivateKey is the server's private key (base64 encoded)
	PrivateKey string `json:"private_key" yaml:"private_key"`

	// ListenPort is the UDP port to listen on
	ListenPort int `json:"listen_port" yaml:"listen_port"`

	// Peers is the list of allowed peers
	Peers []PeerConfig `json:"peers" yaml:"peers"`

	// MTU is the maximum transmission unit
	MTU int `json:"mtu" yaml:"mtu"`

	// KeepaliveInterval is the interval for keepalive packets
	KeepaliveInterval time.Duration `json:"keepalive_interval" yaml:"keepalive_interval"`
}

// PeerConfig represents a WireGuard peer configuration.
type PeerConfig struct {
	// PublicKey is the peer's public key (base64 encoded)
	PublicKey string `json:"public_key" yaml:"public_key"`

	// PresharedKey is the optional preshared key (base64 encoded)
	PresharedKey string `json:"preshared_key" yaml:"preshared_key"`

	// AllowedIPs is the list of allowed IP ranges for this peer
	AllowedIPs []string `json:"allowed_ips" yaml:"allowed_ips"`

	// Endpoint is the peer's endpoint (optional, for client mode)
	Endpoint string `json:"endpoint" yaml:"endpoint"`

	// PersistentKeepalive is the keepalive interval for this peer
	PersistentKeepalive time.Duration `json:"persistent_keepalive" yaml:"persistent_keepalive"`
}

// Peer represents an active WireGuard peer.
type Peer struct {
	config     PeerConfig
	publicKey  [wireguard.KeySize]byte
	psk        [wireguard.KeySize]byte
	allowedIPs []*net.IPNet
	endpoint   *net.UDPAddr
	handshake  *wireguard.NoiseHandshake
	cipher     *wireguard.TransportCipher
	lastSeen   time.Time
	mu         sync.RWMutex
}

// Handler implements the WireGuard protocol handler.
type Handler struct {
	config     Config
	privateKey *wireguard.KeyPair
	publicKey  [wireguard.KeySize]byte
	conn       *net.UDPConn
	peers      map[[wireguard.KeySize]byte]*Peer
	peersByIdx map[uint32]*Peer
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	log        logger.Logger
}

// NewHandler creates a new WireGuard handler.
func NewHandler(cfg Config, log logger.Logger) (*Handler, error) {
	// Decode private key
	privKeyBytes, err := base64.StdEncoding.DecodeString(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	if len(privKeyBytes) != wireguard.KeySize {
		return nil, errors.New("private key must be 32 bytes")
	}

	var privKey [wireguard.KeySize]byte
	copy(privKey[:], privKeyBytes)
	keyPair := wireguard.NewKeyPairFromPrivate(privKey)

	h := &Handler{
		config:     cfg,
		privateKey: keyPair,
		publicKey:  keyPair.PublicKey,
		peers:      make(map[[wireguard.KeySize]byte]*Peer),
		peersByIdx: make(map[uint32]*Peer),
		log:        log,
	}

	// Initialize peers
	for _, peerCfg := range cfg.Peers {
		peer, err := h.addPeer(peerCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to add peer: %w", err)
		}
		h.peers[peer.publicKey] = peer
	}

	return h, nil
}

// addPeer adds a peer to the handler.
func (h *Handler) addPeer(cfg PeerConfig) (*Peer, error) {
	// Decode public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(cfg.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	if len(pubKeyBytes) != wireguard.KeySize {
		return nil, errors.New("public key must be 32 bytes")
	}

	var pubKey [wireguard.KeySize]byte
	copy(pubKey[:], pubKeyBytes)

	// Decode preshared key if present
	var psk [wireguard.KeySize]byte
	if cfg.PresharedKey != "" {
		pskBytes, err := base64.StdEncoding.DecodeString(cfg.PresharedKey)
		if err != nil {
			return nil, fmt.Errorf("invalid preshared key: %w", err)
		}
		if len(pskBytes) != wireguard.KeySize {
			return nil, errors.New("preshared key must be 32 bytes")
		}
		copy(psk[:], pskBytes)
	}

	// Parse allowed IPs
	var allowedIPs []*net.IPNet
	for _, cidr := range cfg.AllowedIPs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed IP %s: %w", cidr, err)
		}
		allowedIPs = append(allowedIPs, ipNet)
	}

	// Parse endpoint if present
	var endpoint *net.UDPAddr
	if cfg.Endpoint != "" {
		endpoint, err = net.ResolveUDPAddr("udp", cfg.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid endpoint: %w", err)
		}
	}

	return &Peer{
		config:     cfg,
		publicKey:  pubKey,
		psk:        psk,
		allowedIPs: allowedIPs,
		endpoint:   endpoint,
	}, nil
}

// Start starts the WireGuard handler.
func (h *Handler) Start(ctx context.Context) error {
	h.ctx, h.cancel = context.WithCancel(ctx)

	// Create UDP listener
	addr := &net.UDPAddr{Port: h.config.ListenPort}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP port %d: %w", h.config.ListenPort, err)
	}
	h.conn = conn

	h.log.Info("WireGuard handler started", logger.Any("port", h.config.ListenPort), logger.Any("public_key", base64.StdEncoding.EncodeToString(h.publicKey[:])))

	// Start packet processing
	go h.processPackets()

	// Start keepalive loop
	if h.config.KeepaliveInterval > 0 {
		go h.keepaliveLoop()
	}

	return nil
}

// Stop stops the WireGuard handler.
func (h *Handler) Stop() error {
	if h.cancel != nil {
		h.cancel()
	}
	if h.conn != nil {
		return h.conn.Close()
	}
	return nil
}

// processPackets processes incoming UDP packets.
func (h *Handler) processPackets() {
	buf := make([]byte, 65535)

	for {
		select {
		case <-h.ctx.Done():
			return
		default:
		}

		h.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, remoteAddr, err := h.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			h.log.Error("failed to read UDP packet", logger.Any("error", err))
			continue
		}

		if n < 4 {
			continue
		}

		// Process packet based on type
		msgType := buf[0]
		switch msgType {
		case wireguard.MessageTypeInitiation:
			h.handleInitiation(buf[:n], remoteAddr)
		case wireguard.MessageTypeResponse:
			h.handleResponse(buf[:n], remoteAddr)
		case wireguard.MessageTypeTransport:
			h.handleTransport(buf[:n], remoteAddr)
		case wireguard.MessageTypeCookieReply:
			h.handleCookieReply(buf[:n], remoteAddr)
		default:
			h.log.Debug("unknown message type", logger.Any("type", msgType))
		}
	}
}

// handleInitiation handles a handshake initiation message.
func (h *Handler) handleInitiation(msg []byte, remoteAddr *net.UDPAddr) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Try to find the peer by attempting to decrypt with each peer's key
	for _, peer := range h.peers {
		peer.mu.Lock()

		// Create handshake state
		hs := wireguard.NewNoiseHandshake(h.privateKey, peer.publicKey, peer.psk)

		// Try to consume initiation
		if err := hs.ConsumeInitiation(msg); err != nil {
			peer.mu.Unlock()
			continue
		}

		// Initiation successful, create response
		response, err := hs.CreateResponse()
		if err != nil {
			h.log.Error("failed to create response", logger.Any("error", err))
			peer.mu.Unlock()
			return
		}

		// Send response
		if _, err := h.conn.WriteToUDP(response, remoteAddr); err != nil {
			h.log.Error("failed to send response", logger.Any("error", err))
			peer.mu.Unlock()
			return
		}

		// Derive transport keys
		sendKey, recvKey, err := hs.DeriveKeys()
		if err != nil {
			h.log.Error("failed to derive keys", logger.Any("error", err))
			peer.mu.Unlock()
			return
		}

		// Create transport cipher
		cipher, err := wireguard.NewTransportCipher(sendKey, recvKey)
		if err != nil {
			h.log.Error("failed to create transport cipher", logger.Any("error", err))
			peer.mu.Unlock()
			return
		}

		// Update peer state
		peer.handshake = hs
		peer.cipher = cipher
		peer.endpoint = remoteAddr
		peer.lastSeen = time.Now()

		// Register peer by index
		localIdx, _ := hs.GetIndices()
		h.peersByIdx[localIdx] = peer

		h.log.Info("handshake completed with peer", logger.Any("peer", base64.StdEncoding.EncodeToString(peer.publicKey[:])), logger.Any("endpoint", remoteAddr))

		peer.mu.Unlock()
		return
	}

	h.log.Debug("no matching peer for initiation", logger.Any("remote", remoteAddr))
}

// handleResponse handles a handshake response message.
func (h *Handler) handleResponse(msg []byte, remoteAddr *net.UDPAddr) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Find peer by pending handshake
	for _, peer := range h.peers {
		peer.mu.Lock()

		if peer.handshake == nil {
			peer.mu.Unlock()
			continue
		}

		// Try to consume response
		if err := peer.handshake.ConsumeResponse(msg); err != nil {
			peer.mu.Unlock()
			continue
		}

		// Derive transport keys
		sendKey, recvKey, err := peer.handshake.DeriveKeys()
		if err != nil {
			h.log.Error("failed to derive keys", logger.Any("error", err))
			peer.mu.Unlock()
			return
		}

		// Create transport cipher
		cipher, err := wireguard.NewTransportCipher(sendKey, recvKey)
		if err != nil {
			h.log.Error("failed to create transport cipher", logger.Any("error", err))
			peer.mu.Unlock()
			return
		}

		// Update peer state
		peer.cipher = cipher
		peer.endpoint = remoteAddr
		peer.lastSeen = time.Now()

		h.log.Info("handshake response received", logger.Any("peer", base64.StdEncoding.EncodeToString(peer.publicKey[:])))

		peer.mu.Unlock()
		return
	}
}

// handleTransport handles a transport message.
func (h *Handler) handleTransport(msg []byte, remoteAddr *net.UDPAddr) {
	if len(msg) < wireguard.MessageTransportHeaderSize {
		return
	}

	// Extract receiver index
	receiverIdx := uint32(msg[4]) | uint32(msg[5])<<8 | uint32(msg[6])<<16 | uint32(msg[7])<<24

	h.mu.RLock()
	peer, ok := h.peersByIdx[receiverIdx]
	h.mu.RUnlock()

	if !ok {
		h.log.Debug("unknown receiver index", logger.Any("index", receiverIdx))
		return
	}

	peer.mu.Lock()
	defer peer.mu.Unlock()

	if peer.cipher == nil {
		h.log.Debug("no cipher for peer")
		return
	}

	// Decrypt message
	plaintext, err := peer.cipher.Decrypt(msg)
	if err != nil {
		h.log.Debug("failed to decrypt transport message", logger.Any("error", err))
		return
	}

	// Update peer state
	peer.endpoint = remoteAddr
	peer.lastSeen = time.Now()

	// Process decrypted IP packet
	h.processIPPacket(peer, plaintext)
}

// handleCookieReply handles a cookie reply message.
func (h *Handler) handleCookieReply(msg []byte, remoteAddr *net.UDPAddr) {
	// Cookie replies are used for DoS protection
	// For now, just log it
	h.log.Debug("received cookie reply", logger.Any("remote", remoteAddr))
}

// processIPPacket processes a decrypted IP packet.
func (h *Handler) processIPPacket(peer *Peer, packet []byte) {
	if len(packet) < 20 {
		return
	}

	// Check IP version
	version := packet[0] >> 4
	if version != 4 && version != 6 {
		return
	}

	// Extract destination IP
	var dstIP net.IP
	if version == 4 {
		dstIP = net.IP(packet[16:20])
	} else {
		if len(packet) < 40 {
			return
		}
		dstIP = net.IP(packet[24:40])
	}

	// Verify destination is in allowed IPs
	allowed := false
	for _, ipNet := range peer.allowedIPs {
		if ipNet.Contains(dstIP) {
			allowed = true
			break
		}
	}

	if !allowed {
		h.log.Debug("packet destination not in allowed IPs", logger.Any("dst", dstIP))
		return
	}

	// TODO: Forward packet to TUN device or process further
	h.log.Debug("received IP packet", logger.Any("version", version), logger.Any("dst", dstIP), logger.Any("len", len(packet)))
}

// SendPacket sends an IP packet to a peer.
func (h *Handler) SendPacket(peer *Peer, packet []byte) error {
	peer.mu.RLock()
	defer peer.mu.RUnlock()

	if peer.cipher == nil {
		return errors.New("no cipher established")
	}

	if peer.endpoint == nil {
		return errors.New("no endpoint for peer")
	}

	// Get receiver index
	_, remoteIdx := peer.handshake.GetIndices()

	// Encrypt packet
	encrypted := peer.cipher.Encrypt(packet, remoteIdx)

	// Send to peer
	_, err := h.conn.WriteToUDP(encrypted, peer.endpoint)
	return err
}

// InitiateHandshake initiates a handshake with a peer.
func (h *Handler) InitiateHandshake(peer *Peer) error {
	peer.mu.Lock()
	defer peer.mu.Unlock()

	if peer.endpoint == nil {
		return errors.New("no endpoint for peer")
	}

	// Create handshake state
	hs := wireguard.NewNoiseHandshake(h.privateKey, peer.publicKey, peer.psk)

	// Create initiation message
	initiation, err := hs.CreateInitiation()
	if err != nil {
		return fmt.Errorf("failed to create initiation: %w", err)
	}

	// Send initiation
	if _, err := h.conn.WriteToUDP(initiation, peer.endpoint); err != nil {
		return fmt.Errorf("failed to send initiation: %w", err)
	}

	// Store handshake state
	peer.handshake = hs

	// Register peer by index
	localIdx, _ := hs.GetIndices()
	h.mu.Lock()
	h.peersByIdx[localIdx] = peer
	h.mu.Unlock()

	h.log.Info("initiated handshake with peer", logger.Any("peer", base64.StdEncoding.EncodeToString(peer.publicKey[:])))

	return nil
}

// keepaliveLoop sends keepalive packets to peers.
func (h *Handler) keepaliveLoop() {
	ticker := time.NewTicker(h.config.KeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.mu.RLock()
			for _, peer := range h.peers {
				peer.mu.RLock()
				if peer.cipher != nil && peer.endpoint != nil {
					// Send empty keepalive packet
					_, remoteIdx := peer.handshake.GetIndices()
					keepalive := peer.cipher.Encrypt(nil, remoteIdx)
					h.conn.WriteToUDP(keepalive, peer.endpoint)
				}
				peer.mu.RUnlock()
			}
			h.mu.RUnlock()
		}
	}
}

// GetPublicKey returns the handler's public key.
func (h *Handler) GetPublicKey() string {
	return base64.StdEncoding.EncodeToString(h.publicKey[:])
}

// GetPeers returns the list of peers.
func (h *Handler) GetPeers() []*Peer {
	h.mu.RLock()
	defer h.mu.RUnlock()

	peers := make([]*Peer, 0, len(h.peers))
	for _, peer := range h.peers {
		peers = append(peers, peer)
	}
	return peers
}

// GetPeerStats returns statistics for a peer.
func (h *Handler) GetPeerStats(peer *Peer) map[string]interface{} {
	peer.mu.RLock()
	defer peer.mu.RUnlock()

	stats := map[string]interface{}{
		"public_key":   base64.StdEncoding.EncodeToString(peer.publicKey[:]),
		"last_seen":    peer.lastSeen,
		"has_cipher":   peer.cipher != nil,
		"allowed_ips":  peer.config.AllowedIPs,
	}

	if peer.endpoint != nil {
		stats["endpoint"] = peer.endpoint.String()
	}

	return stats
}

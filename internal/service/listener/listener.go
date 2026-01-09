package listener

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cocowh/netproxy/pkg/transport"
	"github.com/cocowh/netproxy/pkg/transport/kcp"
	"github.com/cocowh/netproxy/pkg/transport/ssh"
	"github.com/cocowh/netproxy/pkg/transport/tcp"
	"github.com/cocowh/netproxy/pkg/transport/tls"
	"github.com/cocowh/netproxy/pkg/transport/udp"
	"github.com/cocowh/netproxy/pkg/transport/websocket"
)

// ListenerConfig configures a listener
type ListenerConfig struct {
	Network  string // "tcp", "udp" (Layer 4)
	Protocol string // "socks5", "http" (Layer 7 - Optional, used for key generation)
	Addr     string
	Announce string
	Options  map[string]interface{}
}

// Manager manages network listeners
type Manager interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Refresh(configs []ListenerConfig) error
	GetPacketConn(addr string) net.PacketConn
}

type listenerManager struct {
	listeners       map[string]net.Listener
	packetListeners map[string]net.PacketConn
	mu              sync.RWMutex
	handler         ConnHandler
}

// ConnHandler handles incoming connections
type ConnHandler interface {
	HandleConn(ctx context.Context, conn net.Conn)
	HandlePacket(ctx context.Context, conn net.PacketConn)
}

func NewManager(handler ConnHandler) Manager {
	return &listenerManager{
		listeners:       make(map[string]net.Listener),
		packetListeners: make(map[string]net.PacketConn),
		handler:         handler,
	}
}

func (m *listenerManager) Start(ctx context.Context) error {
	return nil
}

func (m *listenerManager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, l := range m.listeners {
		l.Close()
	}
	m.listeners = make(map[string]net.Listener)

	for _, l := range m.packetListeners {
		l.Close()
	}
	m.packetListeners = make(map[string]net.PacketConn)

	return nil
}

func (m *listenerManager) Refresh(configs []ListenerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	newListeners := make(map[string]net.Listener)
	newPacketListeners := make(map[string]net.PacketConn)

	for _, cfg := range configs {
		// Determine Network Type
		network := cfg.Network
		if network == "" {
			network = "tcp" // Default
		}

		key := fmt.Sprintf("%s://%s", network, cfg.Addr)

		if network == "udp" {
			if l, ok := m.packetListeners[key]; ok {
				newPacketListeners[key] = l
				delete(m.packetListeners, key)
			} else {
				// Create new UDP listener
				l, err := startPacketListener(cfg)
				if err != nil {
					fmt.Printf("Failed to start packet listener %s: %v\n", key, err)
				} else {
					newPacketListeners[key] = l
					go m.handlePacketLoop(l)
				}
			}
		} else {
			// TCP / Stream
			if l, ok := m.listeners[key]; ok {
				newListeners[key] = l
				delete(m.listeners, key)
			} else {
				l, err := startListener(cfg)
				if err != nil {
					fmt.Printf("Failed to start listener %s: %v\n", key, err)
				} else {
					newListeners[key] = l
					go m.acceptLoop(l)
				}
			}
		}
	}

	// Stop old listeners
	for _, l := range m.listeners {
		l.Close()
	}
	for _, l := range m.packetListeners {
		l.Close()
	}

	m.listeners = newListeners
	m.packetListeners = newPacketListeners
	return nil
}

// GetPacketConn returns an existing packet listener by address
// This allows other components (like SOCKS5 UDP Associate) to reuse the port
func (m *listenerManager) GetPacketConn(addr string) net.PacketConn {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Try direct match first
	if l, ok := m.packetListeners["udp://"+addr]; ok {
		return l
	}

	// Try without protocol prefix if addr already has it?
	// The key format is "udp://:1080"
	return nil
}

func (m *listenerManager) acceptLoop(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			fmt.Printf("Accept error: %v\n", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go m.handler.HandleConn(context.Background(), conn)
	}
}

func (m *listenerManager) handlePacketLoop(conn net.PacketConn) {
	// For UDP PacketConn, there is no "Accept".
	// The PacketConn itself IS the listener and the handler.
	// We pass the PacketConn to the handler, which should start reading from it.
	// However, if we have multiple handlers or if the handler blocks, we should be careful.
	// In NetProxy architecture, Instance.HandlePacket takes the conn and processes it.
	// Since PacketConn is shared, the Handler typically enters a loop reading from it.
	// We run this in a goroutine.
	m.handler.HandlePacket(context.Background(), conn)
}

func getTransporter(cfg ListenerConfig) (transport.Transporter, error) {
	var t transport.Transporter
	var err error

	// Use Protocol to determine Transport type (e.g. "tcp", "kcp", "tls")
	// If Protocol is "socks5", "http", "sps", it implies standard TCP or UDP transport
	// unless specified otherwise.

	// Use Config Options to override or specify transport if Protocol is generic
	// But current design uses Protocol field for both Application Protocol (socks5) and Transport Protocol (kcp) sometimes?
	// The config parsing in main.go separates them:
	// ListenerConfig { Network: "tcp/udp", Protocol: "socks5", ... }
	// And we had transportProtocol passed as Network.
	//
	// However, getTransporter used cfg.Protocol.
	// main.go sets cfg.Protocol = handlerProtocol (socks5).
	// This was a bug in my previous reading or main.go logic?
	//
	// main.go:
	// lcConfig := listener.ListenerConfig{
	//    Network: transportProtocol, // "tcp", "udp", "kcp"
	//    Protocol: handlerProtocol, // "socks5"
	// }
	//
	// So getTransporter should switch on cfg.Network, not cfg.Protocol?
	// Or main.go logic for Transport selection was in options?
	//
	// Let's look at getTransporter in the original file.
	// It switched on cfg.Protocol.
	// But main.go sets cfg.Protocol to "socks5".
	// So it fell through to default: tcp/udp.
	//
	// If user wants KCP?
	// main.go:
	// if transportProtocol == "kcp" { lcConfig.Network = "kcp" }
	//
	// So we should switch on cfg.Network mostly, or special transport type.
	//
	// Let's refine this to check Network first for Transport selection.

	switch cfg.Network {
	case "kcp":
		t, err = parseKCPConfig(cfg.Options)
	case "ws":
		t = websocket.NewWSTransport("/ws")
	case "tls":
		t, err = parseTLSConfig(cfg.Options)
	case "ssh":
		t, err = parseSSHConfig(cfg.Options)
	case "udp":
		t = udp.NewUDPTransport(30 * time.Second)
	default:
		// tcp or others
		t = tcp.NewTCPTransport(30*time.Second, 30*time.Second)
	}
	return t, err
}

func startListener(cfg ListenerConfig) (net.Listener, error) {
	t, err := getTransporter(cfg)
	if err != nil {
		return nil, err
	}
	return t.Listen(context.Background(), cfg.Addr)
}

func startPacketListener(cfg ListenerConfig) (net.PacketConn, error) {
	t, err := getTransporter(cfg)
	if err != nil {
		return nil, err
	}
	return t.ListenPacket(context.Background(), cfg.Addr)
}

func parseTLSConfig(options map[string]interface{}) (transport.Transporter, error) {
	var cert, key, ca string
	var insecure bool

	if v, ok := options["cert"]; ok {
		cert = v.(string)
	}
	if v, ok := options["key"]; ok {
		key = v.(string)
	}
	if v, ok := options["ca"]; ok {
		ca = v.(string)
	}
	if v, ok := options["insecure"]; ok {
		if b, ok := v.(bool); ok {
			insecure = b
		}
	}

	return tls.NewTLSTransport(cert, key, ca, insecure)
}

func parseKCPConfig(options map[string]interface{}) (transport.Transporter, error) {
	dataShards := 10
	parityShards := 3
	key := "key"
	salt := "salt"

	if v, ok := options["data_shards"]; ok {
		if i, ok := v.(int); ok {
			dataShards = i
		} else if s, ok := v.(string); ok {
			if parsed, err := strconv.Atoi(s); err == nil {
				dataShards = parsed
			}
		}
	}
	if v, ok := options["parity_shards"]; ok {
		if i, ok := v.(int); ok {
			parityShards = i
		} else if s, ok := v.(string); ok {
			if parsed, err := strconv.Atoi(s); err == nil {
				parityShards = parsed
			}
		}
	}
	if v, ok := options["key"]; ok {
		key = v.(string)
	}
	if v, ok := options["salt"]; ok {
		salt = v.(string)
	}

	return kcp.NewKCPTransport(dataShards, parityShards, key, salt), nil
}

func parseSSHConfig(options map[string]interface{}) (transport.Transporter, error) {
	var user, ZINFOID_06Q, keyFile, remoteAddr string

	if v, ok := options["user"]; ok {
		user = v.(string)
	}
	if v, ok := options["ZINFOID_06Q"]; ok {
		ZINFOID_06Q = v.(string)
	}
	if v, ok := options["key_file"]; ok {
		keyFile = v.(string)
	}
	if v, ok := options["remote_addr"]; ok {
		remoteAddr = v.(string)
	}

	return ssh.NewSSHTransport(user, ZINFOID_06Q, keyFile, remoteAddr), nil
}

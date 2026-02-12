package transport

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/cocowh/netproxy/pkg/transport"
	"github.com/cocowh/netproxy/pkg/transport/kcp"
)

// KCPDialer implements ProxyDialer for KCP transport.
// It wraps the pkg/transport/kcp package for integration with the project's
// routing and proxy chain system.
type KCPDialer struct {
	next      transport.ProxyDialer
	addr      string
	config    *kcp.Config
	transport *kcp.Transport
	timeout   time.Duration
}

// KCPDialerOption is a function that configures a KCPDialer.
type KCPDialerOption func(*KCPDialer)

// WithKCPConfig sets the KCP configuration.
func WithKCPConfig(config *kcp.Config) KCPDialerOption {
	return func(d *KCPDialer) {
		d.config = config
	}
}

// WithKCPTimeout sets the dial timeout.
func WithKCPTimeout(timeout time.Duration) KCPDialerOption {
	return func(d *KCPDialer) {
		d.timeout = timeout
	}
}

// WithKCPMode sets the KCP mode (normal, fast, mobile).
func WithKCPMode(mode kcp.Mode) KCPDialerOption {
	return func(d *KCPDialer) {
		d.config = kcp.ConfigFromMode(mode)
	}
}

// WithKCPKey sets the encryption key.
func WithKCPKey(key string) KCPDialerOption {
	return func(d *KCPDialer) {
		if d.config == nil {
			d.config = kcp.DefaultConfig()
		}
		d.config.Key = key
	}
}

// WithKCPCrypt sets the encryption method.
func WithKCPCrypt(crypt string) KCPDialerOption {
	return func(d *KCPDialer) {
		if d.config == nil {
			d.config = kcp.DefaultConfig()
		}
		d.config.Crypt = crypt
	}
}

// WithKCPCompression enables or disables compression.
func WithKCPCompression(enabled bool) KCPDialerOption {
	return func(d *KCPDialer) {
		if d.config == nil {
			d.config = kcp.DefaultConfig()
		}
		d.config.Compression = enabled
	}
}

// NewKCPDialer creates a new KCP dialer.
// The addr parameter specifies the KCP server address (host:port).
// The next parameter is the underlying dialer (usually DirectDialer for KCP).
func NewKCPDialer(next transport.ProxyDialer, addr string, opts ...KCPDialerOption) (*KCPDialer, error) {
	d := &KCPDialer{
		next:    next,
		addr:    addr,
		config:  kcp.DefaultConfig(),
		timeout: 30 * time.Second,
	}

	for _, opt := range opts {
		opt(d)
	}

	// Create KCP transport
	t, err := kcp.NewTransport(d.config)
	if err != nil {
		return nil, fmt.Errorf("failed to create KCP transport: %w", err)
	}
	d.transport = t

	return d, nil
}

// Dial establishes a connection through KCP to the target address.
// For KCP, we first connect to the KCP server, then the server proxies to the target.
func (d *KCPDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.timeout)
		defer cancel()
	}

	// Dial KCP server
	conn, err := d.transport.Dial(ctx, d.addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial KCP server %s: %w", d.addr, err)
	}

	return conn, nil
}

// DialPacket is not supported for KCP as it provides stream connections.
func (d *KCPDialer) DialPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	return nil, fmt.Errorf("KCP does not support packet connections")
}

// KCPTransportDialer wraps KCP transport as a ProxyDialer.
// This is useful when you want to use KCP as a transport layer
// for other proxy protocols (e.g., SOCKS5 over KCP).
type KCPTransportDialer struct {
	transport *kcp.Transport
	serverAddr string
	timeout   time.Duration
}

// NewKCPTransportDialer creates a new KCP transport dialer.
func NewKCPTransportDialer(serverAddr string, config *kcp.Config, timeout time.Duration) (*KCPTransportDialer, error) {
	if config == nil {
		config = kcp.DefaultConfig()
	}

	t, err := kcp.NewTransport(config)
	if err != nil {
		return nil, err
	}

	return &KCPTransportDialer{
		transport:  t,
		serverAddr: serverAddr,
		timeout:    timeout,
	}, nil
}

// Dial establishes a KCP connection to the server.
// The network and addr parameters are ignored as KCP connects to a fixed server.
func (d *KCPTransportDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.timeout)
		defer cancel()
	}

	return d.transport.Dial(ctx, d.serverAddr)
}

// DialPacket is not supported for KCP.
func (d *KCPTransportDialer) DialPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	return nil, fmt.Errorf("KCP does not support packet connections")
}

// ParseKCPConfig parses KCP configuration from a map.
// This is useful for parsing configuration from YAML/JSON.
func ParseKCPConfig(m map[string]interface{}) (*kcp.Config, error) {
	config := kcp.DefaultConfig()

	if v, ok := m["mtu"].(int); ok {
		config.MTU = v
	}
	if v, ok := m["snd_wnd"].(int); ok {
		config.SndWnd = v
	}
	if v, ok := m["rcv_wnd"].(int); ok {
		config.RcvWnd = v
	}
	if v, ok := m["data_shard"].(int); ok {
		config.DataShard = v
	}
	if v, ok := m["parity_shard"].(int); ok {
		config.ParityShard = v
	}
	if v, ok := m["dscp"].(int); ok {
		config.DSCP = v
	}
	if v, ok := m["no_delay"].(int); ok {
		config.NoDelay = v
	}
	if v, ok := m["interval"].(int); ok {
		config.Interval = v
	}
	if v, ok := m["resend"].(int); ok {
		config.Resend = v
	}
	if v, ok := m["nc"].(int); ok {
		config.NC = v
	}
	if v, ok := m["read_buffer"].(int); ok {
		config.ReadBuffer = v
	}
	if v, ok := m["write_buffer"].(int); ok {
		config.WriteBuffer = v
	}
	if v, ok := m["ack_no_delay"].(bool); ok {
		config.AckNoDelay = v
	}
	if v, ok := m["keep_alive"].(string); ok {
		if d, err := time.ParseDuration(v); err == nil {
			config.KeepAlive = d
		}
	}
	if v, ok := m["crypt"].(string); ok {
		config.Crypt = v
	}
	if v, ok := m["key"].(string); ok {
		config.Key = v
	}
	if v, ok := m["compression"].(bool); ok {
		config.Compression = v
	}
	if v, ok := m["stream_mode"].(bool); ok {
		config.StreamMode = v
	}
	if v, ok := m["mode"].(string); ok {
		switch v {
		case "fast":
			config = kcp.FastConfig()
		case "mobile":
			config = kcp.MobileConfig()
		case "normal":
			config = kcp.NormalConfig()
		}
		// Re-apply specific overrides after mode preset
		if key, ok := m["key"].(string); ok {
			config.Key = key
		}
		if crypt, ok := m["crypt"].(string); ok {
			config.Crypt = crypt
		}
	}

	return config, config.Validate()
}

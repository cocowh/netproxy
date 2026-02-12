// Package kcp provides KCP transport protocol implementation.
// KCP is a reliable UDP-based transport protocol that trades bandwidth for lower latency.
// It is particularly suitable for mobile networks and high packet loss environments.
package kcp

import (
	"crypto/sha256"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

// Config holds KCP transport configuration options.
// These parameters control the behavior of the KCP protocol.
type Config struct {
	// MTU is the Maximum Transmission Unit size (default: 1350)
	MTU int `json:"mtu" yaml:"mtu"`

	// SndWnd is the send window size (default: 1024)
	SndWnd int `json:"snd_wnd" yaml:"snd_wnd"`

	// RcvWnd is the receive window size (default: 1024)
	RcvWnd int `json:"rcv_wnd" yaml:"rcv_wnd"`

	// DataShard is the number of data shards for FEC (default: 10)
	// Set to 0 to disable FEC
	DataShard int `json:"data_shard" yaml:"data_shard"`

	// ParityShard is the number of parity shards for FEC (default: 3)
	// Set to 0 to disable FEC
	ParityShard int `json:"parity_shard" yaml:"parity_shard"`

	// DSCP is the Differentiated Services Code Point for QoS (default: 0)
	DSCP int `json:"dscp" yaml:"dscp"`

	// NoDelay enables nodelay mode for lower latency (default: true)
	// 0: disable, 1: enable
	NoDelay int `json:"no_delay" yaml:"no_delay"`

	// Interval is the internal update interval in milliseconds (default: 40)
	Interval int `json:"interval" yaml:"interval"`

	// Resend is the fast retransmit trigger count (default: 2)
	// 0: disable fast retransmit
	Resend int `json:"resend" yaml:"resend"`

	// NC controls congestion control (default: 1)
	// 0: enable congestion control, 1: disable congestion control
	NC int `json:"nc" yaml:"nc"`

	// ReadBuffer is the socket read buffer size in bytes (default: 4MB)
	ReadBuffer int `json:"read_buffer" yaml:"read_buffer"`

	// WriteBuffer is the socket write buffer size in bytes (default: 4MB)
	WriteBuffer int `json:"write_buffer" yaml:"write_buffer"`

	// AckNoDelay enables immediate ACK sending (default: false)
	AckNoDelay bool `json:"ack_no_delay" yaml:"ack_no_delay"`

	// KeepAlive is the keep-alive interval (default: 10s)
	KeepAlive time.Duration `json:"keep_alive" yaml:"keep_alive"`

	// Crypt specifies the encryption method (default: "aes")
	// Supported: "aes", "aes-128", "aes-192", "salsa20", "blowfish",
	// "twofish", "cast5", "3des", "tea", "xtea", "xor", "sm4", "none"
	Crypt string `json:"crypt" yaml:"crypt"`

	// Key is the encryption key/password
	Key string `json:"key" yaml:"key"`

	// Compression enables Snappy compression (default: false)
	Compression bool `json:"compression" yaml:"compression"`

	// StreamMode enables stream mode (default: true)
	// In stream mode, KCP behaves like TCP with ordered byte stream
	StreamMode bool `json:"stream_mode" yaml:"stream_mode"`
}

// DefaultConfig returns a Config with sensible defaults optimized for
// general use cases with a balance between latency and bandwidth.
func DefaultConfig() *Config {
	return &Config{
		MTU:         1350,
		SndWnd:      1024,
		RcvWnd:      1024,
		DataShard:   10,
		ParityShard: 3,
		DSCP:        0,
		NoDelay:     1,
		Interval:    40,
		Resend:      2,
		NC:          1,
		ReadBuffer:  4 * 1024 * 1024,  // 4MB
		WriteBuffer: 4 * 1024 * 1024,  // 4MB
		AckNoDelay:  false,
		KeepAlive:   10 * time.Second,
		Crypt:       "aes",
		Key:         "",
		Compression: false,
		StreamMode:  true,
	}
}

// FastConfig returns a Config optimized for low latency at the cost of bandwidth.
// Suitable for real-time applications like gaming or VoIP.
func FastConfig() *Config {
	cfg := DefaultConfig()
	cfg.NoDelay = 1
	cfg.Interval = 10
	cfg.Resend = 2
	cfg.NC = 1
	cfg.SndWnd = 2048
	cfg.RcvWnd = 2048
	return cfg
}

// NormalConfig returns a Config with balanced settings.
// Suitable for general proxy usage.
func NormalConfig() *Config {
	cfg := DefaultConfig()
	cfg.NoDelay = 0
	cfg.Interval = 40
	cfg.Resend = 2
	cfg.NC = 1
	return cfg
}

// MobileConfig returns a Config optimized for mobile networks with high packet loss.
func MobileConfig() *Config {
	cfg := DefaultConfig()
	cfg.NoDelay = 1
	cfg.Interval = 20
	cfg.Resend = 2
	cfg.NC = 1
	cfg.DataShard = 20
	cfg.ParityShard = 10
	cfg.SndWnd = 512
	cfg.RcvWnd = 512
	return cfg
}

// Validate checks if the configuration is valid and applies defaults for zero values.
func (c *Config) Validate() error {
	if c.MTU <= 0 {
		c.MTU = 1350
	}
	if c.SndWnd <= 0 {
		c.SndWnd = 1024
	}
	if c.RcvWnd <= 0 {
		c.RcvWnd = 1024
	}
	if c.Interval <= 0 {
		c.Interval = 40
	}
	if c.ReadBuffer <= 0 {
		c.ReadBuffer = 4 * 1024 * 1024
	}
	if c.WriteBuffer <= 0 {
		c.WriteBuffer = 4 * 1024 * 1024
	}
	if c.KeepAlive <= 0 {
		c.KeepAlive = 10 * time.Second
	}
	if c.Crypt == "" {
		c.Crypt = "aes"
	}
	return nil
}

// GetBlockCrypt returns the block cipher for KCP encryption based on config.
func (c *Config) GetBlockCrypt() (kcp.BlockCrypt, error) {
	if c.Crypt == "none" || c.Key == "" {
		return nil, nil
	}

	// Derive key using PBKDF2
	pass := pbkdf2.Key([]byte(c.Key), []byte("kcp-go"), 4096, 32, sha256.New)

	switch c.Crypt {
	case "aes", "aes-128":
		return kcp.NewAESBlockCrypt(pass[:16])
	case "aes-192":
		return kcp.NewAESBlockCrypt(pass[:24])
	case "aes-256":
		return kcp.NewAESBlockCrypt(pass[:32])
	case "salsa20":
		return kcp.NewSalsa20BlockCrypt(pass)
	case "blowfish":
		return kcp.NewBlowfishBlockCrypt(pass)
	case "twofish":
		return kcp.NewTwofishBlockCrypt(pass)
	case "cast5":
		return kcp.NewCast5BlockCrypt(pass[:16])
	case "3des":
		return kcp.NewTripleDESBlockCrypt(pass[:24])
	case "tea":
		return kcp.NewTEABlockCrypt(pass[:16])
	case "xtea":
		return kcp.NewXTEABlockCrypt(pass[:16])
	case "xor":
		return kcp.NewSimpleXORBlockCrypt(pass)
	case "sm4":
		return kcp.NewSM4BlockCrypt(pass[:16])
	default:
		return kcp.NewAESBlockCrypt(pass[:16])
	}
}

// Mode represents predefined KCP configuration modes.
type Mode string

const (
	// ModeNormal is the default balanced mode
	ModeNormal Mode = "normal"
	// ModeFast is optimized for low latency
	ModeFast Mode = "fast"
	// ModeMobile is optimized for mobile networks
	ModeMobile Mode = "mobile"
)

// ConfigFromMode returns a Config based on the specified mode.
func ConfigFromMode(mode Mode) *Config {
	switch mode {
	case ModeFast:
		return FastConfig()
	case ModeMobile:
		return MobileConfig()
	default:
		return NormalConfig()
	}
}

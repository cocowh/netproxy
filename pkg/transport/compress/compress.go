package compress

import (
	"fmt"
	"net"
)

// Type represents the compression algorithm type.
type Type string

const (
	// TypeNone means no compression.
	TypeNone Type = "none"
	// TypeSnappy uses Snappy compression (fast, moderate ratio).
	TypeSnappy Type = "snappy"
	// TypeGzip uses Gzip compression (slower, better ratio).
	TypeGzip Type = "gzip"
)

// Config holds compression configuration.
type Config struct {
	// Type is the compression algorithm to use.
	Type Type `json:"type" yaml:"type"`

	// Level is the compression level (only applicable for Gzip).
	// Valid values: 0 (no compression) to 9 (best compression).
	// Default is -1 (default compression).
	Level int `json:"level" yaml:"level"`
}

// DefaultConfig returns a default compression configuration.
func DefaultConfig() *Config {
	return &Config{
		Type:  TypeSnappy,
		Level: -1, // Default compression level
	}
}

// Validate validates the compression configuration.
func (c *Config) Validate() error {
	switch c.Type {
	case TypeNone, TypeSnappy, TypeGzip:
		// Valid types
	default:
		return fmt.Errorf("unsupported compression type: %s", c.Type)
	}

	if c.Type == TypeGzip && (c.Level < -1 || c.Level > 9) {
		return fmt.Errorf("invalid gzip compression level: %d (must be -1 to 9)", c.Level)
	}

	return nil
}

// Compressor provides compression and decompression functionality.
type Compressor interface {
	// Compress compresses the input data.
	Compress(src []byte) ([]byte, error)

	// Decompress decompresses the input data.
	Decompress(src []byte) ([]byte, error)

	// WrapConn wraps a connection with compression.
	WrapConn(conn net.Conn) net.Conn

	// Type returns the compression type.
	Type() Type
}

// snappyCompressor implements Compressor for Snappy.
type snappyCompressor struct{}

func (c *snappyCompressor) Compress(src []byte) ([]byte, error) {
	return CompressSnappy(src), nil
}

func (c *snappyCompressor) Decompress(src []byte) ([]byte, error) {
	return DecompressSnappy(src)
}

func (c *snappyCompressor) WrapConn(conn net.Conn) net.Conn {
	return NewSnappyConn(conn)
}

func (c *snappyCompressor) Type() Type {
	return TypeSnappy
}

// gzipCompressor implements Compressor for Gzip.
type gzipCompressor struct {
	level GzipLevel
}

func (c *gzipCompressor) Compress(src []byte) ([]byte, error) {
	return CompressGzipLevel(src, c.level)
}

func (c *gzipCompressor) Decompress(src []byte) ([]byte, error) {
	return DecompressGzip(src)
}

func (c *gzipCompressor) WrapConn(conn net.Conn) net.Conn {
	return NewGzipConn(conn, WithGzipLevel(c.level))
}

func (c *gzipCompressor) Type() Type {
	return TypeGzip
}

// noneCompressor implements Compressor with no compression.
type noneCompressor struct{}

func (c *noneCompressor) Compress(src []byte) ([]byte, error) {
	return src, nil
}

func (c *noneCompressor) Decompress(src []byte) ([]byte, error) {
	return src, nil
}

func (c *noneCompressor) WrapConn(conn net.Conn) net.Conn {
	return conn
}

func (c *noneCompressor) Type() Type {
	return TypeNone
}

// NewCompressor creates a new Compressor based on the configuration.
func NewCompressor(config *Config) (Compressor, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	switch config.Type {
	case TypeNone:
		return &noneCompressor{}, nil
	case TypeSnappy:
		return &snappyCompressor{}, nil
	case TypeGzip:
		level := GzipLevel(config.Level)
		if config.Level == -1 {
			level = GzipDefaultCompression
		}
		return &gzipCompressor{level: level}, nil
	default:
		return nil, fmt.Errorf("unsupported compression type: %s", config.Type)
	}
}

// NewCompressorByType creates a new Compressor by type name.
func NewCompressorByType(t Type) (Compressor, error) {
	return NewCompressor(&Config{Type: t, Level: -1})
}

// WrapConn wraps a connection with the specified compression type.
// This is a convenience function for simple use cases.
func WrapConn(conn net.Conn, t Type) (net.Conn, error) {
	compressor, err := NewCompressorByType(t)
	if err != nil {
		return nil, err
	}
	return compressor.WrapConn(conn), nil
}

// Compress compresses data using the specified compression type.
func Compress(src []byte, t Type) ([]byte, error) {
	compressor, err := NewCompressorByType(t)
	if err != nil {
		return nil, err
	}
	return compressor.Compress(src)
}

// Decompress decompresses data using the specified compression type.
func Decompress(src []byte, t Type) ([]byte, error) {
	compressor, err := NewCompressorByType(t)
	if err != nil {
		return nil, err
	}
	return compressor.Decompress(src)
}

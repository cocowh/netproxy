// Package compress provides compression wrappers for network connections.
// It supports multiple compression algorithms including Snappy and Gzip.
package compress

import (
	"net"

	"github.com/golang/snappy"
)

// SnappyConn wraps a net.Conn with Snappy compression.
// Snappy is optimized for speed rather than compression ratio,
// making it suitable for real-time network traffic.
type SnappyConn struct {
	net.Conn
	reader *snappy.Reader
	writer *snappy.Writer
}

// NewSnappyConn creates a new Snappy-compressed connection wrapper.
func NewSnappyConn(conn net.Conn) net.Conn {
	return &SnappyConn{
		Conn:   conn,
		reader: snappy.NewReader(conn),
		writer: snappy.NewBufferedWriter(conn),
	}
}

// Read reads and decompresses data from the underlying connection.
func (c *SnappyConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// Write compresses and writes data to the underlying connection.
func (c *SnappyConn) Write(b []byte) (int, error) {
	n, err := c.writer.Write(b)
	if err != nil {
		return n, err
	}
	// Snappy buffered writer needs Flush to actually send data
	err = c.writer.Flush()
	return n, err
}

// Close closes the underlying connection.
func (c *SnappyConn) Close() error {
	return c.Conn.Close()
}

// SnappyReader wraps an io.Reader with Snappy decompression.
type SnappyReader struct {
	reader *snappy.Reader
}

// NewSnappyReader creates a new Snappy reader.
func NewSnappyReader(r net.Conn) *SnappyReader {
	return &SnappyReader{
		reader: snappy.NewReader(r),
	}
}

// Read reads and decompresses data.
func (r *SnappyReader) Read(b []byte) (int, error) {
	return r.reader.Read(b)
}

// Reset resets the reader to read from a new source.
func (r *SnappyReader) Reset(conn net.Conn) {
	r.reader.Reset(conn)
}

// SnappyWriter wraps an io.Writer with Snappy compression.
type SnappyWriter struct {
	writer *snappy.Writer
}

// NewSnappyWriter creates a new Snappy writer.
func NewSnappyWriter(w net.Conn) *SnappyWriter {
	return &SnappyWriter{
		writer: snappy.NewBufferedWriter(w),
	}
}

// Write compresses and writes data.
func (w *SnappyWriter) Write(b []byte) (int, error) {
	n, err := w.writer.Write(b)
	if err != nil {
		return n, err
	}
	return n, w.writer.Flush()
}

// Reset resets the writer to write to a new destination.
func (w *SnappyWriter) Reset(conn net.Conn) {
	w.writer.Reset(conn)
}

// Flush flushes any buffered data to the underlying writer.
func (w *SnappyWriter) Flush() error {
	return w.writer.Flush()
}

// CompressSnappy compresses data using Snappy algorithm.
func CompressSnappy(src []byte) []byte {
	return snappy.Encode(nil, src)
}

// DecompressSnappy decompresses Snappy-compressed data.
func DecompressSnappy(src []byte) ([]byte, error) {
	return snappy.Decode(nil, src)
}

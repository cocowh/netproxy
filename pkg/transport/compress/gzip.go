package compress

import (
	"bytes"
	"compress/gzip"
	"io"
	"net"
	"sync"
)

// GzipLevel represents the compression level for Gzip.
type GzipLevel int

const (
	// GzipNoCompression means no compression at all.
	GzipNoCompression GzipLevel = gzip.NoCompression
	// GzipBestSpeed provides the fastest compression.
	GzipBestSpeed GzipLevel = gzip.BestSpeed
	// GzipBestCompression provides the best compression ratio.
	GzipBestCompression GzipLevel = gzip.BestCompression
	// GzipDefaultCompression is the default compression level.
	GzipDefaultCompression GzipLevel = gzip.DefaultCompression
	// GzipHuffmanOnly uses Huffman compression only.
	GzipHuffmanOnly GzipLevel = gzip.HuffmanOnly
)

// GzipConn wraps a net.Conn with Gzip compression.
// Gzip provides better compression ratio than Snappy but is slower.
// It's suitable for bandwidth-constrained environments.
type GzipConn struct {
	net.Conn
	reader     *gzip.Reader
	writer     *gzip.Writer
	level      GzipLevel
	readMutex  sync.Mutex
	writeMutex sync.Mutex
	readInit   bool
	writeInit  bool
}

// GzipConnOption is a function that configures a GzipConn.
type GzipConnOption func(*GzipConn)

// WithGzipLevel sets the compression level.
func WithGzipLevel(level GzipLevel) GzipConnOption {
	return func(c *GzipConn) {
		c.level = level
	}
}

// NewGzipConn creates a new Gzip-compressed connection wrapper.
func NewGzipConn(conn net.Conn, opts ...GzipConnOption) net.Conn {
	c := &GzipConn{
		Conn:  conn,
		level: GzipDefaultCompression,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Read reads and decompresses data from the underlying connection.
func (c *GzipConn) Read(b []byte) (int, error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	if !c.readInit {
		var err error
		c.reader, err = gzip.NewReader(c.Conn)
		if err != nil {
			return 0, err
		}
		c.readInit = true
	}

	return c.reader.Read(b)
}

// Write compresses and writes data to the underlying connection.
func (c *GzipConn) Write(b []byte) (int, error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	if !c.writeInit {
		var err error
		c.writer, err = gzip.NewWriterLevel(c.Conn, int(c.level))
		if err != nil {
			return 0, err
		}
		c.writeInit = true
	}

	n, err := c.writer.Write(b)
	if err != nil {
		return n, err
	}

	// Flush to ensure data is sent immediately
	err = c.writer.Flush()
	return n, err
}

// Close closes the gzip writer/reader and the underlying connection.
func (c *GzipConn) Close() error {
	c.writeMutex.Lock()
	if c.writer != nil {
		c.writer.Close()
	}
	c.writeMutex.Unlock()

	c.readMutex.Lock()
	if c.reader != nil {
		c.reader.Close()
	}
	c.readMutex.Unlock()

	return c.Conn.Close()
}

// GzipReader wraps an io.Reader with Gzip decompression.
type GzipReader struct {
	reader *gzip.Reader
	source io.Reader
	init   bool
	mu     sync.Mutex
}

// NewGzipReader creates a new Gzip reader.
func NewGzipReader(r io.Reader) *GzipReader {
	return &GzipReader{
		source: r,
	}
}

// Read reads and decompresses data.
func (r *GzipReader) Read(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.init {
		var err error
		r.reader, err = gzip.NewReader(r.source)
		if err != nil {
			return 0, err
		}
		r.init = true
	}

	return r.reader.Read(b)
}

// Close closes the gzip reader.
func (r *GzipReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.reader != nil {
		return r.reader.Close()
	}
	return nil
}

// Reset resets the reader to read from a new source.
func (r *GzipReader) Reset(source io.Reader) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.source = source
	if r.reader != nil {
		return r.reader.Reset(source)
	}
	r.init = false
	return nil
}

// GzipWriter wraps an io.Writer with Gzip compression.
type GzipWriter struct {
	writer *gzip.Writer
	dest   io.Writer
	level  GzipLevel
	init   bool
	mu     sync.Mutex
}

// NewGzipWriter creates a new Gzip writer with default compression level.
func NewGzipWriter(w io.Writer) *GzipWriter {
	return NewGzipWriterLevel(w, GzipDefaultCompression)
}

// NewGzipWriterLevel creates a new Gzip writer with specified compression level.
func NewGzipWriterLevel(w io.Writer, level GzipLevel) *GzipWriter {
	return &GzipWriter{
		dest:  w,
		level: level,
	}
}

// Write compresses and writes data.
func (w *GzipWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.init {
		var err error
		w.writer, err = gzip.NewWriterLevel(w.dest, int(w.level))
		if err != nil {
			return 0, err
		}
		w.init = true
	}

	n, err := w.writer.Write(b)
	if err != nil {
		return n, err
	}

	return n, w.writer.Flush()
}

// Flush flushes any buffered data to the underlying writer.
func (w *GzipWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.writer != nil {
		return w.writer.Flush()
	}
	return nil
}

// Close closes the gzip writer.
func (w *GzipWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.writer != nil {
		return w.writer.Close()
	}
	return nil
}

// Reset resets the writer to write to a new destination.
func (w *GzipWriter) Reset(dest io.Writer) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.dest = dest
	if w.writer != nil {
		w.writer.Reset(dest)
	} else {
		w.init = false
	}
}

// CompressGzip compresses data using Gzip algorithm with default compression level.
func CompressGzip(src []byte) ([]byte, error) {
	return CompressGzipLevel(src, GzipDefaultCompression)
}

// CompressGzipLevel compresses data using Gzip algorithm with specified compression level.
func CompressGzipLevel(src []byte, level GzipLevel) ([]byte, error) {
	var buf bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buf, int(level))
	if err != nil {
		return nil, err
	}

	_, err = writer.Write(src)
	if err != nil {
		writer.Close()
		return nil, err
	}

	err = writer.Close()
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecompressGzip decompresses Gzip-compressed data.
func DecompressGzip(src []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(src))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return io.ReadAll(reader)
}

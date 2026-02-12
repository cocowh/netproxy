package compress

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestSnappyCompressDecompress(t *testing.T) {
	testData := []byte("Hello, World! This is a test message for Snappy compression.")

	compressed := CompressSnappy(testData)
	if len(compressed) == 0 {
		t.Error("compressed data should not be empty")
	}

	decompressed, err := DecompressSnappy(compressed)
	if err != nil {
		t.Fatalf("failed to decompress: %v", err)
	}

	if !bytes.Equal(testData, decompressed) {
		t.Errorf("decompressed data does not match original: got %s, want %s", decompressed, testData)
	}
}

func TestGzipCompressDecompress(t *testing.T) {
	testData := []byte("Hello, World! This is a test message for Gzip compression.")

	compressed, err := CompressGzip(testData)
	if err != nil {
		t.Fatalf("failed to compress: %v", err)
	}

	if len(compressed) == 0 {
		t.Error("compressed data should not be empty")
	}

	decompressed, err := DecompressGzip(compressed)
	if err != nil {
		t.Fatalf("failed to decompress: %v", err)
	}

	if !bytes.Equal(testData, decompressed) {
		t.Errorf("decompressed data does not match original: got %s, want %s", decompressed, testData)
	}
}

func TestGzipCompressLevels(t *testing.T) {
	testData := make([]byte, 10000)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	levels := []GzipLevel{
		GzipNoCompression,
		GzipBestSpeed,
		GzipDefaultCompression,
		GzipBestCompression,
	}

	for _, level := range levels {
		compressed, err := CompressGzipLevel(testData, level)
		if err != nil {
			t.Errorf("level %d: failed to compress: %v", level, err)
			continue
		}

		decompressed, err := DecompressGzip(compressed)
		if err != nil {
			t.Errorf("level %d: failed to decompress: %v", level, err)
			continue
		}

		if !bytes.Equal(testData, decompressed) {
			t.Errorf("level %d: decompressed data does not match original", level)
		}
	}
}

func TestCompressorInterface(t *testing.T) {
	testData := []byte("Test data for compressor interface")

	tests := []struct {
		name   string
		config *Config
	}{
		{"none", &Config{Type: TypeNone}},
		{"snappy", &Config{Type: TypeSnappy}},
		{"gzip-default", &Config{Type: TypeGzip, Level: -1}},
		{"gzip-best-speed", &Config{Type: TypeGzip, Level: 1}},
		{"gzip-best-compression", &Config{Type: TypeGzip, Level: 9}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressor, err := NewCompressor(tt.config)
			if err != nil {
				t.Fatalf("failed to create compressor: %v", err)
			}

			if compressor.Type() != tt.config.Type {
				t.Errorf("type mismatch: got %s, want %s", compressor.Type(), tt.config.Type)
			}

			compressed, err := compressor.Compress(testData)
			if err != nil {
				t.Fatalf("failed to compress: %v", err)
			}

			decompressed, err := compressor.Decompress(compressed)
			if err != nil {
				t.Fatalf("failed to decompress: %v", err)
			}

			if !bytes.Equal(testData, decompressed) {
				t.Error("decompressed data does not match original")
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{"valid-none", &Config{Type: TypeNone}, false},
		{"valid-snappy", &Config{Type: TypeSnappy}, false},
		{"valid-gzip", &Config{Type: TypeGzip, Level: 5}, false},
		{"invalid-type", &Config{Type: "invalid"}, true},
		{"invalid-gzip-level-low", &Config{Type: TypeGzip, Level: -2}, true},
		{"invalid-gzip-level-high", &Config{Type: TypeGzip, Level: 10}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// mockConn is a simple mock net.Conn for testing
type mockConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	closed   bool
	mu       sync.Mutex
}

func newMockConn() *mockConn {
	return &mockConn{
		readBuf:  new(bytes.Buffer),
		writeBuf: new(bytes.Buffer),
	}
}

func (c *mockConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readBuf.Read(b)
}

func (c *mockConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeBuf.Write(b)
}

func (c *mockConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *mockConn) LocalAddr() net.Addr                { return nil }
func (c *mockConn) RemoteAddr() net.Addr               { return nil }
func (c *mockConn) SetDeadline(t time.Time) error      { return nil }
func (c *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestSnappyConnWriteRead(t *testing.T) {
	// Create a pipe for testing
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	testData := []byte("Hello, Snappy!")

	// Wrap both ends with Snappy compression
	serverConn := NewSnappyConn(server)
	clientConn := NewSnappyConn(client)

	var wg sync.WaitGroup
	wg.Add(2)

	// Writer goroutine
	go func() {
		defer wg.Done()
		_, err := clientConn.Write(testData)
		if err != nil {
			t.Errorf("write error: %v", err)
		}
	}()

	// Reader goroutine
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		n, err := serverConn.Read(buf)
		if err != nil && err != io.EOF {
			t.Errorf("read error: %v", err)
			return
		}
		if !bytes.Equal(buf[:n], testData) {
			t.Errorf("data mismatch: got %s, want %s", buf[:n], testData)
		}
	}()

	wg.Wait()
}

func TestGzipConnWriteRead(t *testing.T) {
	// Create a pipe for testing
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	testData := []byte("Hello, Gzip!")

	// Wrap both ends with Gzip compression
	serverConn := NewGzipConn(server)
	clientConn := NewGzipConn(client)

	var wg sync.WaitGroup
	wg.Add(2)

	// Writer goroutine
	go func() {
		defer wg.Done()
		_, err := clientConn.Write(testData)
		if err != nil {
			t.Errorf("write error: %v", err)
		}
	}()

	// Reader goroutine
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		n, err := serverConn.Read(buf)
		if err != nil && err != io.EOF {
			t.Errorf("read error: %v", err)
			return
		}
		if !bytes.Equal(buf[:n], testData) {
			t.Errorf("data mismatch: got %s, want %s", buf[:n], testData)
		}
	}()

	wg.Wait()
}

func TestWrapConnConvenience(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Test WrapConn function
	wrappedServer, err := WrapConn(server, TypeSnappy)
	if err != nil {
		t.Fatalf("failed to wrap server conn: %v", err)
	}

	wrappedClient, err := WrapConn(client, TypeSnappy)
	if err != nil {
		t.Fatalf("failed to wrap client conn: %v", err)
	}

	testData := []byte("Test WrapConn")

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		wrappedClient.Write(testData)
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		n, _ := wrappedServer.Read(buf)
		if !bytes.Equal(buf[:n], testData) {
			t.Errorf("data mismatch")
		}
	}()

	wg.Wait()
}

func TestCompressDecompressConvenience(t *testing.T) {
	testData := []byte("Test convenience functions")

	types := []Type{TypeNone, TypeSnappy, TypeGzip}

	for _, typ := range types {
		compressed, err := Compress(testData, typ)
		if err != nil {
			t.Errorf("type %s: compress error: %v", typ, err)
			continue
		}

		decompressed, err := Decompress(compressed, typ)
		if err != nil {
			t.Errorf("type %s: decompress error: %v", typ, err)
			continue
		}

		if !bytes.Equal(testData, decompressed) {
			t.Errorf("type %s: data mismatch", typ)
		}
	}
}

// Benchmark tests
func BenchmarkSnappyCompress(b *testing.B) {
	data := make([]byte, 10000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CompressSnappy(data)
	}
}

func BenchmarkSnappyDecompress(b *testing.B) {
	data := make([]byte, 10000)
	for i := range data {
		data[i] = byte(i % 256)
	}
	compressed := CompressSnappy(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecompressSnappy(compressed)
	}
}

func BenchmarkGzipCompress(b *testing.B) {
	data := make([]byte, 10000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CompressGzip(data)
	}
}

func BenchmarkGzipDecompress(b *testing.B) {
	data := make([]byte, 10000)
	for i := range data {
		data[i] = byte(i % 256)
	}
	compressed, _ := CompressGzip(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecompressGzip(compressed)
	}
}

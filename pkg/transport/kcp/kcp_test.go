package kcp

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.MTU != 1350 {
		t.Errorf("expected MTU 1350, got %d", config.MTU)
	}
	if config.SndWnd != 1024 {
		t.Errorf("expected SndWnd 1024, got %d", config.SndWnd)
	}
	if config.RcvWnd != 1024 {
		t.Errorf("expected RcvWnd 1024, got %d", config.RcvWnd)
	}
	if config.DataShard != 10 {
		t.Errorf("expected DataShard 10, got %d", config.DataShard)
	}
	if config.ParityShard != 3 {
		t.Errorf("expected ParityShard 3, got %d", config.ParityShard)
	}
	if config.NoDelay != 1 {
		t.Errorf("expected NoDelay 1, got %d", config.NoDelay)
	}
	if config.Interval != 40 {
		t.Errorf("expected Interval 40, got %d", config.Interval)
	}
	if config.Crypt != "aes" {
		t.Errorf("expected Crypt 'aes', got %s", config.Crypt)
	}
}

func TestFastConfig(t *testing.T) {
	config := FastConfig()

	if config.NoDelay != 1 {
		t.Errorf("expected NoDelay 1, got %d", config.NoDelay)
	}
	if config.Interval != 10 {
		t.Errorf("expected Interval 10, got %d", config.Interval)
	}
	if config.SndWnd != 2048 {
		t.Errorf("expected SndWnd 2048, got %d", config.SndWnd)
	}
	if config.RcvWnd != 2048 {
		t.Errorf("expected RcvWnd 2048, got %d", config.RcvWnd)
	}
}

func TestMobileConfig(t *testing.T) {
	config := MobileConfig()

	if config.DataShard != 20 {
		t.Errorf("expected DataShard 20, got %d", config.DataShard)
	}
	if config.ParityShard != 10 {
		t.Errorf("expected ParityShard 10, got %d", config.ParityShard)
	}
	if config.SndWnd != 512 {
		t.Errorf("expected SndWnd 512, got %d", config.SndWnd)
	}
}

func TestConfigValidate(t *testing.T) {
	config := &Config{}
	err := config.Validate()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Check defaults are applied
	if config.MTU != 1350 {
		t.Errorf("expected MTU 1350 after validation, got %d", config.MTU)
	}
	if config.SndWnd != 1024 {
		t.Errorf("expected SndWnd 1024 after validation, got %d", config.SndWnd)
	}
	if config.Crypt != "aes" {
		t.Errorf("expected Crypt 'aes' after validation, got %s", config.Crypt)
	}
}

func TestConfigFromMode(t *testing.T) {
	tests := []struct {
		mode     Mode
		interval int
	}{
		{ModeNormal, 40},
		{ModeFast, 10},
		{ModeMobile, 20},
	}

	for _, tt := range tests {
		config := ConfigFromMode(tt.mode)
		if config.Interval != tt.interval {
			t.Errorf("mode %s: expected Interval %d, got %d", tt.mode, tt.interval, config.Interval)
		}
	}
}

func TestGetBlockCrypt(t *testing.T) {
	tests := []struct {
		crypt string
		key   string
		isNil bool
	}{
		{"none", "", true},
		{"aes", "", true},
		{"aes", "testkey", false},
		{"aes-128", "testkey", false},
		{"aes-192", "testkey", false},
		{"aes-256", "testkey", false},
		{"salsa20", "testkey", false},
		{"blowfish", "testkey", false},
		{"twofish", "testkey", false},
		{"cast5", "testkey", false},
		{"3des", "testkey", false},
		{"tea", "testkey", false},
		{"xtea", "testkey", false},
		{"xor", "testkey", false},
		{"sm4", "testkey", false},
	}

	for _, tt := range tests {
		config := &Config{
			Crypt: tt.crypt,
			Key:   tt.key,
		}
		block, err := config.GetBlockCrypt()
		if err != nil {
			t.Errorf("crypt %s: unexpected error: %v", tt.crypt, err)
			continue
		}
		if tt.isNil && block != nil {
			t.Errorf("crypt %s: expected nil block, got non-nil", tt.crypt)
		}
		if !tt.isNil && block == nil {
			t.Errorf("crypt %s: expected non-nil block, got nil", tt.crypt)
		}
	}
}

func TestNewTransport(t *testing.T) {
	// Test with nil config
	transport, err := NewTransport(nil)
	if err != nil {
		t.Errorf("unexpected error with nil config: %v", err)
	}
	if transport == nil {
		t.Error("expected non-nil transport")
	}

	// Test with custom config
	config := FastConfig()
	config.Key = "testkey"
	transport, err = NewTransport(config)
	if err != nil {
		t.Errorf("unexpected error with custom config: %v", err)
	}
	if transport == nil {
		t.Error("expected non-nil transport")
	}
}

func TestTransportDialPacketNotSupported(t *testing.T) {
	transport, _ := NewTransport(nil)
	_, err := transport.DialPacket(context.Background(), "127.0.0.1:12345")
	if err == nil {
		t.Error("expected error for DialPacket")
	}
}

func TestTransportListenPacketNotSupported(t *testing.T) {
	transport, _ := NewTransport(nil)
	_, err := transport.ListenPacket(context.Background(), "127.0.0.1:12345")
	if err == nil {
		t.Error("expected error for ListenPacket")
	}
}

// Integration test for KCP transport
func TestKCPTransportIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	config := DefaultConfig()
	config.Key = "test-key-12345"
	config.Crypt = "aes"
	config.DataShard = 0  // Disable FEC for faster test
	config.ParityShard = 0

	// Create server
	server, err := NewServer("127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Close()

	serverAddr := server.Addr().String()
	t.Logf("Server listening on %s", serverAddr)

	// Create client transport
	clientTransport, err := NewTransport(config)
	if err != nil {
		t.Fatalf("failed to create client transport: %v", err)
	}

	// Test data
	testData := []byte("Hello, KCP!")
	responseData := []byte("Hello from server!")

	var wg sync.WaitGroup
	wg.Add(2)

	// Server goroutine
	go func() {
		defer wg.Done()
		conn, err := server.Accept()
		if err != nil {
			t.Errorf("server accept error: %v", err)
			return
		}
		defer conn.Close()

		// Read from client
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			t.Errorf("server read error: %v", err)
			return
		}

		if string(buf[:n]) != string(testData) {
			t.Errorf("server received unexpected data: %s", string(buf[:n]))
		}

		// Write response
		_, err = conn.Write(responseData)
		if err != nil {
			t.Errorf("server write error: %v", err)
		}
	}()

	// Client goroutine
	go func() {
		defer wg.Done()
		time.Sleep(100 * time.Millisecond) // Wait for server to be ready

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, err := clientTransport.Dial(ctx, serverAddr)
		if err != nil {
			t.Errorf("client dial error: %v", err)
			return
		}
		defer conn.Close()

		// Write to server
		_, err = conn.Write(testData)
		if err != nil {
			t.Errorf("client write error: %v", err)
			return
		}

		// Read response
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			t.Errorf("client read error: %v", err)
			return
		}

		if string(buf[:n]) != string(responseData) {
			t.Errorf("client received unexpected data: %s", string(buf[:n]))
		}
	}()

	wg.Wait()
}

// Test KCP with compression
func TestKCPWithCompression(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	config := DefaultConfig()
	config.Key = "test-key-compress"
	config.Compression = true
	config.DataShard = 0
	config.ParityShard = 0

	server, err := NewServer("127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Close()

	serverAddr := server.Addr().String()

	clientTransport, err := NewTransport(config)
	if err != nil {
		t.Fatalf("failed to create client transport: %v", err)
	}

	// Large test data to benefit from compression
	testData := make([]byte, 10000)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		conn, err := server.Accept()
		if err != nil {
			t.Errorf("server accept error: %v", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, len(testData))
		n, err := io.ReadFull(conn, buf)
		if err != nil {
			t.Errorf("server read error: %v", err)
			return
		}

		if n != len(testData) {
			t.Errorf("server received %d bytes, expected %d", n, len(testData))
		}

		_, err = conn.Write([]byte("OK"))
		if err != nil {
			t.Errorf("server write error: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		time.Sleep(100 * time.Millisecond)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, err := clientTransport.Dial(ctx, serverAddr)
		if err != nil {
			t.Errorf("client dial error: %v", err)
			return
		}
		defer conn.Close()

		_, err = conn.Write(testData)
		if err != nil {
			t.Errorf("client write error: %v", err)
			return
		}

		buf := make([]byte, 10)
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			t.Errorf("client read error: %v", err)
			return
		}

		if string(buf[:n]) != "OK" {
			t.Errorf("client received unexpected response: %s", string(buf[:n]))
		}
	}()

	wg.Wait()
}

// Benchmark KCP throughput
func BenchmarkKCPThroughput(b *testing.B) {
	config := DefaultConfig()
	config.Key = "bench-key"
	config.DataShard = 0
	config.ParityShard = 0

	server, err := NewServer("127.0.0.1:0", config)
	if err != nil {
		b.Fatalf("failed to create server: %v", err)
	}
	defer server.Close()

	serverAddr := server.Addr().String()

	clientTransport, err := NewTransport(config)
	if err != nil {
		b.Fatalf("failed to create client transport: %v", err)
	}

	// Server echo goroutine
	go func() {
		for {
			conn, err := server.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	ctx := context.Background()
	conn, err := clientTransport.Dial(ctx, serverAddr)
	if err != nil {
		b.Fatalf("client dial error: %v", err)
	}
	defer conn.Close()

	data := make([]byte, 1024)
	buf := make([]byte, 1024)

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		_, err := conn.Write(data)
		if err != nil {
			b.Fatalf("write error: %v", err)
		}
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			b.Fatalf("read error: %v", err)
		}
	}
}

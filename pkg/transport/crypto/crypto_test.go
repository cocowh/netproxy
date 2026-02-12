package crypto

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	tests := []struct {
		name   string
		keyLen int
	}{
		{"AES-128", AES128KeySize},
		{"AES-256", AES256KeySize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateKey(tt.keyLen)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}
			if len(key) != tt.keyLen {
				t.Errorf("key length mismatch: got %d, want %d", len(key), tt.keyLen)
			}
		})
	}
}

func TestDeriveKey(t *testing.T) {
	password := "test-password-123"
	salt := []byte("test-salt")

	key1 := DeriveKey(password, salt, AES256KeySize)
	key2 := DeriveKey(password, salt, AES256KeySize)

	if !bytes.Equal(key1, key2) {
		t.Error("derived keys should be identical for same password and salt")
	}

	key3 := DeriveKey(password, []byte("different-salt"), AES256KeySize)
	if bytes.Equal(key1, key3) {
		t.Error("derived keys should be different for different salts")
	}

	key4 := DeriveKey("different-password", salt, AES256KeySize)
	if bytes.Equal(key1, key4) {
		t.Error("derived keys should be different for different passwords")
	}
}

func TestAESGCMConnWriteRead(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	key, err := GenerateAES256Key()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	serverConn, err := NewAESGCMConn(server, key)
	if err != nil {
		t.Fatalf("failed to create server conn: %v", err)
	}

	clientConn, err := NewAESGCMConn(client, key)
	if err != nil {
		t.Fatalf("failed to create client conn: %v", err)
	}

	testData := []byte("Hello, AES-GCM!")

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

func TestAESGCMConnLargeData(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	key, _ := GenerateAES256Key()

	serverConn, _ := NewAESGCMConn(server, key)
	clientConn, _ := NewAESGCMConn(client, key)

	// Test with data larger than MaxPayloadSize
	testData := make([]byte, MaxPayloadSize*2+1000)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := clientConn.Write(testData)
		if err != nil {
			t.Errorf("write error: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, len(testData))
		total := 0
		for total < len(testData) {
			n, err := serverConn.Read(buf[total:])
			if err != nil && err != io.EOF {
				t.Errorf("read error: %v", err)
				return
			}
			total += n
			if err == io.EOF {
				break
			}
		}
		if !bytes.Equal(buf[:total], testData) {
			t.Error("data mismatch for large data")
		}
	}()

	wg.Wait()
}

func TestAESCFBConnWriteRead(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	key, _ := GenerateAES256Key()

	serverConn, err := NewAESCFBConn(server, key)
	if err != nil {
		t.Fatalf("failed to create server conn: %v", err)
	}

	clientConn, err := NewAESCFBConn(client, key)
	if err != nil {
		t.Fatalf("failed to create client conn: %v", err)
	}

	testData := []byte("Hello, AES-CFB!")

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := clientConn.Write(testData)
		if err != nil {
			t.Errorf("write error: %v", err)
		}
	}()

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

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{"valid-none", &Config{Type: TypeNone}, false},
		{"valid-aes-gcm-key", &Config{Type: TypeAESGCM, Key: make([]byte, 32)}, false},
		{"valid-aes-gcm-password", &Config{Type: TypeAESGCM, Password: "test"}, false},
		{"invalid-type", &Config{Type: "invalid"}, true},
		{"missing-key-and-password", &Config{Type: TypeAESGCM}, true},
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

func TestEncryptorInterface(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
	}{
		{"none", &Config{Type: TypeNone}},
		{"aes-gcm", &Config{Type: TypeAESGCM, Password: "test-password"}},
		{"aes-256-gcm", &Config{Type: TypeAES256GCM, Password: "test-password"}},
		{"aes-128-gcm", &Config{Type: TypeAES128GCM, Password: "test-password"}},
		{"aes-cfb", &Config{Type: TypeAESCFB, Password: "test-password"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encryptor, err := NewEncryptor(tt.config)
			if err != nil {
				t.Fatalf("failed to create encryptor: %v", err)
			}

			if tt.config.Type == TypeNone {
				if encryptor.Type() != TypeNone {
					t.Errorf("type mismatch: got %s, want %s", encryptor.Type(), TypeNone)
				}
				return
			}

			// Test with pipe
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()

			serverConn, err := encryptor.WrapConn(server)
			if err != nil {
				t.Fatalf("failed to wrap server conn: %v", err)
			}

			clientConn, err := encryptor.WrapConn(client)
			if err != nil {
				t.Fatalf("failed to wrap client conn: %v", err)
			}

			testData := []byte("Test encryptor interface")

			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				clientConn.Write(testData)
			}()

			go func() {
				defer wg.Done()
				buf := make([]byte, 1024)
				n, _ := serverConn.Read(buf)
				if !bytes.Equal(buf[:n], testData) {
					t.Errorf("data mismatch")
				}
			}()

			wg.Wait()
		})
	}
}

func TestWrapConnConvenience(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	password := "test-password"

	serverConn, err := WrapConn(server, TypeAESGCM, password)
	if err != nil {
		t.Fatalf("failed to wrap server conn: %v", err)
	}

	clientConn, err := WrapConn(client, TypeAESGCM, password)
	if err != nil {
		t.Fatalf("failed to wrap client conn: %v", err)
	}

	testData := []byte("Test WrapConn")

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		clientConn.Write(testData)
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		n, _ := serverConn.Read(buf)
		if !bytes.Equal(buf[:n], testData) {
			t.Errorf("data mismatch")
		}
	}()

	wg.Wait()
}

func TestInvalidKeySize(t *testing.T) {
	server, _ := net.Pipe()
	defer server.Close()

	// Test invalid key sizes
	invalidKeys := [][]byte{
		make([]byte, 15), // Too short
		make([]byte, 17), // Invalid size
		make([]byte, 33), // Too long
	}

	for _, key := range invalidKeys {
		_, err := NewAESGCMConn(server, key)
		if err == nil {
			t.Errorf("expected error for key size %d", len(key))
		}
	}
}

func TestIncrementNonce(t *testing.T) {
	tests := []struct {
		input    []byte
		expected []byte
	}{
		{[]byte{0, 0, 0}, []byte{0, 0, 1}},
		{[]byte{0, 0, 255}, []byte{0, 1, 0}},
		{[]byte{0, 255, 255}, []byte{1, 0, 0}},
		{[]byte{255, 255, 255}, []byte{0, 0, 0}}, // Overflow
	}

	for _, tt := range tests {
		nonce := make([]byte, len(tt.input))
		copy(nonce, tt.input)
		incrementNonce(nonce)
		if !bytes.Equal(nonce, tt.expected) {
			t.Errorf("incrementNonce(%v) = %v, want %v", tt.input, nonce, tt.expected)
		}
	}
}

// Benchmark tests
func BenchmarkAESGCMWrite(b *testing.B) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	key, _ := GenerateAES256Key()
	clientConn, _ := NewAESGCMConn(client, key)

	// Drain server side
	go func() {
		buf := make([]byte, 32*1024)
		for {
			_, err := server.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	data := make([]byte, 1024)

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		clientConn.Write(data)
	}
}

func BenchmarkAESCFBWrite(b *testing.B) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	key, _ := GenerateAES256Key()
	clientConn, _ := NewAESCFBConn(client, key)

	// Drain server side
	go func() {
		buf := make([]byte, 32*1024)
		for {
			_, err := server.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	data := make([]byte, 1024)

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		clientConn.Write(data)
	}
}

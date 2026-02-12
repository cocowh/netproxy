// Package wireguard provides WireGuard protocol implementation.
// This package implements the Noise protocol framework used by WireGuard.
package wireguard

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	// NoiseConstruction is the protocol name
	NoiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"

	// WGIdentifier is the WireGuard identifier
	WGIdentifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"

	// WGLabelMAC1 is the label for MAC1
	WGLabelMAC1 = "mac1----"

	// WGLabelCookie is the label for cookie
	WGLabelCookie = "cookie--"

	// KeySize is the size of a key in bytes
	KeySize = 32

	// NonceSize is the size of a nonce in bytes
	NonceSize = 12

	// TagSize is the size of an AEAD tag in bytes
	TagSize = 16

	// TimestampSize is the size of a TAI64N timestamp
	TimestampSize = 12

	// MessageInitiationSize is the size of a handshake initiation message
	MessageInitiationSize = 148

	// MessageResponseSize is the size of a handshake response message
	MessageResponseSize = 92

	// MessageCookieReplySize is the size of a cookie reply message
	MessageCookieReplySize = 64

	// MessageTransportHeaderSize is the size of a transport message header
	MessageTransportHeaderSize = 16

	// MessageTransportSize is the maximum size of a transport message
	MessageTransportSize = MessageTransportHeaderSize + 65535 + TagSize
)

// Message types
const (
	MessageTypeInitiation  = 1
	MessageTypeResponse    = 2
	MessageTypeCookieReply = 3
	MessageTypeTransport   = 4
)

var (
	// ErrInvalidKey is returned when a key is invalid
	ErrInvalidKey = errors.New("invalid key")

	// ErrInvalidMessage is returned when a message is invalid
	ErrInvalidMessage = errors.New("invalid message")

	// ErrDecryptionFailed is returned when decryption fails
	ErrDecryptionFailed = errors.New("decryption failed")

	// ErrReplayAttack is returned when a replay attack is detected
	ErrReplayAttack = errors.New("replay attack detected")

	// ErrHandshakeTimeout is returned when handshake times out
	ErrHandshakeTimeout = errors.New("handshake timeout")
)

// KeyPair represents a Curve25519 key pair.
type KeyPair struct {
	PrivateKey [KeySize]byte
	PublicKey  [KeySize]byte
}

// GenerateKeyPair generates a new Curve25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	var kp KeyPair

	_, err := io.ReadFull(rand.Reader, kp.PrivateKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Clamp the private key
	kp.PrivateKey[0] &= 248
	kp.PrivateKey[31] &= 127
	kp.PrivateKey[31] |= 64

	// Derive public key
	curve25519.ScalarBaseMult(&kp.PublicKey, &kp.PrivateKey)

	return &kp, nil
}

// NewKeyPairFromPrivate creates a key pair from a private key.
func NewKeyPairFromPrivate(privateKey [KeySize]byte) *KeyPair {
	kp := &KeyPair{
		PrivateKey: privateKey,
	}

	// Clamp the private key
	kp.PrivateKey[0] &= 248
	kp.PrivateKey[31] &= 127
	kp.PrivateKey[31] |= 64

	// Derive public key
	curve25519.ScalarBaseMult(&kp.PublicKey, &kp.PrivateKey)

	return kp
}

// SharedSecret computes the shared secret with another public key.
func (kp *KeyPair) SharedSecret(peerPublicKey [KeySize]byte) ([KeySize]byte, error) {
	var shared [KeySize]byte
	curve25519.ScalarMult(&shared, &kp.PrivateKey, &peerPublicKey)

	// Check for low-order points
	var zero [KeySize]byte
	if shared == zero {
		return zero, ErrInvalidKey
	}

	return shared, nil
}

// NoiseHandshake represents the state of a Noise handshake.
type NoiseHandshake struct {
	mu sync.Mutex

	// Static keys
	localStatic  *KeyPair
	remoteStatic [KeySize]byte

	// Ephemeral keys
	localEphemeral  *KeyPair
	remoteEphemeral [KeySize]byte

	// Pre-shared key
	presharedKey [KeySize]byte

	// Handshake hash
	hash [KeySize]byte

	// Chaining key
	chainKey [KeySize]byte

	// Sender/Receiver indices
	localIndex  uint32
	remoteIndex uint32

	// Timestamps
	lastTimestamp [TimestampSize]byte
	lastInitTime  time.Time

	// State
	state int
}

// Handshake states
const (
	handshakeStateInitSent = iota
	handshakeStateInitReceived
	handshakeStateComplete
)

// NewNoiseHandshake creates a new Noise handshake.
func NewNoiseHandshake(localStatic *KeyPair, remoteStatic [KeySize]byte, psk [KeySize]byte) *NoiseHandshake {
	hs := &NoiseHandshake{
		localStatic:  localStatic,
		remoteStatic: remoteStatic,
		presharedKey: psk,
	}

	// Initialize hash with construction
	hs.hash = blake2sHash([]byte(NoiseConstruction))

	// Mix in identifier
	hs.hash = blake2sHash(append(hs.hash[:], []byte(WGIdentifier)...))

	// Mix in responder's public key
	hs.hash = blake2sHash(append(hs.hash[:], remoteStatic[:]...))

	// Initialize chaining key
	hs.chainKey = blake2sHash([]byte(NoiseConstruction))

	return hs
}

// CreateInitiation creates a handshake initiation message.
func (hs *NoiseHandshake) CreateInitiation() ([]byte, error) {
	hs.mu.Lock()
	defer hs.mu.Unlock()

	// Generate ephemeral key pair
	var err error
	hs.localEphemeral, err = GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	// Generate local index
	var indexBuf [4]byte
	if _, err := io.ReadFull(rand.Reader, indexBuf[:]); err != nil {
		return nil, err
	}
	hs.localIndex = binary.LittleEndian.Uint32(indexBuf[:])

	msg := make([]byte, MessageInitiationSize)

	// Message type
	msg[0] = MessageTypeInitiation
	msg[1] = 0
	msg[2] = 0
	msg[3] = 0

	// Sender index
	binary.LittleEndian.PutUint32(msg[4:8], hs.localIndex)

	// Ephemeral public key (unencrypted)
	copy(msg[8:40], hs.localEphemeral.PublicKey[:])

	// Mix ephemeral into hash
	hs.hash = blake2sHash(append(hs.hash[:], hs.localEphemeral.PublicKey[:]...))

	// DH: ephemeral -> remote static
	ss, err := hs.localEphemeral.SharedSecret(hs.remoteStatic)
	if err != nil {
		return nil, err
	}

	// KDF
	hs.chainKey, _ = hkdf2(hs.chainKey[:], ss[:])

	// Encrypt static public key
	key := hkdf1(hs.chainKey[:], nil)
	aead, _ := chacha20poly1305.New(key[:])
	nonce := make([]byte, NonceSize)
	encrypted := aead.Seal(nil, nonce, hs.localStatic.PublicKey[:], hs.hash[:])
	copy(msg[40:88], encrypted)

	// Mix encrypted static into hash
	hs.hash = blake2sHash(append(hs.hash[:], encrypted...))

	// DH: static -> remote static
	ss, err = hs.localStatic.SharedSecret(hs.remoteStatic)
	if err != nil {
		return nil, err
	}

	// KDF
	hs.chainKey, _ = hkdf2(hs.chainKey[:], ss[:])

	// Create timestamp
	timestamp := tai64nNow()
	copy(hs.lastTimestamp[:], timestamp[:])

	// Encrypt timestamp
	key = hkdf1(hs.chainKey[:], nil)
	aead, _ = chacha20poly1305.New(key[:])
	encrypted = aead.Seal(nil, nonce, timestamp[:], hs.hash[:])
	copy(msg[88:116], encrypted)

	// Mix encrypted timestamp into hash
	hs.hash = blake2sHash(append(hs.hash[:], encrypted...))

	// MAC1
	mac1Key := blake2sHash(append([]byte(WGLabelMAC1), hs.remoteStatic[:]...))
	mac1 := blake2sMAC(mac1Key[:], msg[:116])
	copy(msg[116:132], mac1[:16])

	// MAC2 (zeros for now, would need cookie)
	// msg[132:148] is already zeros

	hs.state = handshakeStateInitSent
	hs.lastInitTime = time.Now()

	return msg, nil
}

// ConsumeInitiation processes a handshake initiation message.
func (hs *NoiseHandshake) ConsumeInitiation(msg []byte) error {
	hs.mu.Lock()
	defer hs.mu.Unlock()

	if len(msg) != MessageInitiationSize {
		return ErrInvalidMessage
	}

	if msg[0] != MessageTypeInitiation {
		return ErrInvalidMessage
	}

	// Verify MAC1
	mac1Key := blake2sHash(append([]byte(WGLabelMAC1), hs.localStatic.PublicKey[:]...))
	expectedMAC1 := blake2sMAC(mac1Key[:], msg[:116])
	if !constantTimeCompare(msg[116:132], expectedMAC1[:16]) {
		return ErrInvalidMessage
	}

	// Extract sender index
	hs.remoteIndex = binary.LittleEndian.Uint32(msg[4:8])

	// Extract ephemeral public key
	copy(hs.remoteEphemeral[:], msg[8:40])

	// Mix ephemeral into hash
	hs.hash = blake2sHash(append(hs.hash[:], hs.remoteEphemeral[:]...))

	// DH: local static -> remote ephemeral
	ss, err := hs.localStatic.SharedSecret(hs.remoteEphemeral)
	if err != nil {
		return err
	}

	// KDF
	hs.chainKey, _ = hkdf2(hs.chainKey[:], ss[:])

	// Decrypt static public key
	key := hkdf1(hs.chainKey[:], nil)
	aead, _ := chacha20poly1305.New(key[:])
	nonce := make([]byte, NonceSize)
	decrypted, err := aead.Open(nil, nonce, msg[40:88], hs.hash[:])
	if err != nil {
		return ErrDecryptionFailed
	}

	var peerStatic [KeySize]byte
	copy(peerStatic[:], decrypted)

	// Verify peer static matches expected
	if peerStatic != hs.remoteStatic {
		return ErrInvalidKey
	}

	// Mix encrypted static into hash
	hs.hash = blake2sHash(append(hs.hash[:], msg[40:88]...))

	// DH: local static -> peer static
	ss, err = hs.localStatic.SharedSecret(peerStatic)
	if err != nil {
		return err
	}

	// KDF
	hs.chainKey, _ = hkdf2(hs.chainKey[:], ss[:])

	// Decrypt timestamp
	key = hkdf1(hs.chainKey[:], nil)
	aead, _ = chacha20poly1305.New(key[:])
	decrypted, err = aead.Open(nil, nonce, msg[88:116], hs.hash[:])
	if err != nil {
		return ErrDecryptionFailed
	}

	// Verify timestamp is newer
	var timestamp [TimestampSize]byte
	copy(timestamp[:], decrypted)
	if !isNewerTimestamp(timestamp, hs.lastTimestamp) {
		return ErrReplayAttack
	}
	hs.lastTimestamp = timestamp

	// Mix encrypted timestamp into hash
	hs.hash = blake2sHash(append(hs.hash[:], msg[88:116]...))

	hs.state = handshakeStateInitReceived

	return nil
}

// CreateResponse creates a handshake response message.
func (hs *NoiseHandshake) CreateResponse() ([]byte, error) {
	hs.mu.Lock()
	defer hs.mu.Unlock()

	if hs.state != handshakeStateInitReceived {
		return nil, errors.New("invalid handshake state")
	}

	// Generate ephemeral key pair
	var err error
	hs.localEphemeral, err = GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	// Generate local index
	var indexBuf [4]byte
	if _, err := io.ReadFull(rand.Reader, indexBuf[:]); err != nil {
		return nil, err
	}
	hs.localIndex = binary.LittleEndian.Uint32(indexBuf[:])

	msg := make([]byte, MessageResponseSize)

	// Message type
	msg[0] = MessageTypeResponse
	msg[1] = 0
	msg[2] = 0
	msg[3] = 0

	// Sender index
	binary.LittleEndian.PutUint32(msg[4:8], hs.localIndex)

	// Receiver index
	binary.LittleEndian.PutUint32(msg[8:12], hs.remoteIndex)

	// Ephemeral public key
	copy(msg[12:44], hs.localEphemeral.PublicKey[:])

	// Mix ephemeral into hash
	hs.hash = blake2sHash(append(hs.hash[:], hs.localEphemeral.PublicKey[:]...))

	// DH: ephemeral -> remote ephemeral
	ss, err := hs.localEphemeral.SharedSecret(hs.remoteEphemeral)
	if err != nil {
		return nil, err
	}
	hs.chainKey, _ = hkdf2(hs.chainKey[:], ss[:])

	// DH: ephemeral -> remote static
	ss, err = hs.localEphemeral.SharedSecret(hs.remoteStatic)
	if err != nil {
		return nil, err
	}
	hs.chainKey, _ = hkdf2(hs.chainKey[:], ss[:])

	// Mix in preshared key
	var temp [KeySize]byte
	hs.chainKey, temp = hkdf2(hs.chainKey[:], hs.presharedKey[:])
	hs.hash = blake2sHash(append(hs.hash[:], temp[:]...))

	// Encrypt empty
	key := hkdf1(hs.chainKey[:], nil)
	aead, _ := chacha20poly1305.New(key[:])
	nonce := make([]byte, NonceSize)
	encrypted := aead.Seal(nil, nonce, nil, hs.hash[:])
	copy(msg[44:60], encrypted)

	// Mix encrypted empty into hash
	hs.hash = blake2sHash(append(hs.hash[:], encrypted...))

	// MAC1
	mac1Key := blake2sHash(append([]byte(WGLabelMAC1), hs.remoteStatic[:]...))
	mac1 := blake2sMAC(mac1Key[:], msg[:60])
	copy(msg[60:76], mac1[:16])

	// MAC2 (zeros)
	// msg[76:92] is already zeros

	hs.state = handshakeStateComplete

	return msg, nil
}

// ConsumeResponse processes a handshake response message.
func (hs *NoiseHandshake) ConsumeResponse(msg []byte) error {
	hs.mu.Lock()
	defer hs.mu.Unlock()

	if len(msg) != MessageResponseSize {
		return ErrInvalidMessage
	}

	if msg[0] != MessageTypeResponse {
		return ErrInvalidMessage
	}

	if hs.state != handshakeStateInitSent {
		return errors.New("invalid handshake state")
	}

	// Verify receiver index matches our sender index
	receiverIndex := binary.LittleEndian.Uint32(msg[8:12])
	if receiverIndex != hs.localIndex {
		return ErrInvalidMessage
	}

	// Verify MAC1
	mac1Key := blake2sHash(append([]byte(WGLabelMAC1), hs.localStatic.PublicKey[:]...))
	expectedMAC1 := blake2sMAC(mac1Key[:], msg[:60])
	if !constantTimeCompare(msg[60:76], expectedMAC1[:16]) {
		return ErrInvalidMessage
	}

	// Extract sender index
	hs.remoteIndex = binary.LittleEndian.Uint32(msg[4:8])

	// Extract ephemeral public key
	copy(hs.remoteEphemeral[:], msg[12:44])

	// Mix ephemeral into hash
	hs.hash = blake2sHash(append(hs.hash[:], hs.remoteEphemeral[:]...))

	// DH: local ephemeral -> remote ephemeral
	ss, err := hs.localEphemeral.SharedSecret(hs.remoteEphemeral)
	if err != nil {
		return err
	}
	hs.chainKey, _ = hkdf2(hs.chainKey[:], ss[:])

	// DH: local static -> remote ephemeral
	ss, err = hs.localStatic.SharedSecret(hs.remoteEphemeral)
	if err != nil {
		return err
	}
	hs.chainKey, _ = hkdf2(hs.chainKey[:], ss[:])

	// Mix in preshared key
	var temp [KeySize]byte
	hs.chainKey, temp = hkdf2(hs.chainKey[:], hs.presharedKey[:])
	hs.hash = blake2sHash(append(hs.hash[:], temp[:]...))

	// Decrypt empty
	key := hkdf1(hs.chainKey[:], nil)
	aead, _ := chacha20poly1305.New(key[:])
	nonce := make([]byte, NonceSize)
	_, err = aead.Open(nil, nonce, msg[44:60], hs.hash[:])
	if err != nil {
		return ErrDecryptionFailed
	}

	// Mix encrypted empty into hash
	hs.hash = blake2sHash(append(hs.hash[:], msg[44:60]...))

	hs.state = handshakeStateComplete

	return nil
}

// DeriveKeys derives the transport keys after handshake completion.
func (hs *NoiseHandshake) DeriveKeys() (sendKey, recvKey [KeySize]byte, err error) {
	hs.mu.Lock()
	defer hs.mu.Unlock()

	if hs.state != handshakeStateComplete {
		return sendKey, recvKey, errors.New("handshake not complete")
	}

	// Derive transport keys
	sendKey, recvKey = hkdf2(hs.chainKey[:], nil)

	return sendKey, recvKey, nil
}

// GetIndices returns the local and remote indices.
func (hs *NoiseHandshake) GetIndices() (local, remote uint32) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	return hs.localIndex, hs.remoteIndex
}

// TransportCipher handles encryption/decryption of transport messages.
type TransportCipher struct {
	sendKey   [KeySize]byte
	recvKey   [KeySize]byte
	sendNonce uint64
	recvNonce uint64
	sendAEAD  cipher.AEAD
	recvAEAD  cipher.AEAD
	mu        sync.Mutex
}

// NewTransportCipher creates a new transport cipher.
func NewTransportCipher(sendKey, recvKey [KeySize]byte) (*TransportCipher, error) {
	sendAEAD, err := chacha20poly1305.New(sendKey[:])
	if err != nil {
		return nil, err
	}

	recvAEAD, err := chacha20poly1305.New(recvKey[:])
	if err != nil {
		return nil, err
	}

	return &TransportCipher{
		sendKey:  sendKey,
		recvKey:  recvKey,
		sendAEAD: sendAEAD,
		recvAEAD: recvAEAD,
	}, nil
}

// Encrypt encrypts a message for transport.
func (tc *TransportCipher) Encrypt(plaintext []byte, receiverIndex uint32) []byte {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Build message
	msg := make([]byte, MessageTransportHeaderSize+len(plaintext)+TagSize)

	// Message type
	msg[0] = MessageTypeTransport
	msg[1] = 0
	msg[2] = 0
	msg[3] = 0

	// Receiver index
	binary.LittleEndian.PutUint32(msg[4:8], receiverIndex)

	// Counter
	binary.LittleEndian.PutUint64(msg[8:16], tc.sendNonce)

	// Encrypt
	nonce := make([]byte, NonceSize)
	binary.LittleEndian.PutUint64(nonce[4:], tc.sendNonce)
	tc.sendAEAD.Seal(msg[16:16], nonce, plaintext, nil)

	tc.sendNonce++

	return msg
}

// Decrypt decrypts a transport message.
func (tc *TransportCipher) Decrypt(msg []byte) ([]byte, error) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if len(msg) < MessageTransportHeaderSize+TagSize {
		return nil, ErrInvalidMessage
	}

	if msg[0] != MessageTypeTransport {
		return nil, ErrInvalidMessage
	}

	// Extract counter
	counter := binary.LittleEndian.Uint64(msg[8:16])

	// Check for replay
	if counter <= tc.recvNonce && tc.recvNonce > 0 {
		return nil, ErrReplayAttack
	}

	// Decrypt
	nonce := make([]byte, NonceSize)
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	plaintext, err := tc.recvAEAD.Open(nil, nonce, msg[16:], nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	tc.recvNonce = counter

	return plaintext, nil
}

// Helper functions

func blake2sHash(data []byte) [KeySize]byte {
	return blake2s.Sum256(data)
}

func blake2sMAC(key, data []byte) [KeySize]byte {
	h, _ := blake2s.New256(key)
	h.Write(data)
	var result [KeySize]byte
	copy(result[:], h.Sum(nil))
	return result
}

func hkdf1(key, input []byte) [KeySize]byte {
	h, _ := blake2s.New256(key)
	h.Write(input)
	h.Write([]byte{0x01})
	var result [KeySize]byte
	copy(result[:], h.Sum(nil))
	return result
}

func hkdf2(key, input []byte) ([KeySize]byte, [KeySize]byte) {
	// HKDF-Extract
	h, _ := blake2s.New256(key)
	h.Write(input)
	prk := h.Sum(nil)

	// HKDF-Expand for first output
	h, _ = blake2s.New256(prk)
	h.Write([]byte{0x01})
	var out1 [KeySize]byte
	copy(out1[:], h.Sum(nil))

	// HKDF-Expand for second output
	h, _ = blake2s.New256(prk)
	h.Write(out1[:])
	h.Write([]byte{0x02})
	var out2 [KeySize]byte
	copy(out2[:], h.Sum(nil))

	return out1, out2
}

func tai64nNow() [TimestampSize]byte {
	now := time.Now()
	var timestamp [TimestampSize]byte

	// TAI64N: 8 bytes seconds + 4 bytes nanoseconds
	secs := uint64(now.Unix()) + 4611686018427387914 // TAI offset
	binary.BigEndian.PutUint64(timestamp[:8], secs)
	binary.BigEndian.PutUint32(timestamp[8:], uint32(now.Nanosecond()))

	return timestamp
}

func isNewerTimestamp(a, b [TimestampSize]byte) bool {
	for i := 0; i < TimestampSize; i++ {
		if a[i] > b[i] {
			return true
		}
		if a[i] < b[i] {
			return false
		}
	}
	return false
}

func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// HMAC implements HMAC using BLAKE2s
type HMAC struct {
	outer hash.Hash
	inner hash.Hash
	ipad  [64]byte
	opad  [64]byte
}

// NewHMAC creates a new HMAC using BLAKE2s
func NewHMAC(key []byte) *HMAC {
	h := &HMAC{}

	// If key is longer than block size, hash it
	if len(key) > 64 {
		sum := blake2s.Sum256(key)
		key = sum[:]
	}

	// Pad key
	copy(h.ipad[:], key)
	copy(h.opad[:], key)

	for i := 0; i < 64; i++ {
		h.ipad[i] ^= 0x36
		h.opad[i] ^= 0x5c
	}

	h.inner, _ = blake2s.New256(nil)
	h.outer, _ = blake2s.New256(nil)

	h.inner.Write(h.ipad[:])

	return h
}

// Write writes data to the HMAC
func (h *HMAC) Write(p []byte) (n int, err error) {
	return h.inner.Write(p)
}

// Sum returns the HMAC sum
func (h *HMAC) Sum(b []byte) []byte {
	innerSum := h.inner.Sum(nil)
	h.outer.Write(h.opad[:])
	h.outer.Write(innerSum)
	return h.outer.Sum(b)
}

// Reset resets the HMAC
func (h *HMAC) Reset() {
	h.inner.Reset()
	h.outer.Reset()
	h.inner.Write(h.ipad[:])
}

// Size returns the size of the HMAC output
func (h *HMAC) Size() int {
	return h.inner.Size()
}

// BlockSize returns the block size
func (h *HMAC) BlockSize() int {
	return h.inner.BlockSize()
}

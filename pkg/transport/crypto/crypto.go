package crypto

import (
	"fmt"
	"net"
)

// Type represents the encryption algorithm type.
type Type string

const (
	// TypeNone means no encryption.
	TypeNone Type = "none"
	// TypeAESGCM uses AES-GCM authenticated encryption (recommended).
	TypeAESGCM Type = "aes-gcm"
	// TypeAES256GCM uses AES-256-GCM authenticated encryption.
	TypeAES256GCM Type = "aes-256-gcm"
	// TypeAES128GCM uses AES-128-GCM authenticated encryption.
	TypeAES128GCM Type = "aes-128-gcm"
	// TypeAESCFB uses AES-CFB stream encryption (legacy).
	TypeAESCFB Type = "aes-cfb"
	// TypeAES256CFB uses AES-256-CFB stream encryption (legacy).
	TypeAES256CFB Type = "aes-256-cfb"
)

// Config holds encryption configuration.
type Config struct {
	// Type is the encryption algorithm to use.
	Type Type `json:"type" yaml:"type"`

	// Key is the encryption key (raw bytes).
	// If empty, Password will be used to derive a key.
	Key []byte `json:"-" yaml:"-"`

	// Password is used to derive the encryption key if Key is not set.
	Password string `json:"password" yaml:"password"`

	// Salt is used for key derivation (optional).
	Salt []byte `json:"salt" yaml:"salt"`
}

// DefaultConfig returns a default encryption configuration.
func DefaultConfig() *Config {
	return &Config{
		Type: TypeAES256GCM,
	}
}

// Validate validates the encryption configuration.
func (c *Config) Validate() error {
	switch c.Type {
	case TypeNone:
		return nil
	case TypeAESGCM, TypeAES256GCM, TypeAES128GCM, TypeAESCFB, TypeAES256CFB:
		if len(c.Key) == 0 && c.Password == "" {
			return fmt.Errorf("either key or password must be provided")
		}
	default:
		return fmt.Errorf("unsupported encryption type: %s", c.Type)
	}
	return nil
}

// GetKey returns the encryption key, deriving it from password if necessary.
func (c *Config) GetKey() ([]byte, error) {
	if len(c.Key) > 0 {
		return c.Key, nil
	}

	if c.Password == "" {
		return nil, fmt.Errorf("no key or password provided")
	}

	keyLen := AES256KeySize
	switch c.Type {
	case TypeAES128GCM:
		keyLen = AES128KeySize
	}

	return DeriveKey(c.Password, c.Salt, keyLen), nil
}

// Encryptor provides encryption and decryption functionality.
type Encryptor interface {
	// WrapConn wraps a connection with encryption.
	WrapConn(conn net.Conn) (net.Conn, error)

	// Type returns the encryption type.
	Type() Type
}

// aesGCMEncryptor implements Encryptor for AES-GCM.
type aesGCMEncryptor struct {
	key  []byte
	salt []byte
}

func (e *aesGCMEncryptor) WrapConn(conn net.Conn) (net.Conn, error) {
	return NewAESGCMConn(conn, e.key)
}

func (e *aesGCMEncryptor) Type() Type {
	return TypeAESGCM
}

// aesCFBEncryptor implements Encryptor for AES-CFB.
type aesCFBEncryptor struct {
	key []byte
}

func (e *aesCFBEncryptor) WrapConn(conn net.Conn) (net.Conn, error) {
	return NewAESCFBConn(conn, e.key)
}

func (e *aesCFBEncryptor) Type() Type {
	return TypeAESCFB
}

// noneEncryptor implements Encryptor with no encryption.
type noneEncryptor struct{}

func (e *noneEncryptor) WrapConn(conn net.Conn) (net.Conn, error) {
	return conn, nil
}

func (e *noneEncryptor) Type() Type {
	return TypeNone
}

// NewEncryptor creates a new Encryptor based on the configuration.
func NewEncryptor(config *Config) (Encryptor, error) {
	if config == nil {
		return &noneEncryptor{}, nil
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	switch config.Type {
	case TypeNone:
		return &noneEncryptor{}, nil

	case TypeAESGCM, TypeAES256GCM, TypeAES128GCM:
		key, err := config.GetKey()
		if err != nil {
			return nil, err
		}
		return &aesGCMEncryptor{key: key, salt: config.Salt}, nil

	case TypeAESCFB, TypeAES256CFB:
		key, err := config.GetKey()
		if err != nil {
			return nil, err
		}
		return &aesCFBEncryptor{key: key}, nil

	default:
		return nil, fmt.Errorf("unsupported encryption type: %s", config.Type)
	}
}

// NewEncryptorWithPassword creates a new Encryptor with a password.
func NewEncryptorWithPassword(t Type, password string) (Encryptor, error) {
	return NewEncryptor(&Config{
		Type:        t,
		Password: password,
	})
}

// NewEncryptorWithKey creates a new Encryptor with a raw key.
func NewEncryptorWithKey(t Type, key []byte) (Encryptor, error) {
	return NewEncryptor(&Config{
		Type: t,
		Key:  key,
	})
}

// WrapConn wraps a connection with the specified encryption type and password.
// This is a convenience function for simple use cases.
func WrapConn(conn net.Conn, t Type, password string) (net.Conn, error) {
	encryptor, err := NewEncryptorWithPassword(t, password)
	if err != nil {
		return nil, err
	}
	return encryptor.WrapConn(conn)
}

// WrapConnWithKey wraps a connection with the specified encryption type and key.
func WrapConnWithKey(conn net.Conn, t Type, key []byte) (net.Conn, error) {
	encryptor, err := NewEncryptorWithKey(t, key)
	if err != nil {
		return nil, err
	}
	return encryptor.WrapConn(conn)
}

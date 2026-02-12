// Package user provides user management functionality for the netproxy framework.
package user

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Common errors
var (
	ErrUserNotFound     = errors.New("user not found")
	ErrUserExists       = errors.New("user already exists")
	ErrInvalidPassword  = errors.New("invalid password")
	ErrQuotaExceeded    = errors.New("traffic quota exceeded")
	ErrUserExpired      = errors.New("user account expired")
	ErrUserDisabled     = errors.New("user account disabled")
)

// Level represents user privilege level.
type Level int

const (
	// LevelFree is the free tier with limited features.
	LevelFree Level = 0
	// LevelBasic is the basic tier.
	LevelBasic Level = 1
	// LevelPremium is the premium tier with all features.
	LevelPremium Level = 2
	// LevelAdmin is the administrator level.
	LevelAdmin Level = 99
)

// User represents a user account.
type User struct {
	// ID is the unique identifier for the user.
	ID string `json:"id"`

	// Username is the login name.
	Username string `json:"username"`

	// PasswordHash is the bcrypt hash of the password.
	PasswordHash string `json:"-"`

	// Email is the user's email address.
	Email string `json:"email,omitempty"`

	// UUID is used for VMess/VLESS authentication.
	UUID string `json:"uuid"`

	// Level is the user's privilege level.
	Level Level `json:"level"`

	// Quota is the traffic quota in bytes (0 = unlimited).
	Quota int64 `json:"quota"`

	// UsedUpload is the total uploaded bytes.
	UsedUpload int64 `json:"used_upload"`

	// UsedDownload is the total downloaded bytes.
	UsedDownload int64 `json:"used_download"`

	// ExpireAt is when the account expires (zero = never).
	ExpireAt time.Time `json:"expire_at,omitempty"`

	// Enabled indicates if the account is active.
	Enabled bool `json:"enabled"`

	// MaxConnections is the maximum concurrent connections (0 = unlimited).
	MaxConnections int `json:"max_connections"`

	// SpeedLimit is the speed limit in bytes per second (0 = unlimited).
	SpeedLimit int64 `json:"speed_limit"`

	// AllowedIPs is a list of allowed client IP addresses (empty = all).
	AllowedIPs []string `json:"allowed_ips,omitempty"`

	// Metadata holds additional user data.
	Metadata map[string]string `json:"metadata,omitempty"`

	// CreatedAt is when the account was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the account was last updated.
	UpdatedAt time.Time `json:"updated_at"`

	// LastLoginAt is when the user last logged in.
	LastLoginAt time.Time `json:"last_login_at,omitempty"`

	// LastLoginIP is the IP address of the last login.
	LastLoginIP string `json:"last_login_ip,omitempty"`
}

// NewUser creates a new user with default values.
func NewUser(username, password string) (*User, error) {
	if username == "" {
		return nil, errors.New("username is required")
	}
	if password == "" {
		return nil, ErrInvalidPassword
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Generate UUID for VMess/VLESS
	userUUID := uuid.New().String()

	now := time.Now()
	return &User{
		ID:           generateID(),
		Username:     username,
		PasswordHash: string(hash),
		UUID:         userUUID,
		Level:        LevelBasic,
		Enabled:      true,
		CreatedAt:    now,
		UpdatedAt:    now,
		Metadata:     make(map[string]string),
	}, nil
}

// generateID generates a random ID.
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// VerifyPassword checks if the provided password matches the stored hash.
func (u *User) VerifyPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	return err == nil
}

// SetPassword sets a new password for the user.
func (u *User) SetPassword(password string) error {
	if password == "" {
		return ErrInvalidPassword
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	u.PasswordHash = string(hash)
	u.UpdatedAt = time.Now()
	return nil
}

// IsExpired returns true if the user account has expired.
func (u *User) IsExpired() bool {
	if u.ExpireAt.IsZero() {
		return false
	}
	return time.Now().After(u.ExpireAt)
}

// IsQuotaExceeded returns true if the user has exceeded their traffic quota.
func (u *User) IsQuotaExceeded() bool {
	if u.Quota <= 0 {
		return false
	}
	return u.UsedUpload+u.UsedDownload >= u.Quota
}

// IsActive returns true if the user account is active and usable.
func (u *User) IsActive() bool {
	return u.Enabled && !u.IsExpired() && !u.IsQuotaExceeded()
}

// AddTraffic adds traffic usage to the user.
func (u *User) AddTraffic(upload, download int64) {
	u.UsedUpload += upload
	u.UsedDownload += download
	u.UpdatedAt = time.Now()
}

// ResetTraffic resets the user's traffic counters.
func (u *User) ResetTraffic() {
	u.UsedUpload = 0
	u.UsedDownload = 0
	u.UpdatedAt = time.Now()
}

// TotalTraffic returns the total traffic used.
func (u *User) TotalTraffic() int64 {
	return u.UsedUpload + u.UsedDownload
}

// RemainingQuota returns the remaining traffic quota.
// Returns -1 if quota is unlimited.
func (u *User) RemainingQuota() int64 {
	if u.Quota <= 0 {
		return -1
	}
	remaining := u.Quota - u.TotalTraffic()
	if remaining < 0 {
		return 0
	}
	return remaining
}

// RegenerateUUID generates a new UUID for the user.
func (u *User) RegenerateUUID() {
	u.UUID = uuid.New().String()
	u.UpdatedAt = time.Now()
}

// Clone creates a deep copy of the user.
func (u *User) Clone() *User {
	clone := *u
	if u.AllowedIPs != nil {
		clone.AllowedIPs = make([]string, len(u.AllowedIPs))
		copy(clone.AllowedIPs, u.AllowedIPs)
	}
	if u.Metadata != nil {
		clone.Metadata = make(map[string]string)
		for k, v := range u.Metadata {
			clone.Metadata[k] = v
		}
	}
	return &clone
}

// TrafficStats holds traffic statistics for a user.
type TrafficStats struct {
	UserID       string    `json:"user_id"`
	Upload       int64     `json:"upload"`
	Download     int64     `json:"download"`
	Total        int64     `json:"total"`
	Quota        int64     `json:"quota"`
	Remaining    int64     `json:"remaining"`
	LastUpdated  time.Time `json:"last_updated"`
}

// GetTrafficStats returns the user's traffic statistics.
func (u *User) GetTrafficStats() *TrafficStats {
	return &TrafficStats{
		UserID:      u.ID,
		Upload:      u.UsedUpload,
		Download:    u.UsedDownload,
		Total:       u.TotalTraffic(),
		Quota:       u.Quota,
		Remaining:   u.RemainingQuota(),
		LastUpdated: u.UpdatedAt,
	}
}

// CreateUserRequest is the request body for creating a user.
type CreateUserRequest struct {
	Username       string            `json:"username"`
	Password       string            `json:"password"`
	Email          string            `json:"email,omitempty"`
	Level          Level             `json:"level,omitempty"`
	Quota          int64             `json:"quota,omitempty"`
	ExpireDays     int               `json:"expire_days,omitempty"`
	MaxConnections int               `json:"max_connections,omitempty"`
	SpeedLimit     int64             `json:"speed_limit,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// UpdateUserRequest is the request body for updating a user.
type UpdateUserRequest struct {
	Email          *string           `json:"email,omitempty"`
	Password       *string           `json:"password,omitempty"`
	Level          *Level            `json:"level,omitempty"`
	Quota          *int64            `json:"quota,omitempty"`
	Enabled        *bool             `json:"enabled,omitempty"`
	ExpireAt       *time.Time        `json:"expire_at,omitempty"`
	MaxConnections *int              `json:"max_connections,omitempty"`
	SpeedLimit     *int64            `json:"speed_limit,omitempty"`
	AllowedIPs     []string          `json:"allowed_ips,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// Apply applies the update request to the user.
func (r *UpdateUserRequest) Apply(u *User) error {
	if r.Email != nil {
		u.Email = *r.Email
	}
	if r.Password != nil {
		if err := u.SetPassword(*r.Password); err != nil {
			return err
		}
	}
	if r.Level != nil {
		u.Level = *r.Level
	}
	if r.Quota != nil {
		u.Quota = *r.Quota
	}
	if r.Enabled != nil {
		u.Enabled = *r.Enabled
	}
	if r.ExpireAt != nil {
		u.ExpireAt = *r.ExpireAt
	}
	if r.MaxConnections != nil {
		u.MaxConnections = *r.MaxConnections
	}
	if r.SpeedLimit != nil {
		u.SpeedLimit = *r.SpeedLimit
	}
	if r.AllowedIPs != nil {
		u.AllowedIPs = r.AllowedIPs
	}
	if r.Metadata != nil {
		if u.Metadata == nil {
			u.Metadata = make(map[string]string)
		}
		for k, v := range r.Metadata {
			u.Metadata[k] = v
		}
	}
	u.UpdatedAt = time.Now()
	return nil
}

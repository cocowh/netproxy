package user

import (
	"context"
)

// Store defines the interface for user storage.
type Store interface {
	// Create creates a new user.
	Create(ctx context.Context, user *User) error

	// Get retrieves a user by ID.
	Get(ctx context.Context, id string) (*User, error)

	// GetByUsername retrieves a user by username.
	GetByUsername(ctx context.Context, username string) (*User, error)

	// GetByUUID retrieves a user by UUID.
	GetByUUID(ctx context.Context, uuid string) (*User, error)

	// Update updates an existing user.
	Update(ctx context.Context, user *User) error

	// Delete deletes a user by ID.
	Delete(ctx context.Context, id string) error

	// List returns all users with optional pagination.
	List(ctx context.Context, offset, limit int) ([]*User, int, error)

	// Count returns the total number of users.
	Count(ctx context.Context) (int, error)

	// Search searches users by username or email.
	Search(ctx context.Context, query string, offset, limit int) ([]*User, int, error)

	// UpdateTraffic updates a user's traffic counters.
	UpdateTraffic(ctx context.Context, id string, upload, download int64) error

	// ResetTraffic resets a user's traffic counters.
	ResetTraffic(ctx context.Context, id string) error

	// ResetAllTraffic resets all users' traffic counters.
	ResetAllTraffic(ctx context.Context) error

	// GetActiveUsers returns all active users.
	GetActiveUsers(ctx context.Context) ([]*User, error)

	// Close closes the store.
	Close() error
}

// ListOptions holds options for listing users.
type ListOptions struct {
	Offset      int
	Limit       int
	SortBy      string
	SortOrder   string // "asc" or "desc"
	FilterLevel *Level
	FilterEnabled *bool
}

// DefaultListOptions returns default list options.
func DefaultListOptions() *ListOptions {
	return &ListOptions{
		Offset:    0,
		Limit:     100,
		SortBy:    "created_at",
		SortOrder: "desc",
	}
}

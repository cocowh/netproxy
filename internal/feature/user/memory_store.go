package user

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

// MemoryStore implements Store using in-memory storage.
// This is suitable for development and testing, or small deployments.
type MemoryStore struct {
	users    map[string]*User // keyed by ID
	byName   map[string]string // username -> ID
	byUUID   map[string]string // UUID -> ID
	mu       sync.RWMutex
}

// NewMemoryStore creates a new in-memory user store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		users:  make(map[string]*User),
		byName: make(map[string]string),
		byUUID: make(map[string]string),
	}
}

// Create creates a new user.
func (s *MemoryStore) Create(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if username already exists
	if _, exists := s.byName[user.Username]; exists {
		return ErrUserExists
	}

	// Check if ID already exists
	if _, exists := s.users[user.ID]; exists {
		return ErrUserExists
	}

	// Store the user
	s.users[user.ID] = user.Clone()
	s.byName[user.Username] = user.ID
	s.byUUID[user.UUID] = user.ID

	return nil
}

// Get retrieves a user by ID.
func (s *MemoryStore) Get(ctx context.Context, id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[id]
	if !exists {
		return nil, ErrUserNotFound
	}

	return user.Clone(), nil
}

// GetByUsername retrieves a user by username.
func (s *MemoryStore) GetByUsername(ctx context.Context, username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.byName[username]
	if !exists {
		return nil, ErrUserNotFound
	}

	user, exists := s.users[id]
	if !exists {
		return nil, ErrUserNotFound
	}

	return user.Clone(), nil
}

// GetByUUID retrieves a user by UUID.
func (s *MemoryStore) GetByUUID(ctx context.Context, uuid string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.byUUID[uuid]
	if !exists {
		return nil, ErrUserNotFound
	}

	user, exists := s.users[id]
	if !exists {
		return nil, ErrUserNotFound
	}

	return user.Clone(), nil
}

// Update updates an existing user.
func (s *MemoryStore) Update(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.users[user.ID]
	if !exists {
		return ErrUserNotFound
	}

	// Update username index if changed
	if existing.Username != user.Username {
		// Check if new username is taken
		if _, taken := s.byName[user.Username]; taken {
			return ErrUserExists
		}
		delete(s.byName, existing.Username)
		s.byName[user.Username] = user.ID
	}

	// Update UUID index if changed
	if existing.UUID != user.UUID {
		delete(s.byUUID, existing.UUID)
		s.byUUID[user.UUID] = user.ID
	}

	user.UpdatedAt = time.Now()
	s.users[user.ID] = user.Clone()

	return nil
}

// Delete deletes a user by ID.
func (s *MemoryStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[id]
	if !exists {
		return ErrUserNotFound
	}

	delete(s.users, id)
	delete(s.byName, user.Username)
	delete(s.byUUID, user.UUID)

	return nil
}

// List returns all users with optional pagination.
func (s *MemoryStore) List(ctx context.Context, offset, limit int) ([]*User, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Get all users
	users := make([]*User, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user.Clone())
	}

	// Sort by created_at descending
	sort.Slice(users, func(i, j int) bool {
		return users[i].CreatedAt.After(users[j].CreatedAt)
	})

	total := len(users)

	// Apply pagination
	if offset >= len(users) {
		return []*User{}, total, nil
	}

	end := offset + limit
	if end > len(users) {
		end = len(users)
	}

	return users[offset:end], total, nil
}

// Count returns the total number of users.
func (s *MemoryStore) Count(ctx context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users), nil
}

// Search searches users by username or email.
func (s *MemoryStore) Search(ctx context.Context, query string, offset, limit int) ([]*User, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query = strings.ToLower(query)
	var results []*User

	for _, user := range s.users {
		if strings.Contains(strings.ToLower(user.Username), query) ||
			strings.Contains(strings.ToLower(user.Email), query) {
			results = append(results, user.Clone())
		}
	}

	// Sort by created_at descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].CreatedAt.After(results[j].CreatedAt)
	})

	total := len(results)

	// Apply pagination
	if offset >= len(results) {
		return []*User{}, total, nil
	}

	end := offset + limit
	if end > len(results) {
		end = len(results)
	}

	return results[offset:end], total, nil
}

// UpdateTraffic updates a user's traffic counters.
func (s *MemoryStore) UpdateTraffic(ctx context.Context, id string, upload, download int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[id]
	if !exists {
		return ErrUserNotFound
	}

	user.UsedUpload += upload
	user.UsedDownload += download
	user.UpdatedAt = time.Now()

	return nil
}

// ResetTraffic resets a user's traffic counters.
func (s *MemoryStore) ResetTraffic(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[id]
	if !exists {
		return ErrUserNotFound
	}

	user.UsedUpload = 0
	user.UsedDownload = 0
	user.UpdatedAt = time.Now()

	return nil
}

// ResetAllTraffic resets all users' traffic counters.
func (s *MemoryStore) ResetAllTraffic(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for _, user := range s.users {
		user.UsedUpload = 0
		user.UsedDownload = 0
		user.UpdatedAt = now
	}

	return nil
}

// GetActiveUsers returns all active users.
func (s *MemoryStore) GetActiveUsers(ctx context.Context) ([]*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var active []*User
	for _, user := range s.users {
		if user.IsActive() {
			active = append(active, user.Clone())
		}
	}

	return active, nil
}

// Close closes the store.
func (s *MemoryStore) Close() error {
	return nil
}

// Ensure MemoryStore implements Store
var _ Store = (*MemoryStore)(nil)

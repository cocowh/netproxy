package auth

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// CacheEntry represents a cached authentication result
type CacheEntry struct {
	user      *User
	expiresAt time.Time
	key       string
}

// LRUCache implements a simple LRU cache
type LRUCache struct {
	mu       sync.Mutex
	capacity int
	items    map[string]*list.Element
	order    *list.List
}

// NewLRUCache creates a new LRU cache with the given capacity
func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		items:    make(map[string]*list.Element),
		order:    list.New(),
	}
}

// Get retrieves an item from the cache
func (c *LRUCache) Get(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)
		return elem.Value, true
	}
	return nil, false
}

// Add adds an item to the cache
func (c *LRUCache) Add(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If key exists, update and move to front
	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)
		elem.Value = value
		return
	}

	// Evict oldest if at capacity
	if c.order.Len() >= c.capacity {
		oldest := c.order.Back()
		if oldest != nil {
			c.order.Remove(oldest)
			if entry, ok := oldest.Value.(*CacheEntry); ok {
				delete(c.items, entry.key)
			}
		}
	}

	// Add new item
	elem := c.order.PushFront(value)
	c.items[key] = elem
}

// Remove removes an item from the cache
func (c *LRUCache) Remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.Remove(elem)
		delete(c.items, key)
	}
}

// Clear clears the cache
func (c *LRUCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*list.Element)
	c.order.Init()
}

// Len returns the number of items in the cache
func (c *LRUCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// CachedAuthenticator wraps an Authenticator with caching
type CachedAuthenticator struct {
	backend  Authenticator
	cache    *LRUCache
	ttl      time.Duration
	hashPass bool // Whether to hash passwords in cache keys
}

// CachedAuthenticatorOption is a functional option for CachedAuthenticator
type CachedAuthenticatorOption func(*CachedAuthenticator)

// WithTTL sets the cache TTL
func WithTTL(ttl time.Duration) CachedAuthenticatorOption {
	return func(a *CachedAuthenticator) {
		a.ttl = ttl
	}
}

// WithCapacity sets the cache capacity
func WithCapacity(capacity int) CachedAuthenticatorOption {
	return func(a *CachedAuthenticator) {
		a.cache = NewLRUCache(capacity)
	}
}

// WithHashPassword enables password hashing in cache keys
func WithHashPassword(hash bool) CachedAuthenticatorOption {
	return func(a *CachedAuthenticator) {
		a.hashPass = hash
	}
}

// NewCachedAuthenticator creates a new cached authenticator
func NewCachedAuthenticator(backend Authenticator, opts ...CachedAuthenticatorOption) *CachedAuthenticator {
	a := &CachedAuthenticator{
		backend:  backend,
		cache:    NewLRUCache(1000), // Default capacity
		ttl:      5 * time.Minute,   // Default TTL
		hashPass: true,              // Hash passwords by default for security
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

// Authenticate checks the cache first, then falls back to the backend
func (a *CachedAuthenticator) Authenticate(ctx context.Context, user, pass string) (*User, error) {
	key := a.cacheKey(user, pass)

	// Check cache
	if val, ok := a.cache.Get(key); ok {
		if entry, ok := val.(*CacheEntry); ok {
			// Check if entry is still valid
			if time.Now().Before(entry.expiresAt) {
				// Return a copy of the user to prevent modification
				return copyUser(entry.user), nil
			}
			// Entry expired, remove it
			a.cache.Remove(key)
		}
	}

	// Cache miss or expired, authenticate with backend
	u, err := a.backend.Authenticate(ctx, user, pass)
	if err != nil {
		return nil, err
	}

	// Cache successful authentication
	entry := &CacheEntry{
		user:      copyUser(u),
		expiresAt: time.Now().Add(a.ttl),
		key:       key,
	}
	a.cache.Add(key, entry)

	return u, nil
}

// cacheKey generates a cache key from username and password
func (a *CachedAuthenticator) cacheKey(user, pass string) string {
	if a.hashPass {
		// Hash the password for security
		h := sha256.New()
		h.Write([]byte(user + ":" + pass))
		return hex.EncodeToString(h.Sum(nil))
	}
	return user + ":" + pass
}

// Invalidate removes a user from the cache
func (a *CachedAuthenticator) Invalidate(user, pass string) {
	key := a.cacheKey(user, pass)
	a.cache.Remove(key)
}

// InvalidateUser removes all cache entries for a user
// Note: This is expensive as it requires iterating the cache
func (a *CachedAuthenticator) InvalidateUser(user string) {
	// For security, we can't easily invalidate by user only
	// since we hash the password. Clear the entire cache instead.
	a.cache.Clear()
}

// Clear clears the entire cache
func (a *CachedAuthenticator) Clear() {
	a.cache.Clear()
}

// CacheStats returns cache statistics
func (a *CachedAuthenticator) CacheStats() map[string]interface{} {
	return map[string]interface{}{
		"size":     a.cache.Len(),
		"capacity": a.cache.capacity,
		"ttl":      a.ttl.String(),
	}
}

// copyUser creates a copy of a User to prevent modification
func copyUser(u *User) *User {
	if u == nil {
		return nil
	}

	groups := make([]string, len(u.Groups))
	copy(groups, u.Groups)

	meta := make(map[string]interface{}, len(u.Meta))
	for k, v := range u.Meta {
		meta[k] = v
	}

	return &User{
		Username: u.Username,
		Groups:   groups,
		Meta:     meta,
	}
}

// NegativeCacheAuthenticator also caches failed authentication attempts
// to prevent repeated expensive backend calls for invalid credentials
type NegativeCacheAuthenticator struct {
	*CachedAuthenticator
	negativeCache    *LRUCache
	negativeTTL      time.Duration
	maxFailedAttempts int
	failedAttempts   map[string]int
	mu               sync.Mutex
}

// NewNegativeCacheAuthenticator creates an authenticator that also caches failures
func NewNegativeCacheAuthenticator(backend Authenticator, opts ...CachedAuthenticatorOption) *NegativeCacheAuthenticator {
	return &NegativeCacheAuthenticator{
		CachedAuthenticator: NewCachedAuthenticator(backend, opts...),
		negativeCache:       NewLRUCache(1000),
		negativeTTL:         1 * time.Minute,
		maxFailedAttempts:   5,
		failedAttempts:      make(map[string]int),
	}
}

// SetNegativeTTL sets the TTL for negative cache entries
func (a *NegativeCacheAuthenticator) SetNegativeTTL(ttl time.Duration) {
	a.negativeTTL = ttl
}

// SetMaxFailedAttempts sets the maximum failed attempts before blocking
func (a *NegativeCacheAuthenticator) SetMaxFailedAttempts(max int) {
	a.maxFailedAttempts = max
}

// Authenticate checks both positive and negative caches
func (a *NegativeCacheAuthenticator) Authenticate(ctx context.Context, user, pass string) (*User, error) {
	key := a.cacheKey(user, pass)

	// Check if user is blocked due to too many failed attempts
	a.mu.Lock()
	if attempts, ok := a.failedAttempts[user]; ok && attempts >= a.maxFailedAttempts {
		a.mu.Unlock()
		return nil, ErrTooManyFailedAttempts
	}
	a.mu.Unlock()

	// Check negative cache
	if val, ok := a.negativeCache.Get(key); ok {
		if entry, ok := val.(*negativeEntry); ok {
			if time.Now().Before(entry.expiresAt) {
				return nil, ErrInvalidCredentials
			}
			a.negativeCache.Remove(key)
		}
	}

	// Try positive cache and backend
	u, err := a.CachedAuthenticator.Authenticate(ctx, user, pass)
	if err != nil {
		// Cache the failure
		a.negativeCache.Add(key, &negativeEntry{
			expiresAt: time.Now().Add(a.negativeTTL),
		})

		// Track failed attempts
		a.mu.Lock()
		a.failedAttempts[user]++
		a.mu.Unlock()

		return nil, err
	}

	// Reset failed attempts on success
	a.mu.Lock()
	delete(a.failedAttempts, user)
	a.mu.Unlock()

	return u, nil
}

type negativeEntry struct {
	expiresAt time.Time
}

// Errors
var (
	ErrInvalidCredentials    = &AuthError{Message: "invalid credentials"}
	ErrTooManyFailedAttempts = &AuthError{Message: "too many failed attempts"}
)

// AuthError represents an authentication error
type AuthError struct {
	Message string
}

func (e *AuthError) Error() string {
	return e.Message
}

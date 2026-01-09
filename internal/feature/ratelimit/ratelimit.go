package ratelimit

import (
	"context"

	"golang.org/x/time/rate"
)

// Limiter defines the interface for rate limiting
type Limiter interface {
	// Allow checks if the event is allowed (non-blocking)
	Allow() bool

	// Wait waits for the event to be allowed (blocking)
	Wait(ctx context.Context) error
}

// TokenBucketLimiter implements token bucket rate limiting
type TokenBucketLimiter struct {
	limiter *rate.Limiter
}

// NewTokenBucketLimiter creates a new token bucket limiter
// r: limit (events per second)
// b: burst size
func NewTokenBucketLimiter(r rate.Limit, b int) Limiter {
	return &TokenBucketLimiter{
		limiter: rate.NewLimiter(r, b),
	}
}

func (l *TokenBucketLimiter) Allow() bool {
	return l.limiter.Allow()
}

func (l *TokenBucketLimiter) Wait(ctx context.Context) error {
	return l.limiter.Wait(ctx)
}

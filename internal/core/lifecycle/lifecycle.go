package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Hook defines the start and stop logic for a component
type Hook struct {
	OnStart func(context.Context) error
	OnStop  func(context.Context) error
	Name    string // Optional name for debugging
}

// Lifecycle manages the application lifecycle
type Lifecycle interface {
	// Start starts all registered hooks
	Start(ctx context.Context) error

	// Stop stops all registered hooks
	Stop(ctx context.Context) error

	// Append registers a new lifecycle hook
	Append(hook Hook)
}

// GracefulLifecycle extends Lifecycle with graceful restart support
type GracefulLifecycle interface {
	Lifecycle

	// Restart performs a graceful restart
	Restart(ctx context.Context) error

	// IsRestarting returns true if a restart is in progress
	IsRestarting() bool

	// OnRestart registers a callback for restart events
	OnRestart(callback func())
}

type appLifecycle struct {
	hooks []Hook
	mu    sync.Mutex
	// started keeps track of successfully started hooks (in order) for rollback/stop
	started []Hook
}

// gracefulLifecycle implements GracefulLifecycle
type gracefulLifecycle struct {
	*appLifecycle
	restarting       int32
	restartCallbacks []func()
	restartMu        sync.Mutex
	drainTimeout     time.Duration
	shutdownTimeout  time.Duration
}

// GracefulConfig configures graceful restart behavior
type GracefulConfig struct {
	// DrainTimeout is the time to wait for existing connections to drain
	DrainTimeout time.Duration

	// ShutdownTimeout is the maximum time to wait for shutdown
	ShutdownTimeout time.Duration
}

// DefaultGracefulConfig returns the default graceful configuration
func DefaultGracefulConfig() GracefulConfig {
	return GracefulConfig{
		DrainTimeout:    30 * time.Second,
		ShutdownTimeout: 60 * time.Second,
	}
}

// NewLifecycle creates a new lifecycle manager
func NewLifecycle() Lifecycle {
	return &appLifecycle{}
}

// NewGracefulLifecycle creates a new graceful lifecycle manager
func NewGracefulLifecycle(cfg GracefulConfig) GracefulLifecycle {
	return &gracefulLifecycle{
		appLifecycle:    &appLifecycle{},
		drainTimeout:    cfg.DrainTimeout,
		shutdownTimeout: cfg.ShutdownTimeout,
	}
}

func (l *appLifecycle) Append(hook Hook) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hooks = append(l.hooks, hook)
}

func (l *appLifecycle) Start(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, hook := range l.hooks {
		if hook.OnStart != nil {
			if err := hook.OnStart(ctx); err != nil {
				// Rollback: stop already started hooks
				e := l.stopStarted(ctx)
				if e != nil {
					return fmt.Errorf("failed to start %s: %w", hook.Name, e)
				}
				return fmt.Errorf("failed to start %s: %w", hook.Name, err)
			}
		}
		// Track started hook
		l.started = append(l.started, hook)
	}
	return nil
}

func (l *appLifecycle) Stop(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stopStarted(ctx)
}

// stopStarted stops hooks in l.started in reverse order
// Assumes lock is held
func (l *appLifecycle) stopStarted(ctx context.Context) error {
	var errs []error
	// Reverse order
	for i := len(l.started) - 1; i >= 0; i-- {
		hook := l.started[i]
		if hook.OnStop != nil {
			if err := hook.OnStop(ctx); err != nil {
				errs = append(errs, fmt.Errorf("failed to stop %s: %w", hook.Name, err))
			}
		}
	}
	// Clear started list
	l.started = nil

	if len(errs) > 0 {
		return errors.New(fmt.Sprintf("lifecycle stop errors: %v", errs))
	}
	return nil
}

// Restart performs a graceful restart
func (g *gracefulLifecycle) Restart(ctx context.Context) error {
	// Check if already restarting
	if !atomic.CompareAndSwapInt32(&g.restarting, 0, 1) {
		return errors.New("restart already in progress")
	}
	defer atomic.StoreInt32(&g.restarting, 0)

	// Notify callbacks
	g.notifyRestartCallbacks()

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, g.shutdownTimeout)
	defer shutdownCancel()

	// Stop all hooks
	if err := g.Stop(shutdownCtx); err != nil {
		return fmt.Errorf("failed to stop during restart: %w", err)
	}

	// Wait for drain timeout to allow connections to close
	select {
	case <-time.After(g.drainTimeout):
	case <-ctx.Done():
		return ctx.Err()
	}

	// Start all hooks again
	if err := g.Start(ctx); err != nil {
		return fmt.Errorf("failed to start during restart: %w", err)
	}

	return nil
}

// IsRestarting returns true if a restart is in progress
func (g *gracefulLifecycle) IsRestarting() bool {
	return atomic.LoadInt32(&g.restarting) == 1
}

// OnRestart registers a callback for restart events
func (g *gracefulLifecycle) OnRestart(callback func()) {
	g.restartMu.Lock()
	defer g.restartMu.Unlock()
	g.restartCallbacks = append(g.restartCallbacks, callback)
}

// notifyRestartCallbacks notifies all registered restart callbacks
func (g *gracefulLifecycle) notifyRestartCallbacks() {
	g.restartMu.Lock()
	callbacks := make([]func(), len(g.restartCallbacks))
	copy(callbacks, g.restartCallbacks)
	g.restartMu.Unlock()

	for _, cb := range callbacks {
		cb()
	}
}

// RunAndWait starts the lifecycle, waits for signals, and then stops it.
// This is a helper function for the main entry point.
func RunAndWait(ctx context.Context, l Lifecycle, signals ...os.Signal) error {
	if err := l.Start(ctx); err != nil {
		return err
	}

	sigChan := make(chan os.Signal, 1)
	if len(signals) == 0 {
		signals = []os.Signal{syscall.SIGINT, syscall.SIGTERM}
	}
	signal.Notify(sigChan, signals...)

	select {
	case <-ctx.Done():
		// Context cancelled
	case <-sigChan:
		// Signal received
	}

	// Create a new context for shutdown with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return l.Stop(shutdownCtx)
}

// RunWithGracefulRestart starts the lifecycle with graceful restart support.
// SIGHUP triggers a graceful restart, SIGINT/SIGTERM triggers shutdown.
func RunWithGracefulRestart(ctx context.Context, l GracefulLifecycle) error {
	if err := l.Start(ctx); err != nil {
		return err
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		select {
		case <-ctx.Done():
			// Context cancelled, shutdown
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			err := l.Stop(shutdownCtx)
			cancel()
			return err

		case sig := <-sigChan:
			switch sig {
			case syscall.SIGHUP:
				// Graceful restart
				if err := l.Restart(ctx); err != nil {
					// Log error but continue running
					continue
				}

			case syscall.SIGINT, syscall.SIGTERM:
				// Shutdown
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				err := l.Stop(shutdownCtx)
				cancel()
				return err
			}
		}
	}
}

// DrainableServer is an interface for servers that support connection draining
type DrainableServer interface {
	// Drain stops accepting new connections and waits for existing ones to complete
	Drain(ctx context.Context) error
}

// ConnectionTracker tracks active connections for graceful shutdown
type ConnectionTracker struct {
	active int64
	done   chan struct{}
	mu     sync.Mutex
}

// NewConnectionTracker creates a new connection tracker
func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		done: make(chan struct{}),
	}
}

// Add increments the active connection count
func (t *ConnectionTracker) Add() {
	atomic.AddInt64(&t.active, 1)
}

// Done decrements the active connection count
func (t *ConnectionTracker) Done() {
	if atomic.AddInt64(&t.active, -1) == 0 {
		t.mu.Lock()
		select {
		case <-t.done:
		default:
			close(t.done)
		}
		t.mu.Unlock()
	}
}

// Active returns the number of active connections
func (t *ConnectionTracker) Active() int64 {
	return atomic.LoadInt64(&t.active)
}

// Wait waits for all connections to complete or context to be cancelled
func (t *ConnectionTracker) Wait(ctx context.Context) error {
	if t.Active() == 0 {
		return nil
	}

	select {
	case <-t.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Reset resets the tracker for reuse
func (t *ConnectionTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	atomic.StoreInt64(&t.active, 0)
	t.done = make(chan struct{})
}

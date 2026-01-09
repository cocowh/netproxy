package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
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

type appLifecycle struct {
	hooks []Hook
	mu    sync.Mutex
	// started keeps track of successfully started hooks (in order) for rollback/stop
	started []Hook
}

// NewLifecycle creates a new lifecycle manager
func NewLifecycle() Lifecycle {
	return &appLifecycle{}
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

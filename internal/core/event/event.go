package event

import (
	"reflect"
	"sync"
	"time"
)

// Event represents a system event
type Event struct {
	Topic   string
	Payload interface{}
	Time    time.Time
}

// Handler handles an incoming event
type Handler func(e Event)

// Bus defines the event bus interface
type Bus interface {
	// Publish sends an event to all subscribers of the topic
	Publish(topic string, payload interface{})

	// Subscribe adds a handler for a topic
	Subscribe(topic string, handler Handler)

	// Unsubscribe removes a handler for a topic
	Unsubscribe(topic string, handler Handler)
}

type memoryBus struct {
	subscribers map[string][]Handler
	mu          sync.RWMutex
}

// NewBus creates a new in-memory event bus
func NewBus() Bus {
	return &memoryBus{
		subscribers: make(map[string][]Handler),
	}
}

func (b *memoryBus) Publish(topic string, payload interface{}) {
	b.mu.RLock()
	handlers, ok := b.subscribers[topic]
	// Copy handlers to avoid holding lock during execution
	var snapshot []Handler
	if ok {
		snapshot = make([]Handler, len(handlers))
		copy(snapshot, handlers)
	}
	b.mu.RUnlock()

	if len(snapshot) == 0 {
		return
	}

	event := Event{
		Topic:   topic,
		Payload: payload,
		Time:    time.Now(),
	}

	for _, h := range snapshot {
		// Execute handlers asynchronously to prevent blocking the publisher
		go func(handler Handler) {
			defer func() {
				if r := recover(); r != nil {
					// TODO: log recovery
				}
			}()
			handler(event)
		}(h)
	}
}

func (b *memoryBus) Subscribe(topic string, handler Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subscribers[topic] = append(b.subscribers[topic], handler)
}

func (b *memoryBus) Unsubscribe(topic string, handler Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()

	handlers, ok := b.subscribers[topic]
	if !ok {
		return
	}

	// Use reflection to compare function pointers
	targetPtr := reflect.ValueOf(handler).Pointer()

	var newHandlers []Handler
	for _, h := range handlers {
		if reflect.ValueOf(h).Pointer() != targetPtr {
			newHandlers = append(newHandlers, h)
		}
	}

	if len(newHandlers) == 0 {
		delete(b.subscribers, topic)
	} else {
		b.subscribers[topic] = newHandlers
	}
}

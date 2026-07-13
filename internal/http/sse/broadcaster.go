package sse

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

type Event struct {
	Timestamp time.Time `json:"ts"`
	Sequence  uint64    `json:"seq"`
	Domain    string    `json:"domain"`
	ClientIP  string    `json:"ip"`
	Source    string    `json:"src"`
	Blocked   bool      `json:"blocked"`
	ASN       string    `json:"asn,omitempty"`
	Country   string    `json:"country,omitempty"`
}

type Broadcaster struct {
	subscribers  map[chan Event]struct{}
	nextSequence atomic.Uint64
	logger       *slog.Logger
	mu           sync.RWMutex
}

func NewBroadcaster(logger *slog.Logger) *Broadcaster {
	return &Broadcaster{
		subscribers: make(map[chan Event]struct{}),
		logger:      logger,
	}
}

func (b *Broadcaster) Subscribe() chan Event {
	b.logger.Debug("New subscriber added")
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan Event, 10)
	b.subscribers[ch] = struct{}{}
	return ch
}

func (b *Broadcaster) Unsubscribe(ch chan Event) {
	b.logger.Debug("Subscriber removed")
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.subscribers[ch]; ok {
		delete(b.subscribers, ch)
		close(ch)
	}
}

func (b *Broadcaster) Broadcast(event Event) {
	event.Sequence = b.nextSequence.Add(1)

	b.mu.RLock()
	defer b.mu.RUnlock()

	for ch := range b.subscribers {
		select {
		case ch <- event:
		default:
			// Buffer full, drop message for this slow client
		}
	}
}

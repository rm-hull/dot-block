package sse

import (
	"log/slog"
	"sync"
	"time"
)

type Event struct {
	Sequence uint64    `json:"sequence"`
	Domain   string    `json:"domain"`
	ClientIP string    `json:"client_ip"`
	Source   string    `json:"source"`
	Blocked  bool      `json:"blocked"`
	ASN      string    `json:"asn,omitempty"`
	Country  string    `json:"country,omitempty"`
	Time     time.Time `json:"time"`
}

type Broadcaster struct {
	subscribers  map[chan Event]struct{}
	nextSequence uint64
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
	b.mu.Lock()
	event.Sequence = b.nextSequence
	b.nextSequence++
	b.mu.Unlock()

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

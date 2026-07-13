package sse

import (
	"log/slog"
	"sync"
	"time"
)

type Event struct {
	Domain   string    `json:"domain"`
	ClientIP string    `json:"client_ip"`
	Source   string    `json:"source"`
	Blocked  bool      `json:"blocked"`
	ASN      string    `json:"asn,omitempty"`
	Country  string    `json:"country,omitempty"`
	Time     time.Time `json:"time"`
}

type Broadcaster struct {
	subscribers map[chan []byte]struct{}
	logger      *slog.Logger
	mu          sync.RWMutex
}

func NewBroadcaster(logger *slog.Logger) *Broadcaster {
	return &Broadcaster{
		subscribers: make(map[chan []byte]struct{}),
		logger:      logger,
	}
}

func (b *Broadcaster) Subscribe() chan []byte {
	b.logger.Debug("New subscriber added")
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan []byte, 10)
	b.subscribers[ch] = struct{}{}
	return ch
}

func (b *Broadcaster) Unsubscribe(ch chan []byte) {
	b.logger.Debug("Subscriber removed")
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.subscribers[ch]; ok {
		delete(b.subscribers, ch)
		close(ch)
	}
}

func (b *Broadcaster) Broadcast(msg []byte) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for ch := range b.subscribers {
		select {
		case ch <- msg:
		default:
			// Buffer full, drop message for this slow client
		}
	}
}

package sse

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBroadcaster(t *testing.T) {
	b := NewBroadcaster()

	// Register a subscriber
	subscriber := b.Subscribe()
	defer b.Unsubscribe(subscriber)

	// Broadcast a message
	msg := []byte("hello")
	b.Broadcast(msg)

	// Verify receipt
	select {
	case received := <-subscriber:
		assert.Equal(t, msg, received)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for message")
	}
}

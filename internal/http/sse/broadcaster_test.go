package sse

import (
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBroadcaster(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	b := NewBroadcaster(logger)

	// Register a subscriber
	subscriber := b.Subscribe()
	defer b.Unsubscribe(subscriber)

	// Broadcast a message
	event := Event{Domain: "example.com"}
	b.Broadcast(event)

	// Verify receipt
	select {
	case received := <-subscriber:
		assert.Equal(t, "example.com", received.Domain)
		assert.Equal(t, uint64(0), received.Sequence)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for message")
	}

	// Broadcast another message to check sequence
	b.Broadcast(Event{Domain: "test.com"})

	select {
	case received := <-subscriber:
		assert.Equal(t, "test.com", received.Domain)
		assert.Equal(t, uint64(1), received.Sequence)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for message")
	}
}

func TestEventJSONMarshaling(t *testing.T) {
	now := time.Date(2024, 1, 1, 12, 0, 0, 123456789, time.UTC)
	event := Event{
		Domain: "example.com",
		Time:   now,
	}

	data, err := json.Marshal(event)
	require.NoError(t, err)

	var m map[string]any
	err = json.Unmarshal(data, &m)
	require.NoError(t, err)

	timeStr, ok := m["time"].(string)
	require.True(t, ok, "time field should be a string")

	assert.Equal(t, now.Format(time.RFC3339Nano), timeStr, "timestamp should match the expected RFC3339Nano format")
}

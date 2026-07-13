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

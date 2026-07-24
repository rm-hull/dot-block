package sse

import (
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBroadcaster(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	droppedEvents := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_dropped_sse_events_total",
		Help: "Total number of SSE events dropped because the subscriber buffer was full",
	})
	b := NewBroadcaster(logger, droppedEvents)

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
		assert.Equal(t, uint64(1), received.Sequence)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for message")
	}

	// Broadcast another message to check sequence
	b.Broadcast(Event{Domain: "test.com"})

	select {
	case received := <-subscriber:
		assert.Equal(t, "test.com", received.Domain)
		assert.Equal(t, uint64(2), received.Sequence)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for message")
	}
}

func TestEventJSONMarshaling(t *testing.T) {
	now := time.Date(2024, 1, 1, 12, 0, 0, 123456789, time.UTC)
	event := Event{
		Domain:    "example.com",
		Timestamp: now,
	}

	data, err := json.Marshal(event)
	require.NoError(t, err)

	var m map[string]any
	err = json.Unmarshal(data, &m)
	require.NoError(t, err)

	timestampStr, ok := m["ts"].(string)
	require.True(t, ok, "time field should be a string")

	assert.Equal(t, now.Format(time.RFC3339Nano), timestampStr, "timestamp should match the expected RFC3339Nano format")
}

func TestBroadcasterDropsEventsForSlowSubscribers(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	droppedEvents := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_dropped_sse_events_total",
		Help: "Total number of SSE events dropped because the subscriber buffer was full",
	})
	b := NewBroadcaster(logger, droppedEvents)

	// Subscribe but don't read from the channel - it will fill up quickly
	subscriber := b.Subscribe()
	defer b.Unsubscribe(subscriber)

	// Fill the subscriber buffer (capacity 10) and then some
	for i := 0; i < 15; i++ {
		b.Broadcast(Event{Domain: "example.com"})
	}

	// The dropped events counter should reflect the overflow
	var dto dto.Metric
	err := droppedEvents.(prometheus.Metric).Write(&dto)
	require.NoError(t, err)

	droppedCount := dto.GetCounter().GetValue()
	assert.Greater(t, droppedCount, 0.0, "dropped events counter should be incremented when subscriber buffer is full")
}

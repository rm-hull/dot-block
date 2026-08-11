package handlers

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rm-hull/dot-block/internal/http/sse"
	"github.com/stretchr/testify/assert"
)

func TestSSEHandler_QueryFiltersBlockedEvents(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	droppedEvents := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_dropped_sse_events_total",
		Help: "Total number of SSE events dropped because the subscriber buffer was full",
	})
	broadcaster := sse.NewBroadcaster(logger, droppedEvents)

	req := httptest.NewRequest(http.MethodGet, "/api/events?blocked=true", nil)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	handler := SSEHandler(broadcaster)

	reqCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req = req.WithContext(reqCtx)
	ctx.Request = req

	// Run the handler in a goroutine so the test can drain the response asynchronously.
	done := make(chan struct{})
	go func() {
		handler(ctx)
		close(done)
	}()

	// Give the handler time to subscribe before broadcasting events.
	time.Sleep(50 * time.Millisecond)

	events := []sse.Event{
		{Domain: "allowed.example", Blocked: false},
		{Domain: "blocked.example", Blocked: true},
	}

	for _, ev := range events {
		broadcaster.Broadcast(ev)
	}

	// Give the handler a moment to process broadcast events.
	time.Sleep(50 * time.Millisecond)

	// Stop the handler and wait for it to finish before reading the recorder
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not exit after cancellation")
	}

	// Now it's safe to read the recorder without races
	body := w.Body.String()
	assert.Contains(t, body, "event:ping")
	assert.Contains(t, body, "blocked.example", "blocked=true should include blocked events")
	assert.NotContains(t, body, "allowed.example", "blocked=true should not include non-blocked events")
}

func TestSSEHandler_InvalidQueryParamReturnsBadRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	droppedEvents := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_dropped_sse_events_total",
		Help: "Total number of SSE events dropped because the subscriber buffer was full",
	})
	broadcaster := sse.NewBroadcaster(logger, droppedEvents)

	req := httptest.NewRequest(http.MethodGet, "/api/events?blocked=notabool", nil)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = req

	handler := SSEHandler(broadcaster)

	handler(ctx)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid query parameters")
}

func TestSSEHandler_DomainFiltersMatchMultiple(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	droppedEvents := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_dropped_sse_events_total",
		Help: "Total number of SSE events dropped because the subscriber buffer was full",
	})
	broadcaster := sse.NewBroadcaster(logger, droppedEvents)

	// Request that filters for both example.com and other.com
	req := httptest.NewRequest(http.MethodGet, "/api/events?domain=example.com&domain=other.com", nil)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	handler := SSEHandler(broadcaster)

	reqCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req = req.WithContext(reqCtx)
	ctx.Request = req

	// Run handler
	done := make(chan struct{})
	go func() {
		handler(ctx)
		close(done)
	}()

	// Allow subscription
	time.Sleep(30 * time.Millisecond)

	events := []sse.Event{
		{Domain: "a.b.example.com", Blocked: false},
		{Domain: "x.other.com", Blocked: false},
		{Domain: "nope.notmatched", Blocked: false},
	}
	for _, ev := range events {
		broadcaster.Broadcast(ev)
	}

	time.Sleep(50 * time.Millisecond)

	// Stop the handler and wait for it to finish before reading the recorder
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not exit after cancellation")
	}

	// Now safe to read the response body
	body := w.Body.String()
	assert.Contains(t, body, "a.b.example.com")
	assert.Contains(t, body, "x.other.com")
	assert.NotContains(t, body, "nope.notmatched")
}

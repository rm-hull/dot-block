package logging

import (
	"context"
	"log/slog"
	"time"

	"github.com/getsentry/sentry-go"
)

// SentryHandler wraps an existing slog.Handler and forwards logs with level ERROR or higher to Sentry.
type SentryHandler struct {
	next  slog.Handler
	attrs []slog.Attr
}

// NewSentryHandler creates a new SentryHandler that wraps the provided handler.
func NewSentryHandler(next slog.Handler) *SentryHandler {
	return &SentryHandler{next: next}
}

func (h *SentryHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *SentryHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelError {
		event := h.createSentryEvent(r)
		if hub := sentry.GetHubFromContext(ctx); hub != nil {
			hub.CaptureEvent(event)
		} else {
			sentry.CaptureEvent(event)
		}
	}
	return h.next.Handle(ctx, r)
}

// createSentryEvent converts a slog.Record into a sentry.Event.
func (h *SentryHandler) createSentryEvent(r slog.Record) *sentry.Event {
	event := sentry.NewEvent()
	event.Message = r.Message
	event.Level = sentry.LevelError

	if r.Level > slog.LevelError {
		event.Level = sentry.LevelFatal
	}

	extra := make(map[string]any)
	var err error

	formatVal := func(v slog.Value) any {
		val := v.Any()
		if dur, ok := val.(time.Duration); ok {
			return dur.String()
		}
		return val
	}

	// Add accumulated attributes from the handler
	for _, a := range h.attrs {
		extra[a.Key] = formatVal(a.Value)
	}

	// Add record attributes
	r.Attrs(func(a slog.Attr) bool {
		val := formatVal(a.Value)
		if a.Key == "error" {
			if e, ok := val.(error); ok {
				err = e
			}
		}
		extra[a.Key] = val
		return true
	})

	if err != nil {
		event.SetException(err, 10)
	}
	event.Contexts = map[string]sentry.Context{"extra": extra}

	return event
}

func (h *SentryHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	newAttrs = append(newAttrs, h.attrs...)
	newAttrs = append(newAttrs, attrs...)
	return &SentryHandler{
		next:  h.next.WithAttrs(attrs),
		attrs: newAttrs,
	}
}

func (h *SentryHandler) WithGroup(name string) slog.Handler {
	return &SentryHandler{
		next:  h.next.WithGroup(name),
		attrs: h.attrs,
	}
}

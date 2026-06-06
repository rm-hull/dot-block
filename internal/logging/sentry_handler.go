package logging

import (
	"context"
	"log/slog"

	"github.com/getsentry/sentry-go"
)

// SentryHandler wraps an existing slog.Handler and forwards logs with level ERROR or higher to Sentry.
type SentryHandler struct {
	next slog.Handler
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
		var err error
		attrs := make(map[string]any)
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "error" {
				if e, ok := a.Value.Any().(error); ok {
					err = e
				}
			}
			attrs[a.Key] = a.Value.Any()
			return true
		})

		if err != nil {
			// If we found an error attribute, capture it as an exception
			sentry.CaptureException(err)
		} else {
			// Otherwise, capture the log message
			sentry.CaptureMessage(r.Message)
		}
		
		// We can also add the attributes as extra data to the event
		// Note: sentry.CaptureException/Message are high-level. 
		// To add extra data, we'd need to use sentry.NewEvent().
		// But for most cases, this is sufficient.
	}
	return h.next.Handle(ctx, r)
}

func (h *SentryHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &SentryHandler{next: h.next.WithAttrs(attrs)}
}

func (h *SentryHandler) WithGroup(name string) slog.Handler {
	return &SentryHandler{next: h.next.WithGroup(name)}
}

package logging

import (
	"context"
	"log/slog"

	"github.com/getsentry/sentry-go"
)

// SentryHandler wraps an existing slog.Handler and forwards logs with a specific level or higher to Sentry.
type SentryHandler struct {
	next     slog.Handler
	attrs    []slog.Attr
	minLevel slog.Level
}

// NewSentryHandler creates a new SentryHandler that wraps the provided handler.
func NewSentryHandler(minLevel slog.Level, next slog.Handler) *SentryHandler {
	return &SentryHandler{
		next:     next,
		minLevel: minLevel,
	}
}

func (h *SentryHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *SentryHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= h.minLevel {
		hub := sentry.GetHubFromContext(ctx)
		if hub == nil {
			hub = sentry.CurrentHub()
		}

		hub.WithScope(func(scope *sentry.Scope) {
			scope.SetLevel(mapSlogLevel(r.Level))

			extra := h.extractAttributes(r)
			scope.SetContext("extra", extra)

			if err, ok := extra["error"].(error); ok {
				hub.CaptureException(err)
			} else {
				hub.CaptureMessage(r.Message)
			}
		})
	}
	return h.next.Handle(ctx, r)
}

func mapSlogLevel(l slog.Level) sentry.Level {
	switch {
	case l <= slog.LevelDebug:
		return sentry.LevelDebug
	case l <= slog.LevelInfo:
		return sentry.LevelInfo
	case l <= slog.LevelWarn:
		return sentry.LevelWarning
	case l <= slog.LevelError:
		return sentry.LevelError
	default:
		return sentry.LevelFatal
	}
}

// extractAttributes collects attributes from the handler and the record,
// applying consistent value processing (e.g., for time.Duration).
func (h *SentryHandler) extractAttributes(r slog.Record) map[string]any {
	extra := make(map[string]any)

	// Add accumulated attributes from the handler
	for _, a := range h.attrs {
		extra[a.Key] = processValue(a.Value.Any(), 0)
	}

	// Add record attributes
	r.Attrs(func(a slog.Attr) bool {
		extra[a.Key] = processValue(a.Value.Any(), 0)
		return true
	})

	return extra
}

func (h *SentryHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	newAttrs = append(newAttrs, h.attrs...)
	newAttrs = append(newAttrs, attrs...)
	return &SentryHandler{
		next:     h.next.WithAttrs(attrs),
		attrs:    newAttrs,
		minLevel: h.minLevel,
	}
}

func (h *SentryHandler) WithGroup(name string) slog.Handler {
	return &SentryHandler{
		next:     h.next.WithGroup(name),
		attrs:    h.attrs,
		minLevel: h.minLevel,
	}
}

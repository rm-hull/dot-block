package logging

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

// TracingHandler is a slog.Handler that adds trace_id and span_id to logs if present in the context.
type TracingHandler struct {
	next slog.Handler
}

func NewTracingHandler(next slog.Handler) *TracingHandler {
	return &TracingHandler{next: next}
}

func (h *TracingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *TracingHandler) Handle(ctx context.Context, r slog.Record) error {
	if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		r.AddAttrs(
			slog.String("trace_id", span.SpanContext().TraceID().String()),
			slog.String("span_id", span.SpanContext().SpanID().String()),
		)
	}
	return h.next.Handle(ctx, r)
}

func (h *TracingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &TracingHandler{next: h.next.WithAttrs(attrs)}
}

func (h *TracingHandler) WithGroup(name string) slog.Handler {
	return &TracingHandler{next: h.next.WithGroup(name)}
}

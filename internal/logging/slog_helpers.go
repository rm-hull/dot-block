package logging

import (
	"fmt"
	"log/slog"
)

// ReplaceAttr is a slog.HandlerOptions.ReplaceAttr function that
// extracts stack traces from errors and adds them as a separate "stack_trace" attribute.
func ReplaceAttr(_ []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindAny {
		if err, ok := a.Value.Any().(error); ok && err != nil {
			// Check if the error has a verbose representation (likely a stack trace)
			// that differs from its standard error message.
			// This works for cockroachdb/errors, pkg/errors, and others that support %+v.
			verbose := fmt.Sprintf("%+v", err)
			if verbose != err.Error() {
				return slog.Group("",
					slog.String(a.Key, err.Error()),
					slog.String("stack_trace", verbose),
				)
			}
		}
	}
	return a
}

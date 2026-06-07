package logging

import (
	"log/slog"
	"time"
)

// ReplaceAttr is a slog.HandlerOptions.ReplaceAttr function that
// recursively processes attributes to ensure time.Duration and errors are formatted correctly.
func ReplaceAttr(_ []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() != slog.KindAny {
		return a
	}

	val := a.Value.Any()
	processed := processValue(val, 0)

	return slog.Any(a.Key, processed)
}

func processValue(v any, depth int) any {
	if depth > 10 {
		return v
	}

	switch val := v.(type) {
	case time.Duration:
		return val.String()
	case error:
		return v
	case map[string]any:
		newMap := make(map[string]any, len(val))
		for k, v := range val {
			newMap[k] = processValue(v, depth+1)
		}
		return newMap
	case []any:
		newSlice := make([]any, len(val))
		for i, v := range val {
			newSlice[i] = processValue(v, depth+1)
		}
		return newSlice
	default:
		return v
	}
}

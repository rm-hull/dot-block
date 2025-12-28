package logging

import (
	"log/slog"
)

// SlogAdapter makes slog.Logger compatible with cron.Logger
type slogAdapter struct {
	logger *slog.Logger
}

func NewSlogAdapter(logger *slog.Logger, source string) *slogAdapter {
	return &slogAdapter{
		logger: logger.With(slog.String("source", source)),
	}
}

func (s *slogAdapter) Info(msg string, keysAndValues ...any) {
	s.logger.Info(msg, keysAndValues...)
}

func (s *slogAdapter) Error(err error, msg string, keysAndValues ...any) {
	// Prepend error field to keysAndValues for structured logging
	attrs := append([]any{"error", err}, keysAndValues...)
	s.logger.Error(msg, attrs...)
}

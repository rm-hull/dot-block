package logging

import (
	"log/slog"
)

// compatible with cron.Logger
type cronLoggerAdapter struct {
	logger *slog.Logger
}

func NewCronLoggerAdapter(logger *slog.Logger, source string) *cronLoggerAdapter {
	return &cronLoggerAdapter{
		logger: logger.With(slog.String("source", source)),
	}
}

func (s *cronLoggerAdapter) Info(msg string, keysAndValues ...any) {
	s.logger.Info(msg, keysAndValues...)
}

func (s *cronLoggerAdapter) Error(err error, msg string, keysAndValues ...any) {
	// Prepend error field to keysAndValues for structured logging
	attrs := append([]any{"error", err}, keysAndValues...)
	s.logger.Error(msg, attrs...)
}

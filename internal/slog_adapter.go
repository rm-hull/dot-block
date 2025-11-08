package internal

import (
	"log/slog"
)

// SlogAdapter makes slog.Logger compatible with cron.Logger
type SlogAdapter struct {
	prefix string
	logger *slog.Logger
}

func (s *SlogAdapter) Info(msg string, keysAndValues ...interface{}) {
	s.logger.Info(s.prefix+msg, keysAndValues...)
}

func (s *SlogAdapter) Error(err error, msg string, keysAndValues ...interface{}) {
	// Prepend error field to keysAndValues for structured logging
	attrs := append([]interface{}{"error", err}, keysAndValues...)
	s.logger.Error(s.prefix+msg, attrs...)
}

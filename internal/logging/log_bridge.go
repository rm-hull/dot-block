package logging

import (
	"log"
	"log/slog"
)

// slogWriter implements io.Writer to bridge standard log output to slog.
type slogWriter struct {
	logger *slog.Logger
}

func (w *slogWriter) Write(p []byte) (n int, err error) {
	// Standard log output usually includes timestamps and newlines.
	// We strip the trailing newline to avoid double-spacing in structured logs.
	msg := string(p)
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}

	w.logger.Info(msg)
	return len(p), nil
}

// BridgeStandardLog redirects the global standard log package to use the provided slog.Logger.
func BridgeStandardLog(logger *slog.Logger) {
	log.SetOutput(&slogWriter{logger: logger})
	// Remove flags because slog handles timestamps and other metadata.
	log.SetFlags(0)
}

package logging

import (
	"context"
	"log"
	"log/slog"
	"runtime"
	"time"
)

// slogWriter implements io.Writer to bridge standard log output to slog.
type slogWriter struct {
	logger *slog.Logger
}

func (w *slogWriter) Write(p []byte) (n int, err error) {
	msg := string(p)
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}
	// Skip callers to find the actual log initiator.
	// 1: runtime.Callers
	// 2: w.Write
	// 3: log.Logger.Output
	// 4: log.Printf (or similar)
	// 5: Actual caller
	var pcs [1]uintptr
	runtime.Callers(5, pcs[:])
	pc := pcs[0]
	r := slog.NewRecord(time.Now(), slog.LevelInfo, msg, pc)
	_ = w.logger.Handler().Handle(context.Background(), r)
	return len(p), nil
}

// BridgeStandardLog redirects the global standard log package to use the provided slog.Logger.
func BridgeStandardLog(logger *slog.Logger) {
	log.SetOutput(&slogWriter{logger: logger})
	// Remove flags because slog handles timestamps and other metadata.
	log.SetFlags(0)
}

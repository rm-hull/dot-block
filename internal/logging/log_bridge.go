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
	handler slog.Handler
}

func (w *slogWriter) Write(p []byte) (n int, err error) {
	msg := string(p)
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}

	// Find the caller PC.
	// The call stack is:
	// 0: runtime.Callers
	// 1: slogWriter.Write
	// 2: log.Output (standard logger)
	// 3: The actual call site (e.g. log.Println)
	var pcs [1]uintptr
	runtime.Callers(3, pcs[:])

	r := slog.NewRecord(time.Now(), slog.LevelInfo, msg, pcs[0])
	_ = w.handler.Handle(context.Background(), r)

	return len(p), nil
}

// BridgeStandardLog redirects the global standard log package to use the provided slog.Handler.
func BridgeStandardLog(handler slog.Handler) {
	log.SetOutput(&slogWriter{handler: handler})
	// Remove flags because slog handles timestamps and other metadata.
	log.SetFlags(0)
}

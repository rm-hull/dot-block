package logging

import (
	"log"
	"log/slog"
	"runtime"
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

	// Find the caller PC.
	// The call stack is:
	// 0: runtime.Callers
	// 1: slogWriter.Write
	// 2: log.Output (standard logger)
	// 3: The actual call site (e.g. log.Println)
	var pcs [1]uintptr
	runtime.Callers(3, pcs[:])

	frame, ok := runtime.CallersFrames(pcs[:]).Next()
	if !ok {
		w.logger.Info(msg)
		return len(p), nil
	}

	w.logger.Info(msg,
		"source_file", frame.File,
		"source_line", frame.Line,
	)

	return len(p), nil
}

// BridgeStandardLog redirects the global standard log package to use the provided slog.Logger.
func BridgeStandardLog(logger *slog.Logger) {
	log.SetOutput(&slogWriter{logger: logger})
	// Remove flags because slog handles timestamps and other metadata.
	log.SetFlags(0)
}

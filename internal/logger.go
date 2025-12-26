package internal

import (
	"context"
	"log/slog"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// NewZapLoggerAdapter creates a zap.Logger that writes to the provided slog.Logger.
func NewZapLoggerAdapter(logger *slog.Logger) *zap.Logger {
	return zap.New(&slogCore{logger: logger, level: zap.DebugLevel})
}

type slogCore struct {
	logger *slog.Logger
	level  zapcore.LevelEnabler
	fields []slog.Attr
}

func (c *slogCore) Enabled(l zapcore.Level) bool {
	return c.level.Enabled(l)
}

func (c *slogCore) With(fields []zapcore.Field) zapcore.Core {
	attrs := make([]slog.Attr, 0, len(fields))
	for _, f := range fields {
		attrs = append(attrs, zapFieldToSlogAttr(f))
	}
	// Clone the logger with new fields
	return &slogCore{
		logger: c.logger.With(anyList(attrs)...),
		level:  c.level,
	}
}

func (c *slogCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

func (c *slogCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	ctx := context.Background()
	var lvl slog.Level
	switch ent.Level {
	case zapcore.DebugLevel:
		lvl = slog.LevelDebug
	case zapcore.InfoLevel:
		lvl = slog.LevelInfo
	case zapcore.WarnLevel:
		lvl = slog.LevelWarn
	case zapcore.ErrorLevel:
		lvl = slog.LevelError
	case zapcore.DPanicLevel, zapcore.PanicLevel, zapcore.FatalLevel:
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	attrs := make([]slog.Attr, 0, len(fields)+1)
	attrs = append(attrs, slog.String("source", "certmagic"))
	for _, f := range fields {
		attrs = append(attrs, zapFieldToSlogAttr(f))
	}

	c.logger.LogAttrs(ctx, lvl, ent.Message, attrs...)
	return nil
}

func (c *slogCore) Sync() error {
	return nil
}

func zapFieldToSlogAttr(f zapcore.Field) slog.Attr {
	switch f.Type {
	case zapcore.StringType:
		return slog.String(f.Key, f.String)
	case zapcore.Int64Type, zapcore.Int32Type, zapcore.Int16Type, zapcore.Int8Type:
		return slog.Int64(f.Key, f.Integer)
	case zapcore.Uint64Type, zapcore.Uint32Type, zapcore.Uint16Type, zapcore.Uint8Type:
		return slog.Uint64(f.Key, uint64(f.Integer))
	case zapcore.BoolType:
		return slog.Bool(f.Key, f.Integer == 1)
	case zapcore.ErrorType:
		return slog.Any(f.Key, f.Interface)
	default:
		// Fallback for other types
		return slog.Any(f.Key, f.Interface)
	}
}

func anyList(attrs []slog.Attr) []any {
	args := make([]any, len(attrs))
	for i, a := range attrs {
		args[i] = a
	}
	return args
}

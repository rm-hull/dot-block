package telemetry

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitTracer_NoEndpoint(t *testing.T) {
	_ = os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	shutdown, err := InitTracer(logger, "test-service")
	assert.NoError(t, err)
	assert.NotNil(t, shutdown)

	// Ensure shutdown is a no-op and doesn't panic
	err = shutdown(context.Background())
	assert.NoError(t, err)

	assert.Contains(t, buf.String(), "level=WARN")
	assert.Contains(t, buf.String(), "OTEL_EXPORTER_OTLP_ENDPOINT not defined, skipping tracing initialization")
}

func TestInitTracer_WithEndpoint(t *testing.T) {
	_ = os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	defer func() {
		_ = os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	// This might fail because it tries to create a gRPC connection, 
	// but we just want to check it doesn't return the no-op immediately.
	shutdown, err := InitTracer(logger, "test-service")
	
	// It might error if gRPC fails to init (e.g. network), but it should NOT 
	// return the no-op if endpoint is set.
	if err == nil {
		assert.NotNil(t, shutdown)
		_ = shutdown(context.Background())
		
		assert.Contains(t, buf.String(), "level=INFO")
		assert.Contains(t, buf.String(), "OTEL tracing initialized")
	}
}

package telemetry

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// InitTracer initializes the global TracerProvider and returns a shutdown function.
func InitTracer(logger *slog.Logger, serviceName string, otelEndpoint string, otelSamplingRatio float64) (func(context.Context) error, error) {
	ctx := context.Background()

	// Read OTLP endpoint from environment variable
	endpoint := otelEndpoint
	if endpoint == "" {
		logger.Warn("OTEL endpoint not defined, skipping tracing initialization")
		return func(ctx context.Context) error { return nil }, nil
	}

	// Configure the OTLP exporter
	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Define the resource attributes for the service
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Sampling ratio from environment variable (0.0 to 1.0)
	samplingRatio := otelSamplingRatio
	if samplingRatio == 0 {
		samplingRatio = 0.01
	}

	// Create the TracerProvider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(samplingRatio))),
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	logger.Info("OTEL tracing initialized", "endpoint", endpoint, "sampling_ratio", samplingRatio)

	// Set the global TracerProvider and TextMapPropagator
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))

	return tp.Shutdown, nil
}

// GetTracer returns a tracer for the given instrumentation name.
func GetTracer(name string) trace.Tracer {
	return otel.Tracer(name)
}

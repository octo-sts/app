// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	prombridge "go.opentelemetry.io/contrib/bridges/prometheus"
	gcpdetector "go.opentelemetry.io/contrib/detectors/gcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otellogglobal "go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const instrumentationName = "github.com/octo-sts/app"

type protocol string

const (
	protocolHTTP protocol = "http/protobuf"
	protocolGRPC protocol = "grpc"
)

type exporterMode int

const (
	exporterUnspecified exporterMode = iota
	exporterNone
	exporterOTLP
	exporterLegacyTrace
)

// Setup wires canonical OpenTelemetry exporters requested through OTEL_* env vars.
// When traces are not explicitly configured here, callers can keep using the
// existing Chainguard/GCP trace setup unchanged.
type Setup struct {
	useLegacyTracer bool
	cleanups        []func(context.Context) error
}

func NewSetup(ctx context.Context) (_ *Setup, err error) {
	setup := &Setup{useLegacyTracer: true}
	defer func() {
		if err != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = errors.Join(err, setup.Shutdown(shutdownCtx))
		}
	}()

	logs, err := signalMode("LOGS")
	if err != nil {
		return nil, err
	}
	metrics, err := signalMode("METRICS")
	if err != nil {
		return nil, err
	}
	traces, err := traceMode()
	if err != nil {
		return nil, err
	}

	if logs != exporterOTLP && metrics != exporterOTLP && traces != exporterOTLP {
		setup.useLegacyTracer = traces != exporterNone
		return setup, nil
	}

	res, err := buildResource(ctx)
	if err != nil {
		return nil, err
	}

	if logs == exporterOTLP {
		if err := setupLogs(ctx, setup, res); err != nil {
			return nil, err
		}
	}

	if metrics == exporterOTLP {
		if err := setupMetrics(ctx, setup, res); err != nil {
			return nil, err
		}
	}

	switch traces {
	case exporterOTLP:
		setup.useLegacyTracer = false
		if err := setupTraces(ctx, setup, res); err != nil {
			return nil, err
		}
	case exporterNone:
		setup.useLegacyTracer = false
	case exporterLegacyTrace, exporterUnspecified:
		setup.useLegacyTracer = true
	}

	return setup, nil
}

func (s *Setup) UseLegacyTracer() bool {
	return s.useLegacyTracer
}

func (s *Setup) Shutdown(ctx context.Context) error {
	var err error
	for i := len(s.cleanups) - 1; i >= 0; i-- {
		err = errors.Join(err, s.cleanups[i](ctx))
	}
	return err
}

func signalMode(signal string) (exporterMode, error) {
	raw, ok := os.LookupEnv("OTEL_" + signal + "_EXPORTER")
	if ok {
		entries := splitExporterList(raw)
		if len(entries) > 0 {
			if len(entries) == 1 && entries[0] == "none" {
				return exporterNone, nil
			}
			for _, entry := range entries {
				if entry != "otlp" {
					return exporterUnspecified, fmt.Errorf("unsupported OTEL_%s_EXPORTER value %q", signal, entry)
				}
			}
			return exporterOTLP, nil
		}
	}

	return exporterUnspecified, nil
}

func traceMode() (exporterMode, error) {
	raw, ok := os.LookupEnv("OTEL_TRACES_EXPORTER")
	if ok {
		entries := splitExporterList(raw)
		if len(entries) > 0 {
			if len(entries) == 1 {
				switch entries[0] {
				case "none":
					return exporterNone, nil
				case "otlp":
					return exporterOTLP, nil
				case "gcp":
					return exporterLegacyTrace, nil
				}
			}

			hasOTLP := false
			for _, entry := range entries {
				switch entry {
				case "otlp":
					hasOTLP = true
				case "none":
					return exporterUnspecified, fmt.Errorf("OTEL_TRACES_EXPORTER=none cannot be combined with other exporters")
				case "gcp":
					return exporterUnspecified, fmt.Errorf("OTEL_TRACES_EXPORTER=gcp cannot be combined with app-local OTLP export")
				default:
					return exporterUnspecified, fmt.Errorf("unsupported OTEL_TRACES_EXPORTER value %q", entry)
				}
			}
			if hasOTLP {
				return exporterOTLP, nil
			}
		}
	}

	return exporterUnspecified, nil
}

func splitExporterList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.ToLower(strings.TrimSpace(part)); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func otlpProtocol(signal string) (protocol, error) {
	raw := os.Getenv("OTEL_EXPORTER_OTLP_" + signal + "_PROTOCOL")
	if raw == "" {
		raw = os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(protocolHTTP):
		return protocolHTTP, nil
	case string(protocolGRPC):
		return protocolGRPC, nil
	default:
		return "", fmt.Errorf("unsupported OTEL_EXPORTER_OTLP_%s_PROTOCOL value %q", signal, raw)
	}
}

func setupLogs(ctx context.Context, setup *Setup, res *resource.Resource) error {
	p, err := otlpProtocol("LOGS")
	if err != nil {
		return err
	}
	exporter, err := newLogExporter(ctx, p)
	if err != nil {
		return fmt.Errorf("create OTLP log exporter: %w", err)
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
	)
	oldProvider := otellogglobal.GetLoggerProvider()
	otellogglobal.SetLoggerProvider(provider)

	oldDefault := slog.Default()
	oldLogWriter := log.Writer()
	otelHandler := otelslog.NewHandler(instrumentationName, otelslog.WithLoggerProvider(provider))
	slog.SetDefault(slog.New(fanoutHandler{handlers: []slog.Handler{oldDefault.Handler(), otelHandler}}))
	log.SetOutput(stdlibLogWriter{out: oldLogWriter, logger: slog.New(otelHandler)})

	setup.cleanups = append(setup.cleanups, func(ctx context.Context) error {
		slog.SetDefault(oldDefault)
		log.SetOutput(oldLogWriter)
		otellogglobal.SetLoggerProvider(oldProvider)
		return provider.Shutdown(ctx)
	})
	return nil
}

func setupMetrics(ctx context.Context, setup *Setup, res *resource.Resource) error {
	p, err := otlpProtocol("METRICS")
	if err != nil {
		return err
	}
	exporter, err := newMetricExporter(ctx, p)
	if err != nil {
		return fmt.Errorf("create OTLP metric exporter: %w", err)
	}

	reader := sdkmetric.NewPeriodicReader(exporter,
		sdkmetric.WithProducer(prombridge.NewMetricProducer(prombridge.WithGatherer(prometheus.DefaultGatherer))),
	)
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(reader),
	)
	oldProvider := otel.GetMeterProvider()
	otel.SetMeterProvider(provider)

	setup.cleanups = append(setup.cleanups, func(ctx context.Context) error {
		otel.SetMeterProvider(oldProvider)
		return provider.Shutdown(ctx)
	})
	return nil
}

func setupTraces(ctx context.Context, setup *Setup, res *resource.Resource) error {
	p, err := otlpProtocol("TRACES")
	if err != nil {
		return err
	}
	exporter, err := newTraceExporter(ctx, p)
	if err != nil {
		return fmt.Errorf("create OTLP trace exporter: %w", err)
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
		sdktrace.WithSpanProcessor(sdktrace.NewBatchSpanProcessor(exporter)),
	)
	oldProvider := otel.GetTracerProvider()
	oldPropagator := otel.GetTextMapPropagator()
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(newTextMapPropagator())

	setup.cleanups = append(setup.cleanups, func(ctx context.Context) error {
		otel.SetTracerProvider(oldProvider)
		otel.SetTextMapPropagator(oldPropagator)
		return provider.Shutdown(ctx)
	})
	return nil
}

func newLogExporter(ctx context.Context, p protocol) (sdklog.Exporter, error) {
	switch p {
	case protocolHTTP:
		return otlploghttp.New(ctx)
	case protocolGRPC:
		return otlploggrpc.New(ctx)
	default:
		return nil, fmt.Errorf("unsupported log protocol %q", p)
	}
}

func newMetricExporter(ctx context.Context, p protocol) (sdkmetric.Exporter, error) {
	switch p {
	case protocolHTTP:
		return otlpmetrichttp.New(ctx)
	case protocolGRPC:
		return otlpmetricgrpc.New(ctx)
	default:
		return nil, fmt.Errorf("unsupported metric protocol %q", p)
	}
}

func newTraceExporter(ctx context.Context, p protocol) (sdktrace.SpanExporter, error) {
	switch p {
	case protocolHTTP:
		return otlptracehttp.New(ctx)
	case protocolGRPC:
		return otlptracegrpc.New(ctx)
	default:
		return nil, fmt.Errorf("unsupported trace protocol %q", p)
	}
}

func buildResource(ctx context.Context) (*resource.Resource, error) {
	resOpts := []resource.Option{
		resource.WithTelemetrySDK(),
		resource.WithFromEnv(),
	}
	if isGCP(ctx) {
		resOpts = append(resOpts, resource.WithDetectors(gcpdetector.NewDetector()))
	}
	if serviceName := os.Getenv("K_SERVICE"); serviceName != "" && !hasConfiguredServiceName() {
		resOpts = append(resOpts, resource.WithAttributes(attribute.String("service.name", serviceName)))
	}
	return resource.New(ctx, resOpts...)
}

func isGCP(ctx context.Context) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	projectID, _ := metadata.ProjectIDWithContext(probeCtx)
	return projectID != ""
}

func hasConfiguredServiceName() bool {
	if os.Getenv("OTEL_SERVICE_NAME") != "" {
		return true
	}
	for _, attr := range strings.Split(os.Getenv("OTEL_RESOURCE_ATTRIBUTES"), ",") {
		key, _, ok := strings.Cut(strings.TrimSpace(attr), "=")
		if ok && strings.TrimSpace(key) == "service.name" {
			return true
		}
	}
	return false
}

func newTextMapPropagator() propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
}

type fanoutHandler struct {
	handlers []slog.Handler
}

func (h fanoutHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (h fanoutHandler) Handle(ctx context.Context, record slog.Record) error {
	var err error
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, record.Level) {
			err = errors.Join(err, handler.Handle(ctx, record.Clone()))
		}
	}
	return err
}

func (h fanoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := fanoutHandler{handlers: make([]slog.Handler, len(h.handlers))}
	for i, handler := range h.handlers {
		out.handlers[i] = handler.WithAttrs(attrs)
	}
	return out
}

func (h fanoutHandler) WithGroup(name string) slog.Handler {
	out := fanoutHandler{handlers: make([]slog.Handler, len(h.handlers))}
	for i, handler := range h.handlers {
		out.handlers[i] = handler.WithGroup(name)
	}
	return out
}

type stdlibLogWriter struct {
	out    io.Writer
	logger *slog.Logger
}

func (w stdlibLogWriter) Write(p []byte) (int, error) {
	n, err := w.out.Write(p)
	if msg := strings.TrimRight(string(p), "\r\n"); msg != "" {
		w.logger.Info(msg)
	}
	return n, err
}

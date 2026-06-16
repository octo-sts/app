// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"bytes"
	"context"
	"io"
	stdlog "log"
	"log/slog"
	"sync"
	"testing"

	"go.opentelemetry.io/otel"
	otellogglobal "go.opentelemetry.io/otel/log/global"
	lognoop "go.opentelemetry.io/otel/log/noop"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

func TestSignalMode(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		want    exporterMode
		wantErr bool
	}{
		{
			name: "unset",
			want: exporterUnspecified,
		},
		{
			name: "signal exporter otlp",
			env:  map[string]string{"OTEL_METRICS_EXPORTER": "otlp"},
			want: exporterOTLP,
		},
		{
			name: "signal exporter none overrides endpoint",
			env: map[string]string{
				"OTEL_METRICS_EXPORTER":          "none",
				"OTEL_EXPORTER_OTLP_ENDPOINT":    "http://collector:4318",
				"OTEL_EXPORTER_OTLP_PROTOCOL":    "http/protobuf",
				"OTEL_EXPORTER_OTLP_INSECURE":    "true",
				"OTEL_RESOURCE_ATTRIBUTES":       "service.namespace=test",
				"OTEL_EXPORTER_OTLP_COMPRESSION": "gzip",
			},
			want: exporterNone,
		},
		{
			name: "signal endpoint alone does not activate otlp",
			env:  map[string]string{"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://collector:4318/v1/metrics"},
			want: exporterUnspecified,
		},
		{
			name: "global endpoint alone does not activate otlp",
			env:  map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318"},
			want: exporterUnspecified,
		},
		{
			name:    "unsupported exporter",
			env:     map[string]string{"OTEL_METRICS_EXPORTER": "console"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearOTEL(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			got, err := signalMode("METRICS")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("signalMode() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("signalMode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTraceMode(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		want    exporterMode
		wantErr bool
	}{
		{
			name: "unset uses legacy helper",
			want: exporterUnspecified,
		},
		{
			name: "otlp",
			env:  map[string]string{"OTEL_TRACES_EXPORTER": "otlp"},
			want: exporterOTLP,
		},
		{
			name: "none",
			env:  map[string]string{"OTEL_TRACES_EXPORTER": "none"},
			want: exporterNone,
		},
		{
			name: "gcp keeps legacy helper",
			env:  map[string]string{"OTEL_TRACES_EXPORTER": "gcp"},
			want: exporterLegacyTrace,
		},
		{
			name: "trace endpoint alone does not activate otlp",
			env:  map[string]string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://collector:4318/v1/traces"},
			want: exporterUnspecified,
		},
		{
			name:    "gcp and otlp is unsupported app-local fanout",
			env:     map[string]string{"OTEL_TRACES_EXPORTER": "gcp,otlp"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearOTEL(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			got, err := traceMode()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("traceMode() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("traceMode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOTLPProtocol(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		want    protocol
		wantErr bool
	}{
		{
			name: "default http protobuf",
			want: protocolHTTP,
		},
		{
			name: "global grpc",
			env:  map[string]string{"OTEL_EXPORTER_OTLP_PROTOCOL": "grpc"},
			want: protocolGRPC,
		},
		{
			name: "signal overrides global",
			env: map[string]string{
				"OTEL_EXPORTER_OTLP_PROTOCOL":         "grpc",
				"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL": "http/protobuf",
			},
			want: protocolHTTP,
		},
		{
			name:    "unsupported",
			env:     map[string]string{"OTEL_EXPORTER_OTLP_PROTOCOL": "http/json"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearOTEL(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			got, err := otlpProtocol("METRICS")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("otlpProtocol() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("otlpProtocol() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewSetupRollsBackLogsOnLaterError(t *testing.T) {
	clearOTEL(t)
	t.Setenv("OTEL_LOGS_EXPORTER", "otlp")
	t.Setenv("OTEL_METRICS_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL", "http/json")

	oldDefault := slog.Default()
	oldWriter := stdlog.Writer()
	oldProvider := otellogglobal.GetLoggerProvider()
	baselineLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	baselineWriter := &bytes.Buffer{}
	baselineProvider := lognoop.NewLoggerProvider()
	slog.SetDefault(baselineLogger)
	stdlog.SetOutput(baselineWriter)
	otellogglobal.SetLoggerProvider(baselineProvider)
	t.Cleanup(func() {
		slog.SetDefault(oldDefault)
		stdlog.SetOutput(oldWriter)
		otellogglobal.SetLoggerProvider(oldProvider)
	})

	if _, err := NewSetup(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	if got := slog.Default(); got != baselineLogger {
		t.Fatal("slog default was not restored")
	}
	if got := stdlog.Writer(); got != baselineWriter {
		t.Fatalf("standard log writer was not restored: got %T, want %T", got, baselineWriter)
	}
	if got := otellogglobal.GetLoggerProvider(); got != baselineProvider {
		t.Fatal("OTEL log provider was not restored")
	}
}

func TestNewSetupRollsBackMetricsOnLaterError(t *testing.T) {
	clearOTEL(t)
	t.Setenv("OTEL_METRICS_EXPORTER", "otlp")
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "http/json")

	oldProvider := otel.GetMeterProvider()
	baselineProvider := metricnoop.NewMeterProvider()
	otel.SetMeterProvider(baselineProvider)
	t.Cleanup(func() {
		otel.SetMeterProvider(oldProvider)
	})

	if _, err := NewSetup(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	if got := otel.GetMeterProvider(); got != baselineProvider {
		t.Fatal("OTEL meter provider was not restored")
	}
}

// capturingLogExporter records the body of every exported log record.
type capturingLogExporter struct {
	mu     sync.Mutex
	bodies []string
}

func (e *capturingLogExporter) Export(_ context.Context, records []sdklog.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range records {
		e.bodies = append(e.bodies, r.Body().String())
	}
	return nil
}

func (e *capturingLogExporter) Shutdown(context.Context) error   { return nil }
func (e *capturingLogExporter) ForceFlush(context.Context) error { return nil }

func (e *capturingLogExporter) snapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.bodies...)
}

// TestInstallLogBridgesDoesNotDoubleExport guards the fix for slog records
// being exported twice: once structured via the otelslog handler and once as a
// preformatted line via the slog->stdlib-log->OTEL path.
func TestInstallLogBridgesDoesNotDoubleExport(t *testing.T) {
	// Discard console output; restored by setup.Shutdown via t.Cleanup.
	stdlog.SetOutput(io.Discard)

	exp := &capturingLogExporter{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(exp)))

	setup := &Setup{}
	installLogBridges(setup, provider)
	t.Cleanup(func() { _ = setup.Shutdown(context.Background()) })

	slog.Info("structured message", "answer", 42)
	stdlog.Print("stdlib message")

	bodies := exp.snapshot()
	if len(bodies) != 2 {
		t.Fatalf("expected exactly 2 exported log records, got %d: %v", len(bodies), bodies)
	}

	counts := map[string]int{}
	for _, b := range bodies {
		counts[b]++
	}
	if counts["structured message"] != 1 {
		t.Fatalf("want exactly one structured slog record, got %d: %v", counts["structured message"], bodies)
	}
	if counts["stdlib message"] != 1 {
		t.Fatalf("want exactly one stdlib log record, got %d: %v", counts["stdlib message"], bodies)
	}
}

func clearOTEL(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"OTEL_TRACES_EXPORTER",
		"OTEL_METRICS_EXPORTER",
		"OTEL_LOGS_EXPORTER",
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_PROTOCOL",
		"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
		"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL",
		"OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
		"OTEL_RESOURCE_ATTRIBUTES",
		"OTEL_SERVICE_NAME",
		"K_SERVICE",
	} {
		t.Setenv(key, "")
	}
}

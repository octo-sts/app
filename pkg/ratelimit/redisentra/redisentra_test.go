// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package redisentra

import (
	"crypto/tls"
	"errors"
	"strings"
	"testing"
)

func TestOptionsRejectsEmptyAddress(t *testing.T) {
	if _, err := Options(""); !errors.Is(err, ErrNoAddress) {
		t.Errorf("error = %v, want ErrNoAddress", err)
	}
}

// A bare hostname is a plausible operator mistake, and must be rejected rather
// than producing a client that dials the wrong port.
func TestOptionsRejectsAddressWithoutPort(t *testing.T) {
	_, err := Options("cache.example.redis.azure.net")
	if err == nil {
		t.Fatal("expected an error for an address without a port, got nil")
	}
	if !strings.Contains(err.Error(), "host:port") {
		t.Errorf("error = %q, want it to state the host:port requirement", err)
	}
}

// Entra ID authentication is only valid over TLS, and the ServerName must be
// the bare host so certificate verification succeeds.
func TestOptionsRequiresTLSWithServerName(t *testing.T) {
	const host = "cache.example.redis.azure.net"

	opts, err := Options(host + ":10000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if opts.TLSConfig == nil {
		t.Fatal("TLSConfig is nil, want TLS required for Entra ID auth")
	}
	if got := opts.TLSConfig.ServerName; got != host {
		t.Errorf("ServerName = %q, want %q", got, host)
	}
	if got := opts.TLSConfig.MinVersion; got < tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want at least TLS 1.2", got)
	}
}

// The provider derives the username from the token's oid claim. Setting one
// here would override it and break authentication.
func TestOptionsSetsCredentialsProviderAndNoUsername(t *testing.T) {
	opts, err := Options("cache.example.redis.azure.net:10000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if opts.StreamingCredentialsProvider == nil {
		t.Error("StreamingCredentialsProvider is nil, want the Entra ID provider")
	}
	if opts.Username != "" {
		t.Errorf("Username = %q, want empty so the provider can supply it", opts.Username)
	}
	if opts.Password != "" {
		t.Error("Password is set, want empty for token-based auth")
	}
}

func TestNewClientRejectsBadAddress(t *testing.T) {
	if _, err := NewClient(""); !errors.Is(err, ErrNoAddress) {
		t.Errorf("error = %v, want ErrNoAddress", err)
	}
}

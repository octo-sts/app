// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package maxsize

import (
	"context"
	"net/http"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
)

func TestCompile(t *testing.T) {
	tests := []struct {
		name    string
		size    int64
		wantErr bool
	}{{
		name:    "large size",
		size:    1000000, // 1M bytes
		wantErr: false,
	}, {
		name:    "medium size",
		size:    10000, // 10000 bytes
		wantErr: false,
	}, {
		name:    "tiny size",
		size:    10, // 10 bytes
		wantErr: true,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := oidc.ClientContext(context.Background(), &http.Client{
				Transport: NewRoundTripper(tt.size, http.DefaultTransport),
			})
			for _, issuer := range []string{
				"https://accounts.google.com",
				"https://token.actions.githubusercontent.com",
				"https://issuer.enforce.dev",
			} {
				if _, err := oidc.NewProvider(ctx, issuer); (err != nil) != tt.wantErr {
					t.Errorf("constructing %q provider: %v", issuer, err)
				}
			}
		})
	}
}

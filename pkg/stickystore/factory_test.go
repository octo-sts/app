// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package stickystore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/octo-sts/app/pkg/envconfig"
)

// isolateAWSConfig keeps the developer's or CI's AWS settings out of
// LoadDefaultConfig, so only the region the test sets can be resolved.
func isolateAWSConfig(t *testing.T) {
	t.Helper()
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", empty)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", empty)
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

func TestNewDynamodb(t *testing.T) {
	tests := []struct {
		name    string
		table   string
		region  string
		wantErr string
	}{{
		name:   "table and region",
		table:  "sticky-routes",
		region: "us-east-1",
	}, {
		name:    "missing table",
		region:  "us-east-1",
		wantErr: "OCTOSTS_STICKY_STORE_DYNAMODB_TABLE must be set",
	}, {
		name:    "no region resolved",
		table:   "sticky-routes",
		wantErr: "no AWS region resolved",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateAWSConfig(t)
			t.Setenv("AWS_REGION", tt.region)

			store, closer, err := New(t.Context(), &envconfig.EnvConfig{
				StickyStore:              "dynamodb",
				StickyStoreDynamodbTable: tt.table,
				StickyStoreDynamodbTTL:   time.Hour,
			})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("New() = %v, want error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("New() = %v, want nil", err)
			}
			if store == nil || closer == nil {
				t.Fatalf("New() = (%v, %v), want a store and a closer", store, closer)
			}
		})
	}
}

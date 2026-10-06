// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/octo-sts/app/pkg/envconfig"
)

func TestBuildRouterAppMembership(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "app.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	t.Run("YAML keeps membership in the selected pool", func(t *testing.T) {
		config := fmt.Sprintf(`orgs:
  - name: Org-A
    apps:
      - app_id: 101
        app_name: ci-a
        private_key_file: %[1]q
      - app_id: 201
        app_name: deploy
        private_key_file: %[1]q
  - name: Org-B
    apps:
      - app_id: 102
        app_name: ci-b
        private_key_file: %[1]q
  - name: "*"
    apps:
      - app_id: 301
        app_name: ci-fallback
        private_key_file: %[1]q
`, keyPath)
		configPath := filepath.Join(t.TempDir(), "apps.yaml")
		if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		router, total, apps, closers, err := buildRouterFromYAML(t.Context(), &envconfig.EnvConfig{AppConfigFile: configPath}, nil, nil)
		for _, closer := range closers {
			t.Cleanup(func() { _ = closer.Close() })
		}
		if err != nil {
			t.Fatal(err)
		}
		if total != 4 {
			t.Errorf("total apps = %d, want 4", total)
		}
		if want := map[string]int64{"ci-a": 101, "ci-b": 102, "deploy": 201, "ci-fallback": 301}; !maps.Equal(apps.Names, want) {
			t.Errorf("global app names = %v, want %v", apps.Names, want)
		}
		for owner, want := range map[string]map[int64]bool{
			"ORG-A":       {101: true, 201: true},
			"org-b":       {102: true},
			"another-org": {301: true},
		} {
			pool, err := router.GetPool(owner)
			if err != nil {
				t.Fatal(err)
			}
			if !maps.Equal(pool.AppIDs, want) || pool.AppCount != len(want) {
				t.Errorf("pool for %q = (%v, %d apps), want (%v, %d apps)", owner, pool.AppIDs, pool.AppCount, want, len(want))
			}
		}
	})

	t.Run("legacy environment retains all wildcard apps", func(t *testing.T) {
		cfg := &envconfig.EnvConfig{AppIDs: []int64{101, 102}, AppSecretCertificateFile: keyPath}
		router, total, apps, closers, err := buildRouterFromEnv(t.Context(), cfg, nil, nil)
		for _, closer := range closers {
			t.Cleanup(func() { _ = closer.Close() })
		}
		if err != nil {
			t.Fatal(err)
		}
		pool, err := router.GetPool("any-org")
		if err != nil {
			t.Fatal(err)
		}
		want := map[int64]bool{101: true, 102: true}
		if !maps.Equal(pool.AppIDs, want) || !maps.Equal(apps.IDs, want) || total != len(want) {
			t.Errorf("pool IDs = %v, global IDs = %v, total = %d; want %v and total %d", pool.AppIDs, apps.IDs, total, want, len(want))
		}
	})
}

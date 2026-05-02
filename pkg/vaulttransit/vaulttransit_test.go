// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package vaulttransit

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

// fakeVault is a minimal HTTP stand-in for Vault that handles the two
// endpoints the signer uses: auth/jwt/login and transit/<mount>/sign/<key>.
// It signs with a real in-memory RSA key so the test can verify the JWT.
type fakeVault struct {
	priv *rsa.PrivateKey

	loginCalls int
	signCalls  int
}

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return &fakeVault{priv: priv}
}

func (f *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/v1/auth/jwt/login"):
		f.loginCalls++
		var in struct {
			Role string `json:"role"`
			JWT  string `json:"jwt"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if in.Role == "" || in.JWT == "" {
			http.Error(w, "missing role or jwt", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{
				"client_token":   "fake-client-token",
				"lease_duration": 3600,
			},
		})

	case strings.Contains(r.URL.Path, "/sign/"):
		f.signCalls++
		if r.Header.Get("X-Vault-Token") != "fake-client-token" {
			http.Error(w, "missing token", 403)
			return
		}
		var in struct {
			Input              string `json:"input"`
			Prehashed          bool   `json:"prehashed"`
			HashAlgorithm      string `json:"hash_algorithm"`
			SignatureAlgorithm string `json:"signature_algorithm"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if !in.Prehashed || in.HashAlgorithm != "sha2-256" || in.SignatureAlgorithm != "pkcs1v15" {
			http.Error(w, "unexpected sign params", 400)
			return
		}
		digest, err := base64.StdEncoding.DecodeString(in.Input)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		sig, err := rsa.SignPKCS1v15(rand.Reader, f.priv, crypto.SHA256, digest)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(sig),
			},
		})

	default:
		http.NotFound(w, r)
	}
}

// pubPEM returns the PEM-encoded SubjectPublicKeyInfo for the fake key.
// Useful if a future test wants to verify the JWT against a known-public key.
func (f *fakeVault) pubPEM(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&f.priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func writeTokenFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte("fake-sa-jwt"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	return p
}

func TestSignRoundTrip(t *testing.T) {
	fv := newFakeVault(t)
	srv := httptest.NewServer(fv)
	defer srv.Close()

	ctx := context.Background()
	tokenPath := writeTokenFile(t)

	signer, err := New(ctx, Config{
		Addr:         srv.URL,
		Role:         "octosts-poc",
		JWTPath:      tokenPath,
		TransitMount: "transit/octosts",
		TransitKey:   "github-app-jfrantz-cw-poc",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if fv.loginCalls != 1 {
		t.Fatalf("expected eager login, got %d", fv.loginCalls)
	}

	tokenStr, err := signer.Sign(jwt.RegisteredClaims{Subject: "test", Issuer: "octosts"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if fv.signCalls != 1 {
		t.Fatalf("expected one sign call, got %d", fv.signCalls)
	}

	parsed, err := jwt.Parse(tokenStr, func(_ *jwt.Token) (interface{}, error) {
		return &fv.priv.PublicKey, nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("returned JWT did not validate: err=%v valid=%v", err, parsed.Valid)
	}
	if parsed.Method.Alg() != "RS256" {
		t.Fatalf("unexpected alg: %s", parsed.Method.Alg())
	}

	// Sanity: the digest fakeVault received was actually SHA-256 of header.payload.
	parts := strings.Split(tokenStr, ".")
	want := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	_ = want // already validated transitively via jwt.Parse, kept for readability
}

func TestNewMissingFields(t *testing.T) {
	_, err := New(context.Background(), Config{})
	if err == nil {
		t.Fatal("expected error for empty Config")
	}
}

func TestSignErrorPropagation(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/jwt/login", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "fake-client-token", "lease_duration": 3600},
		})
	})
	mux.HandleFunc("/v1/transit/octosts/sign/k", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "transit key permission denied", http.StatusForbidden)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	signer, err := New(context.Background(), Config{
		Addr:         srv.URL,
		Role:         "r",
		JWTPath:      writeTokenFile(t),
		TransitMount: "transit/octosts",
		TransitKey:   "k",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = signer.Sign(jwt.RegisteredClaims{Subject: "x"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403 error, got %v", err)
	}
}

// silence unused warning for pubPEM helper kept for future verification tests.
var _ = (*fakeVault)(nil).pubPEM

// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package vaulttransit signs GitHub App JWTs using a private key held in
// HashiCorp Vault Transit. The private key never leaves Vault: callers send
// the SHA-256 digest of the JWT signing string and Vault returns the
// RSA-PKCS1v15 signature.
//
// Authentication uses Vault's JWT auth method, intended to be paired with a
// Kubernetes-projected ServiceAccount token mounted into the pod. The token
// at JWTPath is exchanged for a short-lived Vault client token, which is
// cached in-memory and refreshed near expiry.
package vaulttransit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/golang-jwt/jwt/v4"
)

// Config selects which Vault Transit key to sign with.
type Config struct {
	Addr         string // e.g. https://vault.example.com
	Role         string // JWT auth role
	JWTPath      string // path to the projected ServiceAccount token file
	TransitMount string // e.g. transit/octosts
	TransitKey   string // key name within the mount

	// HTTPClient is optional. If nil, a client with a 10s timeout is used.
	HTTPClient *http.Client
}

// Signer implements ghinstallation.Signer by delegating signature operations
// to Vault Transit.
type Signer struct {
	httpClient *http.Client
	addr       string
	role       string
	jwtPath    string
	signPath   string

	mu          sync.Mutex
	clientToken string
	tokenExp    time.Time
}

// New constructs a Signer and performs an initial JWT-auth login so that
// configuration errors surface at startup rather than at first sign.
func New(ctx context.Context, c Config) (ghinstallation.Signer, error) {
	if c.Addr == "" || c.Role == "" || c.JWTPath == "" || c.TransitMount == "" || c.TransitKey == "" {
		return nil, errors.New("vaulttransit: Addr, Role, JWTPath, TransitMount, and TransitKey are all required")
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	s := &Signer{
		httpClient: hc,
		addr:       strings.TrimRight(c.Addr, "/"),
		role:       c.Role,
		jwtPath:    c.JWTPath,
		signPath:   fmt.Sprintf("/v1/%s/sign/%s", strings.Trim(c.TransitMount, "/"), c.TransitKey),
	}
	if err := s.refreshToken(ctx); err != nil {
		return nil, fmt.Errorf("vaulttransit: initial login: %w", err)
	}
	return s, nil
}

// Sign produces a signed JWT string for the given claims, matching the
// ghinstallation.Signer contract used by gcpkms.
func (s *Signer) Sign(claims jwt.Claims) (string, error) {
	method := &signingMethod{s: s}
	return jwt.NewWithClaims(method, claims).SignedString(nil)
}

type signingMethod struct {
	s *Signer
}

func (m *signingMethod) Alg() string                              { return "RS256" }
func (m *signingMethod) Verify(string, string, interface{}) error { return errors.New("vaulttransit: verify not implemented") }

func (m *signingMethod) Sign(signingString string, _ interface{}) (string, error) {
	digest := sha256.Sum256([]byte(signingString))
	sig, err := m.s.transitSign(context.Background(), digest[:])
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func (s *Signer) transitSign(ctx context.Context, digest []byte) ([]byte, error) {
	body, err := json.Marshal(map[string]any{
		"input":               base64.StdEncoding.EncodeToString(digest),
		"prehashed":           true,
		"hash_algorithm":      "sha2-256",
		"signature_algorithm": "pkcs1v15",
	})
	if err != nil {
		return nil, err
	}
	tok, err := s.token(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.addr+s.signPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", tok)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		// Token may have been revoked or lease expired before our cached TTL —
		// drop the cached token so the next call re-logs-in.
		s.mu.Lock()
		s.clientToken = ""
		s.tokenExp = time.Time{}
		s.mu.Unlock()
	}
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("vaulttransit: sign HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var out struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("vaulttransit: decode sign response: %w", err)
	}
	const prefix = "vault:v1:"
	if !strings.HasPrefix(out.Data.Signature, prefix) {
		return nil, fmt.Errorf("vaulttransit: unexpected signature format %q", out.Data.Signature)
	}
	return base64.StdEncoding.DecodeString(out.Data.Signature[len(prefix):])
}

func (s *Signer) token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-auth 30s before lease expiry to avoid a forbidden-then-retry round trip.
	if s.clientToken != "" && time.Now().Before(s.tokenExp.Add(-30*time.Second)) {
		return s.clientToken, nil
	}
	if err := s.refreshTokenLocked(ctx); err != nil {
		return "", err
	}
	return s.clientToken, nil
}

func (s *Signer) refreshToken(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshTokenLocked(ctx)
}

func (s *Signer) refreshTokenLocked(ctx context.Context) error {
	jwtBytes, err := os.ReadFile(s.jwtPath)
	if err != nil {
		return fmt.Errorf("read service account token at %q: %w", s.jwtPath, err)
	}
	body, err := json.Marshal(map[string]any{
		"role": s.role,
		"jwt":  strings.TrimSpace(string(jwtBytes)),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.addr+"/v1/auth/jwt/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vaulttransit: jwt login HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if out.Auth.ClientToken == "" {
		return errors.New("vaulttransit: empty client_token in login response")
	}
	s.clientToken = out.Auth.ClientToken
	if out.Auth.LeaseDuration > 0 {
		s.tokenExp = time.Now().Add(time.Duration(out.Auth.LeaseDuration) * time.Second)
	} else {
		// Vault should always return a non-zero lease for JWT auth, but pick
		// a conservative ceiling if not so we never cache forever.
		s.tokenExp = time.Now().Add(1 * time.Hour)
	}
	return nil
}

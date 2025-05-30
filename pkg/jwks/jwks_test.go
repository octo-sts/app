// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package jwks_test

import (
	"context"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/octo-sts/app/pkg/jwks"
)

func TestNewVerifier(t *testing.T) {
	// This is a JWKS from a kind Kubernetes cluster.
	const rawJWKS = `{
  "keys": [
    {
      "use": "sig",
      "kty": "RSA",
      "kid": "LHVGP8kqzN1MuKRMTsroIcR-7hdicXWdpaquEWcAh9Q",
      "alg": "RS256",
      "n": "s5XuFpodwhj6my_gTUHDKbHmQIx-3Tf40OduMZRWlU6_B_nSdjX01kS1UQSGw_G5eVQARooI-tY1vj3bBwn4dEEFa2TlnNnAJca0hj2Izef8A8Uw-mT0fgGI4Hs3xS84Mn_WXNlKXEiPLiFyOGNr0GQBKZDyTps8JUlvnwuWCv1gkzudUHa8B0i8ITSEUclK9_LqZj4zXUAN0Wj_4DVfI_PQ0IHci9K5Q9bgCV0j1EvTsyrwGyLFwyhktUmNhjREAfgYmxvbIRhPSP4YuO2Et1KM7YmjA75cQ9oE3i-QLrOZDripyMRop5RmWttQCEdEWLQWPzBd7aZ5CLbmZuIlIQ",
      "e": "AQAB"
    }
  ]
}`

	// This is an expired token. We check both if the verifier errors out due to
	// the expiry, and also if it succeds when we skip the expiry check, which is
	// enough to test that the signature is correctly being verified.
	const rawToken = `eyJhbGciOiJSUzI1NiIsImtpZCI6IkxIVkdQOGtxek4xTXVLUk1Uc3JvSWNSLTdoZGljWFdkcGFxdUVXY0FoOVEifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzQ0NzYzODI0LCJpYXQiOjE3NDQ3NjMyMjQsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwianRpIjoiODU2YTA2OWItZmUyZi00OTI4LTgzNGMtOTUwNGYwMmU4MzQzIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0Iiwic2VydmljZWFjY291bnQiOnsibmFtZSI6ImRlZmF1bHQiLCJ1aWQiOiIxYjg3OTNjZC02YTYyLTQ2ZmYtOWNmNy1lN2ZlOWU3Y2RiODYifX0sIm5iZiI6MTc0NDc2MzIyNCwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6ZGVmYXVsdCJ9.NF8UW6O8nqQ0HIKNxc2UuRBOZ5QRQhosS9_2zd0I9sCdE5OL6YWarYLb9-1_hDqEZkve5drvTTUx6fcgP3_mn10RKDg18mxbHL1dGHNTm3ZnfeTEw6XBndBocLs_Ytb8E_du_PozoKkEKDktVb98YTdgF-J3mhJTt_KBPNTkwSaFSzH6RDMq38LQaF-SKDcv2qzdzj8L6edUHNWZxf4UvqFLlEwVcmXjkh1XWmNQ-rvgc4oK7NGPuWQThkozrIsjlgKsG8ueFiATUx7I9SuRRGiOl4Vz6KfMUoCkeKLFfLXNRdVSP1C3KNtOOZWdlIJBye7pz-9VydB3DzkWVtsfAA`

	t.Run("invalid jwks", func(t *testing.T) {
		verifier, err := jwks.NewVerifier("invalid jwks")
		if err == nil {
			t.Error("expected error, got nil")
		}
		if verifier != nil {
			t.Errorf("expected nil verifier, got %v", verifier)
		}
	})

	t.Run("valid jwks and invalid token (expired)", func(t *testing.T) {
		verifier, err := jwks.NewVerifier(rawJWKS)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if verifier == nil {
			t.Fatal("expected non-nil verifier, got nil")
		}

		token, err := verifier.Verify(context.Background(), rawToken)
		if err == nil {
			t.Error("expected error, got nil")
		} else if !strings.Contains(err.Error(), "token is expired") {
			t.Errorf("expected expiry error, got %v", err)
		}
		if token != nil {
			t.Errorf("expected nil token, got %v", token)
		}
	})

	t.Run("valid jwks and token (because expiry is skipped)", func(t *testing.T) {
		verifier, err := jwks.NewVerifier(rawJWKS, func(c *oidc.Config) { c.SkipExpiryCheck = true })
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if verifier == nil {
			t.Fatal("expected non-nil verifier, got nil")
		}

		token, err := verifier.Verify(context.Background(), rawToken)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if token == nil {
			t.Fatal("expected non-nil token, got nil")
		}

		if token.Subject != "system:serviceaccount:default:default" {
			t.Errorf("expected subject 'system:serviceaccount:default:default', got %s", token.Subject)
		}
	})
}

// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "chainguard.dev/sdk/proto/platform/oidc/v1"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-github/v72/github"
	"google.golang.org/grpc/metadata"

	"github.com/octo-sts/app/pkg/jwks"
	"github.com/octo-sts/app/pkg/provider"
)

type fakeGitHub struct {
	mux *http.ServeMux
}

func newFakeGitHub() *fakeGitHub {
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]github.Installation{{
			ID: github.Ptr(int64(1234)),
			Account: &github.User{
				Login: github.Ptr("org"),
			},
		}})
	})
	mux.HandleFunc("/app/installations/{appID}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(github.InstallationToken{
			Token:     github.Ptr(base64.StdEncoding.EncodeToString(b)),
			ExpiresAt: &github.Timestamp{Time: time.Now().Add(10 * time.Minute)},
		})
	})
	mux.HandleFunc("/repos/{org}/{repo}/contents/.github/chainguard/{identity}", func(w http.ResponseWriter, r *http.Request) {
		b, err := os.ReadFile(filepath.Join("testdata", r.PathValue("org"), r.PathValue("repo"), r.PathValue("identity")))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(io.MultiWriter(w, os.Stdout), "ReadFile failed: %v\n", err)
		}
		json.NewEncoder(w).Encode(github.RepositoryContent{
			Content:  github.Ptr(base64.StdEncoding.EncodeToString(b)),
			Type:     github.Ptr("file"),
			Encoding: github.Ptr("base64"),
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
		fmt.Fprintf(io.MultiWriter(w, os.Stdout), "%s %s not implemented\n", r.Method, r.URL.Path)
	})

	return &fakeGitHub{
		mux: mux,
	}
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mux.ServeHTTP(w, r)
}

func TestExchange(t *testing.T) {
	ctx := context.Background()
	atr := newGitHubClient(t, newFakeGitHub())

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate RSA key %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       pk,
	}, nil)
	if err != nil {
		t.Fatalf("jose.NewSigner() = %v", err)
	}

	iss := "https://token.actions.githubusercontent.com"
	token, err := josejwt.Signed(signer).Claims(josejwt.Claims{
		Subject:  "foo",
		Issuer:   iss,
		Audience: josejwt.Audience{"octosts"},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
	}).Serialize()
	if err != nil {
		t.Fatalf("CompactSerialize failed: %v", err)
	}
	provider.AddTestKeySetVerifier(t, iss, &oidc.StaticKeySet{
		PublicKeys: []crypto.PublicKey{pk.Public()},
	})
	signedTokenCtx := metadata.NewIncomingContext(ctx, metadata.MD{"authorization": []string{"Bearer " + token}})

	// This is an expired token.
	const jwksToken = `eyJhbGciOiJSUzI1NiIsImtpZCI6IkxIVkdQOGtxek4xTXVLUk1Uc3JvSWNSLTdoZGljWFdkcGFxdUVXY0FoOVEifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzQ0NzYzODI0LCJpYXQiOjE3NDQ3NjMyMjQsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwianRpIjoiODU2YTA2OWItZmUyZi00OTI4LTgzNGMtOTUwNGYwMmU4MzQzIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0Iiwic2VydmljZWFjY291bnQiOnsibmFtZSI6ImRlZmF1bHQiLCJ1aWQiOiIxYjg3OTNjZC02YTYyLTQ2ZmYtOWNmNy1lN2ZlOWU3Y2RiODYifX0sIm5iZiI6MTc0NDc2MzIyNCwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6ZGVmYXVsdCJ9.NF8UW6O8nqQ0HIKNxc2UuRBOZ5QRQhosS9_2zd0I9sCdE5OL6YWarYLb9-1_hDqEZkve5drvTTUx6fcgP3_mn10RKDg18mxbHL1dGHNTm3ZnfeTEw6XBndBocLs_Ytb8E_du_PozoKkEKDktVb98YTdgF-J3mhJTt_KBPNTkwSaFSzH6RDMq38LQaF-SKDcv2qzdzj8L6edUHNWZxf4UvqFLlEwVcmXjkh1XWmNQ-rvgc4oK7NGPuWQThkozrIsjlgKsG8ueFiATUx7I9SuRRGiOl4Vz6KfMUoCkeKLFfLXNRdVSP1C3KNtOOZWdlIJBye7pz-9VydB3DzkWVtsfAA`
	jwksTokenCtx := metadata.NewIncomingContext(ctx, metadata.MD{"authorization": []string{"Bearer " + jwksToken}})

	sts := &sts{
		atr: atr,
		jwksConfigOpts: []jwks.ConfigOption{
			func(c *oidc.Config) { c.SkipExpiryCheck = true },
		},
	}
	for _, tc := range []struct {
		ctx  context.Context
		name string
		req  *v1.ExchangeRequest
		want *github.InstallationTokenOptions
	}{
		{
			ctx:  signedTokenCtx,
			name: "repo",
			req: &v1.ExchangeRequest{
				Identity: "foo",
				Scope:    "org/repo",
			},
			want: &github.InstallationTokenOptions{
				Repositories: []string{"repo"},
				Permissions: &github.InstallationPermissions{
					PullRequests: github.Ptr("write"),
				},
			},
		},
		{
			ctx:  signedTokenCtx,
			name: "org",
			req: &v1.ExchangeRequest{
				Identity: "foo",
				Scope:    "org",
			},
			want: &github.InstallationTokenOptions{
				Permissions: &github.InstallationPermissions{
					PullRequests: github.Ptr("write"),
				},
			},
		},
		{
			ctx:  jwksTokenCtx,
			name: "repo with jwks",
			req: &v1.ExchangeRequest{
				Identity: "jwks",
				Scope:    "org/repo",
			},
			want: &github.InstallationTokenOptions{
				Repositories: []string{"repo"},
				Permissions: &github.InstallationPermissions{
					PullRequests: github.Ptr("write"),
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := sts.Exchange(tc.ctx, tc.req)
			if err != nil {
				t.Fatalf("Exchange failed: %v", err)
			}

			b, err := base64.StdEncoding.DecodeString(tok.Token)
			if err != nil {
				t.Fatalf("DecodeString failed: %v", err)
			}
			got := new(github.InstallationTokenOptions)
			if err := json.Unmarshal(b, got); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func newGitHubClient(t *testing.T, h http.Handler) *ghinstallation.AppsTransport {
	t.Helper()

	tlsConfig, err := generateTLS(&x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().Add(10 * time.Hour),
		DNSNames:     []string{"localhost"},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = tlsConfig
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// Create a custom transport that overrides the Dial funcs - this forces all traffic
	// that uses this transport to go through this server, regardless of the URL.
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialTLS: func(network, addr string) (net.Conn, error) {
			return tls.Dial(network, strings.TrimPrefix(srv.URL, "https://"), tlsConfig)
		},
		Dial: func(network, addr string) (net.Conn, error) {
			return tls.Dial(network, strings.TrimPrefix(srv.URL, "http://"), tlsConfig)
		},
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	ghsigner := ghinstallation.NewRSASigner(jwt.SigningMethodRS256, key)

	atr, err := ghinstallation.NewAppsTransportWithOptions(transport, 1234, ghinstallation.WithSigner(ghsigner))
	if err != nil {
		t.Fatalf("NewAppsTransportWithOptions failed: %v", err)
	}
	atr.BaseURL = srv.URL

	return atr
}

func generateTLS(tmpl *x509.Certificate) (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("error generating private key: %w", err)
	}
	pub := &priv.PublicKey
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("error generating certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: raw,
	})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("error marshaling key bytes: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("error loading tls certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		return nil, fmt.Errorf("error adding cert to pool")
	}

	// configuration of the certificate what we want to
	return &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		RootCAs:            pool,
		InsecureSkipVerify: true,
	}, nil
}

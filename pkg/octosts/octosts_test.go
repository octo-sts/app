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
	"github.com/google/go-github/v75/github"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

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
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{"authorization": []string{"Bearer " + token}})

	sts := NewSecurityTokenServiceServer(atr, nil, "test.example.com", false).(*sts)
	for _, tc := range []struct {
		name string
		req  *v1.ExchangeRequest
		want *github.InstallationTokenOptions
	}{
		{
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := sts.Exchange(ctx, tc.req)
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

func TestExchangeValidation(t *testing.T) {
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
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{"authorization": []string{"Bearer " + token}})

	sts := &sts{
		atr: atr,
	}

	tests := []struct {
		name string
		req  *v1.ExchangeRequest
	}{
		{
			name: "empty scope",
			req: &v1.ExchangeRequest{
				Identity: "foo",
				Scope:    "",
			},
		},
		{
			name: "empty identity",
			req: &v1.ExchangeRequest{
				Identity: "",
				Scope:    "org/repo",
			},
		},
		{
			name: "both empty",
			req: &v1.ExchangeRequest{
				Identity: "",
				Scope:    "",
			},
		},
		{
			name: "nil",
			req:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sts.Exchange(ctx, tc.req)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("expected gRPC status error, got %T", err)
			}
			if st.Code() != codes.InvalidArgument {
				t.Errorf("expected code InvalidArgument, got %v", st.Code())
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

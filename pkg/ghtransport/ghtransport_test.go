// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ghtransport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/octo-sts/app/pkg/appconfig"
	"github.com/octo-sts/app/pkg/envconfig"
	"github.com/octo-sts/app/pkg/ghinstall"
	"github.com/stretchr/testify/assert"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestQuotaTapPopulatesStore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "8421")
		w.Header().Set("X-RateLimit-Limit", "15000")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	store := ghinstall.NewQuotaStore(time.Minute)
	tap := &quotaTap{inner: http.DefaultTransport, store: store}
	client := &http.Client{Transport: tap}

	const installID = int64(987654)
	req, err := http.NewRequestWithContext(EnrichContext(context.Background(), 12345, installID), http.MethodGet, srv.URL, nil)
	assert.NoError(t, err)
	// Simulate an installation-token request (ghinstallation uses "token " prefix).
	req.Header.Set("Authorization", "token ghs_fake_installation_token")
	resp, err := client.Do(req)
	assert.NoError(t, err)
	resp.Body.Close()

	rem, lim, ok := store.Get(installID)
	assert.True(t, ok, "quota store should be populated after a tapped response")
	assert.Equal(t, 8421, rem)
	assert.Equal(t, 15000, lim)
}

func TestQuotaTapIgnoresJWTAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "4900")
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	store := ghinstall.NewQuotaStore(time.Minute)
	tap := &quotaTap{inner: http.DefaultTransport, store: store}
	client := &http.Client{Transport: tap}

	const installID = int64(987654)
	req, err := http.NewRequestWithContext(EnrichContext(context.Background(), 12345, installID), http.MethodGet, srv.URL, nil)
	assert.NoError(t, err)
	// Simulate an app-JWT request (ghinstallation uses "Bearer " prefix).
	// The 5000 limit is the app-level rate limit, not per-installation.
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.fake.jwt")
	resp, err := client.Do(req)
	assert.NoError(t, err)
	resp.Body.Close()

	if _, _, ok := store.Get(installID); ok {
		t.Errorf("store populated for JWT request — app-level rate limits must not be recorded")
	}
}

func TestQuotaTapIgnoresMissingContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "1234")
		w.Header().Set("X-RateLimit-Limit", "15000")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	store := ghinstall.NewQuotaStore(time.Minute)
	tap := &quotaTap{inner: http.DefaultTransport, store: store}
	client := &http.Client{Transport: tap}

	// Plain context with no EnrichContext → no installID → no store update.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	assert.NoError(t, err)
	resp, err := client.Do(req)
	assert.NoError(t, err)
	resp.Body.Close()

	if _, _, ok := store.Get(0); ok {
		t.Errorf("store unexpectedly populated for installID=0")
	}
}

func TestGCPKMS(t *testing.T) {
	ctx := context.Background()

	credsFile := createGCPKMSCredsFile(t)

	defer os.Remove(credsFile)

	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credsFile)

	testConfig := &envconfig.EnvConfig{
		Port:    8080,
		AppIDs:  []int64{12345678, 87654321},
		KMSKeys: []string{"test-kms-key-1", "test-kms-key-2"},
		Metrics: true,
	}

	kmsClient := generateKMSClient(ctx, t)
	for i, appID := range testConfig.AppIDs {
		transport, err := New(ctx, appID, testConfig.KMSKeys[i], testConfig, kmsClient, nil)
		assert.NoError(t, err)
		assert.NotNil(t, transport)
	}
}

func TestCertEnvVar(t *testing.T) {
	ctx := context.Background()

	testConfig := &envconfig.EnvConfig{
		Port:                       8080,
		AppIDs:                     []int64{12345678, 87654321},
		AppSecretCertificateEnvVar: generateTestCertificateString(),
		Metrics:                    true,
	}

	kmsClient := generateKMSClient(ctx, t)
	for _, appID := range testConfig.AppIDs {
		transport, err := New(ctx, appID, "", testConfig, kmsClient, nil)
		assert.NoError(t, err)
		assert.NotNil(t, transport)
	}
}

func TestCertFile(t *testing.T) {
	ctx := context.Background()

	testConfig := &envconfig.EnvConfig{
		Port:                     8080,
		AppIDs:                   []int64{12345678, 87654321},
		AppSecretCertificateFile: generateTestCertificateFile(t),
		Metrics:                  true,
	}

	kmsClient := generateKMSClient(ctx, t)
	for _, appID := range testConfig.AppIDs {
		transport, err := New(ctx, appID, "", testConfig, kmsClient, nil)
		assert.NoError(t, err)
		assert.NotNil(t, transport)
	}
}

func TestNewFromAppConfigKMS(t *testing.T) {
	ctx := context.Background()
	credsFile := createGCPKMSCredsFile(t)
	defer os.Remove(credsFile)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credsFile)

	kmsClient := generateKMSClient(ctx, t)
	transport, err := NewFromAppConfig(ctx, appconfig.AppConfig{
		AppID:  12345678,
		KMSKey: "test-kms-key",
	}, kmsClient, nil)
	assert.NoError(t, err)
	assert.NotNil(t, transport)
}

func TestNewFromAppConfigPrivateKey(t *testing.T) {
	ctx := context.Background()
	transport, err := NewFromAppConfig(ctx, appconfig.AppConfig{
		AppID:      12345678,
		PrivateKey: generateTestCertificateString(),
	}, nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, transport)
}

func TestNewFromAppConfigPrivateKeyFile(t *testing.T) {
	ctx := context.Background()
	transport, err := NewFromAppConfig(ctx, appconfig.AppConfig{
		AppID:          12345678,
		PrivateKeyFile: generateTestCertificateFile(t),
	}, nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, transport)
}

func TestNewFromAppConfigNoCredential(t *testing.T) {
	ctx := context.Background()
	_, err := NewFromAppConfig(ctx, appconfig.AppConfig{
		AppID: 12345678,
	}, nil, nil)
	assert.Error(t, err)
}

func generateKMSClient(ctx context.Context, t *testing.T) *kms.KeyManagementClient {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	fakeServerAddr := l.Addr().String()

	client, err := kms.NewKeyManagementClient(ctx,
		option.WithEndpoint(fakeServerAddr),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
	)
	if err != nil {
		t.Fatal(err)
	}

	return client
}

func createGCPKMSCredsFile(t *testing.T) string {
	tmpFile, err := os.CreateTemp(t.TempDir(), "creds-")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %s", err)
	}

	jsonStr := fmt.Sprintf(`{
        "type": "service_account",
        "private_key": "%s"
    }`, generateTestCertificateString())

	if _, err := tmpFile.Write([]byte(jsonStr)); err != nil {
		t.Fatalf("Failed to write to temporary file: %s", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("Failed to close temporary file: %s", err)
	}
	return tmpFile.Name()
}

func generateTestCertificateString() string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	privateKeyPEM := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	var pemOut bytes.Buffer
	pem.Encode(&pemOut, &privateKeyPEM)
	return pemOut.String()
}

func generateTestCertificateFile(t *testing.T) string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	privateKeyPEM := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	tmpFile, err := os.CreateTemp(t.TempDir(), "privateKey*.pem")
	if err != nil {
		log.Fatal(err)
	}

	if err := pem.Encode(tmpFile, &privateKeyPEM); err != nil {
		log.Fatal(err)
	}

	return tmpFile.Name()
}

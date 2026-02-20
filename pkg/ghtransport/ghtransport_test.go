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
	"os"
	"testing"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/octo-sts/app/pkg/envconfig"
	"github.com/stretchr/testify/assert"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

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
		transport, err := New(ctx, appID, testConfig.KMSKeys[i], testConfig, kmsClient)
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
		transport, err := New(ctx, appID, "", testConfig, kmsClient)
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
		transport, err := New(ctx, appID, "", testConfig, kmsClient)
		assert.NoError(t, err)
		assert.NotNil(t, transport)
	}
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

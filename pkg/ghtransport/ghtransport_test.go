// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ghtransport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"os"
	"testing"

	"github.com/octo-sts/app/pkg/envconfig"
	"github.com/octo-sts/app/pkg/kms"
	"github.com/stretchr/testify/assert"
)

func TestGCPKMS(t *testing.T) {
	ctx := context.Background()

	credsFile := createGCPKMSCredsFile(t)

	defer os.Remove(credsFile)

	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credsFile)

	testConfig := &envconfig.EnvConfig{
		Port:        8080,
		AppID:       123456,
		KMSKey:      "test-kms-key",
		KMSProvider: "gcp",
		Metrics:     true,
	}

	kms, err := kms.NewKMS(ctx, testConfig.KMSProvider, testConfig.KMSKey)
	if err != nil {
		t.Fatalf("Failed to create KMS: %s", err)
	}

	transport, err := New(ctx, testConfig, kms)

	assert.NoError(t, err)

	assert.NotNil(t, transport)
}

func TestCertEnvVar(t *testing.T) {
	ctx := context.Background()

	testConfig := &envconfig.EnvConfig{
		Port:                       8080,
		AppID:                      123456,
		AppSecretCertificateEnvVar: generateTestCertificateString(),
		Metrics:                    true,
	}

	transport, err := New(ctx, testConfig, nil)

	assert.NoError(t, err)

	assert.NotNil(t, transport)
}

func TestCertFile(t *testing.T) {
	ctx := context.Background()

	testConfig := &envconfig.EnvConfig{
		Port:                     8080,
		AppID:                    123456,
		AppSecretCertificateFile: generateTestCertificateFile(t),
		Metrics:                  true,
	}

	transport, err := New(ctx, testConfig, nil)

	assert.NoError(t, err)

	assert.NotNil(t, transport)
}

func createGCPKMSCredsFile(t *testing.T) string {
	tmpFile, err := os.CreateTemp(t.TempDir(), "creds-")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %s", err)
	}

	// Create proper JSON with escaped private key
	creds := map[string]interface{}{
		"type":        "service_account",
		"private_key": generateTestCertificateString(),
	}

	jsonBytes, err := json.Marshal(creds)
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %s", err)
	}

	if _, err := tmpFile.Write(jsonBytes); err != nil {
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

// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package stickystore

import (
	"context"
	"fmt"
	"io"

	gofirestore "cloud.google.com/go/firestore"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	godynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/octo-sts/app/pkg/envconfig"
	"github.com/octo-sts/app/pkg/stickystore/dynamodb"
	"github.com/octo-sts/app/pkg/stickystore/firestore"
	"github.com/octo-sts/app/pkg/stickystore/memory"
)

// New creates a Store from the given env config. Returns nil (no store)
// if StickyStore is empty. The returned io.Closer must be closed when the
// store is no longer needed (it may close underlying clients).
func New(ctx context.Context, cfg *envconfig.EnvConfig) (Store, io.Closer, error) {
	switch cfg.StickyStore {
	case "":
		return nil, io.NopCloser(nil), nil
	case "memory":
		return memory.New(), io.NopCloser(nil), nil
	case "firestore":
		return newFirestore(ctx, cfg)
	case "dynamodb":
		return newDynamodb(ctx, cfg)
	default:
		return nil, nil, fmt.Errorf("stickystore: unsupported backend %q", cfg.StickyStore)
	}
}

func newDynamodb(ctx context.Context, cfg *envconfig.EnvConfig) (Store, io.Closer, error) {
	if cfg.StickyStoreDynamodbTable == "" {
		return nil, nil, fmt.Errorf("stickystore: OCTOSTS_STICKY_STORE_DYNAMODB_TABLE must be set")
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("stickystore: loading AWS config for dynamodb: %w", err)
	}
	client := godynamodb.NewFromConfig(awsCfg)

	return dynamodb.New(client, cfg.StickyStoreDynamodbTable, cfg.StickyStoreDynamodbTTL), io.NopCloser(nil), nil
}

func newFirestore(ctx context.Context, cfg *envconfig.EnvConfig) (Store, io.Closer, error) {
	if cfg.StickyStoreFirestoreProject == "" {
		return nil, nil, fmt.Errorf("stickystore: OCTOSTS_STICKY_STORE_FIRESTORE_PROJECT must be set")
	}

	client, err := gofirestore.NewClient(ctx, cfg.StickyStoreFirestoreProject)
	if err != nil {
		return nil, nil, fmt.Errorf("stickystore: creating Firestore client: %w", err)
	}

	return firestore.New(client, cfg.StickyStoreFirestoreCollection, cfg.StickyStoreFirestoreTTL), client, nil
}

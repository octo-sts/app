// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package stickystore

import (
	"context"
	"fmt"
	"io"
	"time"

	gofirestore "cloud.google.com/go/firestore"

	"github.com/octo-sts/app/pkg/envconfig"
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
	default:
		return nil, nil, fmt.Errorf("stickystore: unsupported backend %q", cfg.StickyStore)
	}
}

func newFirestore(ctx context.Context, cfg *envconfig.EnvConfig) (Store, io.Closer, error) {
	if cfg.StickyStoreFirestoreProject == "" {
		return nil, nil, fmt.Errorf("stickystore: OCTOSTS_STICKY_STORE_FIRESTORE_PROJECT must be set")
	}

	client, err := gofirestore.NewClient(ctx, cfg.StickyStoreFirestoreProject)
	if err != nil {
		return nil, nil, fmt.Errorf("stickystore: creating Firestore client: %w", err)
	}

	collection := cfg.StickyStoreFirestoreCollection
	if collection == "" {
		collection = "sticky-routes"
	}

	ttl := cfg.StickyStoreFirestoreTTL
	if ttl == 0 {
		ttl = 720 * time.Hour
	}

	return firestore.New(client, collection, ttl), client, nil
}

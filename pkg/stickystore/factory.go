// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package stickystore

import (
	"context"
	"fmt"
	"io"

	gcdocstore "gocloud.dev/docstore"

	// Register docstore drivers. Each blank import registers a URL scheme
	// handler with docstore.OpenCollection.
	_ "gocloud.dev/docstore/awsdynamodb/v2" // dynamodb://
	_ "gocloud.dev/docstore/gcpfirestore"   // firestore://
	_ "gocloud.dev/docstore/memdocstore"    // mem://

	"github.com/octo-sts/app/pkg/envconfig"
	"github.com/octo-sts/app/pkg/stickystore/docstore"
)

// New opens the sticky store identified by cfg.StickyStoreURL. An empty URL
// disables sticky routing — the returned Store is nil and the Closer is a
// no-op. The Closer must be closed when the store is no longer needed.
func New(ctx context.Context, cfg *envconfig.EnvConfig) (Store, io.Closer, error) {
	if cfg.StickyStoreURL == "" {
		return nil, io.NopCloser(nil), nil
	}

	coll, err := gcdocstore.OpenCollection(ctx, cfg.StickyStoreURL)
	if err != nil {
		return nil, nil, fmt.Errorf("stickystore: opening collection %q: %w", cfg.StickyStoreURL, err)
	}
	return docstore.New(coll, cfg.StickyStoreTTL), coll, nil
}

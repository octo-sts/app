// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package firestore

import (
	"context"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/chainguard-dev/clog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Store struct {
	client     *firestore.Client
	collection string
	ttl        time.Duration
}

type doc struct {
	InstallationID int64     `firestore:"installation_id"`
	Scope          string    `firestore:"scope"`
	Identity       string    `firestore:"identity"`
	Subject        string    `firestore:"subject"`
	CreatedAt      time.Time `firestore:"created_at"`
	ExpireAt       time.Time `firestore:"expire_at"`
}

// New creates a Firestore-backed sticky store. Documents are stored in the
// given collection with TTL managed via the expire_at field.
func New(client *firestore.Client, collection string, ttl time.Duration) *Store {
	return &Store{
		client:     client,
		collection: collection,
		ttl:        ttl,
	}
}

// Get returns the persisted installation ID for key. Returns ok=false on
// cache miss. Refreshes the document's expire_at on every hit so active
// mappings never reach the TTL.
func (s *Store) Get(ctx context.Context, key string) (int64, bool, error) {
	snap, err := s.client.Collection(s.collection).Doc(key).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return 0, false, nil
		}
		return 0, false, err
	}

	var d doc
	if err := snap.DataTo(&d); err != nil {
		return 0, false, err
	}

	// Refresh TTL on read so active mappings never expire.
	_, err = s.client.Collection(s.collection).Doc(key).Update(ctx, []firestore.Update{
		{Path: "expire_at", Value: time.Now().Add(s.ttl)},
	})
	if err != nil {
		clog.FromContext(ctx).Warnf("stickystore: failed to refresh TTL for key %s: %v", key, err)
	}

	return d.InstallationID, true, nil
}

// Put persists a sticky mapping. Overwrites any existing document for the
// key. scope, identity, and subject are stored for operator debuggability.
func (s *Store) Put(ctx context.Context, key string, installationID int64, scope, identity, subject string) error {
	now := time.Now()
	_, err := s.client.Collection(s.collection).Doc(key).Set(ctx, doc{
		InstallationID: installationID,
		Scope:          scope,
		Identity:       identity,
		Subject:        subject,
		CreatedAt:      now,
		ExpireAt:       now.Add(s.ttl),
	})
	return err
}

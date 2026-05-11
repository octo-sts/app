// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package docstore implements stickystore.Store on top of gocloud.dev/docstore,
// which provides a portable abstraction over Firestore, DynamoDB, MongoDB,
// and an in-memory backend.
package docstore

import (
	"context"
	"time"

	"github.com/chainguard-dev/clog"
	"gocloud.dev/docstore"
	"gocloud.dev/gcerrors"
)

type Store struct {
	coll *docstore.Collection
	ttl  time.Duration
}

// doc is the on-the-wire shape of a sticky entry. The Key field is the
// document name/partition key; the URL's name_field (Firestore) or
// partition_key (DynamoDB) parameter must reference "key".
type doc struct {
	Key            string    `docstore:"key"`
	InstallationID int64     `docstore:"installation_id"`
	Scope          string    `docstore:"scope"`
	Identity       string    `docstore:"identity"`
	Subject        string    `docstore:"subject"`
	CreatedAt      time.Time `docstore:"created_at"`
	ExpireAt       time.Time `docstore:"expire_at"`
}

// New wraps an already-opened docstore.Collection. The caller retains
// ownership and is responsible for closing the collection.
func New(coll *docstore.Collection, ttl time.Duration) *Store {
	return &Store{coll: coll, ttl: ttl}
}

func (s *Store) Get(ctx context.Context, key string) (int64, bool, error) {
	d := doc{Key: key}
	if err := s.coll.Get(ctx, &d); err != nil {
		if gcerrors.Code(err) == gcerrors.NotFound {
			return 0, false, nil
		}
		return 0, false, err
	}

	err := s.refreshTTL(context.WithoutCancel(ctx), key)
	if err != nil {
		clog.FromContext(ctx).Warnf("stickystore: failed to refresh TTL for key %s: %v", key, err)
	}

	return d.InstallationID, true, nil
}

func (s *Store) refreshTTL(ctx context.Context, key string) error {
	err := s.coll.Actions().Update(&doc{Key: key}, docstore.Mods{
		"expire_at": time.Now().Add(s.ttl),
	}).Do(ctx)
	if err != nil {
		return err
	}
	return nil
}

// Put persists a sticky mapping. scope, identity, and subject are stored for
// operator debuggability — they are not read by application logic.
func (s *Store) Put(ctx context.Context, key string, installationID int64, scope, identity, subject string) error {
	now := time.Now()
	return s.coll.Put(ctx, &doc{
		Key:            key,
		InstallationID: installationID,
		Scope:          scope,
		Identity:       identity,
		Subject:        subject,
		CreatedAt:      now,
		ExpireAt:       now.Add(s.ttl),
	})
}

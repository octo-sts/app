// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ghinstall

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGetPoolExactMatch(t *testing.T) {
	pool := &OrgPool{AppCount: 2}
	router := NewOrgRouter(map[string]*OrgPool{"my-org": pool})

	got, err := router.GetPool("my-org")
	if err != nil {
		t.Fatalf("GetPool() = %v", err)
	}
	if got != pool {
		t.Error("expected exact-match pool")
	}
}

func TestGetPoolWildcardFallback(t *testing.T) {
	wildcard := &OrgPool{AppCount: 1}
	router := NewOrgRouter(map[string]*OrgPool{WildcardOrg: wildcard})

	got, err := router.GetPool("unknown-org")
	if err != nil {
		t.Fatalf("GetPool() = %v", err)
	}
	if got != wildcard {
		t.Error("expected wildcard pool")
	}
}

func TestGetPoolExactTakesPrecedenceOverWildcard(t *testing.T) {
	exact := &OrgPool{AppCount: 2}
	wildcard := &OrgPool{AppCount: 1}
	router := NewOrgRouter(map[string]*OrgPool{
		"my-org": exact,
		WildcardOrg: wildcard,
	})

	got, err := router.GetPool("my-org")
	if err != nil {
		t.Fatalf("GetPool() = %v", err)
	}
	if got != exact {
		t.Error("expected exact pool, got wildcard")
	}
}

func TestGetPoolNotFound(t *testing.T) {
	router := NewOrgRouter(map[string]*OrgPool{"other-org": {AppCount: 1}})

	_, err := router.GetPool("missing-org")
	if err == nil {
		t.Fatal("expected error for unconfigured org")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T", err)
	}
	if st.Code() != codes.NotFound {
		t.Errorf("expected NotFound, got %v", st.Code())
	}
}

func TestGetPoolCaseInsensitive(t *testing.T) {
	pool := &OrgPool{AppCount: 1}
	router := NewOrgRouter(map[string]*OrgPool{"my-org": pool})

	got, err := router.GetPool("My-Org")
	if err != nil {
		t.Fatalf("GetPool() = %v", err)
	}
	if got != pool {
		t.Error("expected case-insensitive match")
	}
}

func TestGetPoolEmptyRouter(t *testing.T) {
	router := NewOrgRouter(map[string]*OrgPool{})

	_, err := router.GetPool("any-org")
	if err == nil {
		t.Fatal("expected error for empty router")
	}
}

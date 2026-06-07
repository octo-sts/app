// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ghinstall

import (
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// WildcardOrg is the key used for a fallback pool that serves any org.
// Used by the legacy env-var code path where all apps serve all orgs.
const WildcardOrg = "*"

// OrgPool holds the Manager that serves a single organization, plus the
// number of underlying apps so callers can cap rate-limit retries.
type OrgPool struct {
	M        Manager
	AppCount int
}

// OrgRouter maps GitHub organization names to their dedicated app pools.
// A wildcard entry (WildcardOrg) serves as a fallback for any org not
// explicitly configured — used by the legacy env-var code path.
type OrgRouter struct {
	orgs map[string]*OrgPool
}

// NewOrgRouter creates an OrgRouter from the given org-to-pool mapping.
func NewOrgRouter(orgs map[string]*OrgPool) *OrgRouter {
	return &OrgRouter{orgs: orgs}
}

// GetPool returns the OrgPool for the given owner. If owner is not explicitly
// configured, it falls back to the WildcardOrg entry. Returns a NotFound
// gRPC error if no pool is available. The lookup is case-insensitive since
// GitHub organization names are case-insensitive.
func (r *OrgRouter) GetPool(owner string) (*OrgPool, error) {
	owner = strings.ToLower(owner)
	if pool, ok := r.orgs[owner]; ok {
		return pool, nil
	}
	if pool, ok := r.orgs[WildcardOrg]; ok {
		return pool, nil
	}
	return nil, status.Errorf(codes.NotFound, "no GitHub App configured for org %q", owner)
}

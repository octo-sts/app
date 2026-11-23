// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"strconv"
	"testing"
)

func TestConfigurePolicyCache(t *testing.T) {
	if err := ConfigurePolicyCache(0); err == nil {
		t.Fatal("ConfigurePolicyCache(0) returned nil, want an error")
	}
	if err := ConfigurePolicyCache(-1); err == nil {
		t.Fatal("ConfigurePolicyCache(-1) returned nil, want an error")
	}

	const size = 3
	if err := ConfigurePolicyCache(size); err != nil {
		t.Fatalf("ConfigurePolicyCache(%d): %v", size, err)
	}
	t.Cleanup(func() {
		if err := ConfigurePolicyCache(defaultPolicyCacheSize); err != nil {
			t.Errorf("restoring default cache size: %v", err)
		}
		for i := range size + 2 {
			key := cacheTrustPolicyKey{owner: "policy-cache-size", repo: "r", identity: strconv.Itoa(i)}
			trustPolicies.Remove(key)
			staleTrustPolicies.Remove(key)
		}
	})

	for i := range size + 2 {
		key := cacheTrustPolicyKey{owner: "policy-cache-size", repo: "r", identity: strconv.Itoa(i)}
		trustPolicies.Add(key, "policy")
		staleTrustPolicies.Add(key, "policy")
	}
	if got := trustPolicies.Len(); got != size {
		t.Errorf("trustPolicies.Len() = %d, want %d", got, size)
	}
	if got := staleTrustPolicies.Len(); got != size {
		t.Errorf("staleTrustPolicies.Len() = %d, want %d", got, size)
	}
}

// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package cleanup

import (
	"fmt"
	"strings"
	"testing"
)

func TestPolicyTraversalLimits(t *testing.T) {
	// The two subdirectories model paths to the same Git tree: both must count.
	repo := fakeRepo{
		owner: "acme", name: "svc",
		entries: []entry{{"root.sts.yaml", "blob"}, {"a", "tree"}, {"b", "tree"}},
		dirs: map[string][]entry{
			"a": {{"leaf.sts.yaml", "blob"}},
			"b": {{"leaf.sts.yaml", "blob"}},
		},
	}
	for _, tc := range []struct {
		name   string
		budget traversalBudget
		want   string
	}{
		{"exact limits", traversalBudget{maxDirectories: 3, maxDepth: 1, maxEntries: 5, maxFiles: 3}, ""},
		{"directories", traversalBudget{maxDirectories: 2, maxDepth: 1, maxEntries: 5, maxFiles: 3}, "directory limit"},
		{"depth", traversalBudget{maxDirectories: 3, maxDepth: 0, maxEntries: 5, maxFiles: 3}, "directory depth"},
		{"entries", traversalBudget{maxDirectories: 3, maxDepth: 1, maxEntries: 4, maxFiles: 3}, "entry limit"},
		{"files", traversalBudget{maxDirectories: 3, maxDepth: 1, maxEntries: 5, maxFiles: 2}, "file limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := fakeGitHub(t, []fakeRepo{repo}, nil, false)
			got, err := policyFiles(t.Context(), client, "acme", policyDir, []string{"svc"}, []policySnapshot{{oid: snapshotOID}}, &tc.budget)
			if tc.want == "" {
				if err != nil || len(got) != 1 || len(got[0]) != 3 {
					t.Fatalf("policyFiles() = %v, %v; want three files", got, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) || got != nil {
				t.Fatalf("policyFiles() = %v, %v; want nil and %q", got, err, tc.want)
			}
		})
	}
}

func TestListPoliciesGlobalDirectoryLimit(t *testing.T) {
	// Each root fans out to identical-looking subtrees. The first batch yields
	// policies, but a later batch must still invalidate the entire result.
	var repos []fakeRepo
	for i := range maxPolicyDirectories/51 + 1 {
		r := fakeRepo{owner: "acme", name: fmt.Sprintf("repo-%03d", i), dirs: map[string][]entry{}}
		r.entries = append(r.entries, entry{"root.sts.yaml", "blob"})
		for j := range 50 {
			name := fmt.Sprintf("dir-%02d", j)
			r.entries = append(r.entries, entry{name, "tree"})
			r.dirs[name] = []entry{}
		}
		repos = append(repos, r)
	}
	client, queries := fakeGitHub(t, repos, nil, false)
	got, err := ListPolicies(t.Context(), client, "acme", policyDir)
	if err == nil || !strings.Contains(err.Error(), "directory limit") || got != nil {
		t.Fatalf("ListPolicies() = %v, %v; want nil and directory limit error", got, err)
	}
	// Directory aliases are batched; scheduling stops at the global budget.
	if queries.Load() > int32(maxPolicyDirectories/batchSize+5) {
		t.Fatalf("GraphQL queries = %d; traversal exceeded bounded budget", queries.Load())
	}
}

func TestPolicyTraversalSharedTreeFanout(t *testing.T) {
	// Each directory has the same contents, as when every child points to
	// one shared Git tree. Paths still expand exponentially without a limit.
	r := fakeRepo{owner: "acme", name: "svc", dirs: map[string][]entry{}}
	paths := []string{""}
	for depth := 0; depth < 4; depth++ {
		var next []string
		for _, p := range paths {
			entries := []entry{{"policy.sts.yaml", "blob"}}
			for _, child := range []string{"a", "b", "c"} {
				entries = append(entries, entry{child, "tree"})
				if p == "" {
					next = append(next, child)
				} else {
					next = append(next, p+"/"+child)
				}
			}
			if p == "" {
				r.entries = entries
			} else {
				r.dirs[p] = entries
			}
		}
		paths = next
	}
	client, queries := fakeGitHub(t, []fakeRepo{r}, nil, false)
	budget := traversalBudget{maxDirectories: 10, maxDepth: 10, maxEntries: 100, maxFiles: 100}
	got, err := policyFiles(t.Context(), client, "acme", policyDir, []string{"svc"}, []policySnapshot{{oid: snapshotOID}}, &budget)
	if err == nil || !strings.Contains(err.Error(), "directory limit") || got != nil {
		t.Fatalf("policyFiles() = %v, %v; want nil and directory limit error", got, err)
	}
	if budget.directories != budget.maxDirectories || queries.Load() != 2 {
		t.Fatalf("scheduled directories = %d, queries = %d; want 10 and 2", budget.directories, queries.Load())
	}
}

func TestPolicyTraversalBudgetAcrossBatches(t *testing.T) {
	repos := []fakeRepo{
		{owner: "acme", name: "first", entries: []entry{{"one.sts.yaml", "blob"}}},
		{owner: "acme", name: "second", entries: []entry{{"two.sts.yaml", "blob"}}},
	}
	for _, tc := range []struct {
		name   string
		budget traversalBudget
		want   string
	}{
		{"directories", traversalBudget{maxDirectories: 1, maxDepth: 1, maxEntries: 2, maxFiles: 2}, "directory limit"},
		{"entries", traversalBudget{maxDirectories: 2, maxDepth: 1, maxEntries: 1, maxFiles: 2}, "entry limit"},
		{"files", traversalBudget{maxDirectories: 2, maxDepth: 1, maxEntries: 2, maxFiles: 1}, "file limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := fakeGitHub(t, repos, nil, false)
			snapshot := []policySnapshot{{oid: snapshotOID}}
			if _, err := policyFiles(t.Context(), client, "acme", policyDir, []string{"first"}, snapshot, &tc.budget); err != nil {
				t.Fatalf("first batch: %v", err)
			}
			got, err := policyFiles(t.Context(), client, "acme", policyDir, []string{"second"}, snapshot, &tc.budget)
			if err == nil || !strings.Contains(err.Error(), tc.want) || got != nil {
				t.Fatalf("second batch = %v, %v; want nil and %q", got, err, tc.want)
			}
		})
	}
}

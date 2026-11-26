// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-github/v88/github"
)

func TestRecursivePolicySecurity(t *testing.T) {
	for _, tc := range []struct {
		name, parentMode, policyMode string
		wantError                    bool
	}{
		{"regular", "040000", "100644", false},
		{"symlink file", "040000", "120000", true},
		{"symlink parent", "120000", "100644", true},
		{"missing file mode", "040000", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := func(name, typ, mode, sha string) *github.TreeEntry {
				return &github.TreeEntry{Path: new(name), Type: new(typ), Mode: new(mode), SHA: new(sha)}
			}
			client := discoveryClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/git/commits/") {
					json.NewEncoder(w).Encode(&github.Commit{Tree: &github.Tree{SHA: new("root")}})
					return
				}
				var entries []*github.TreeEntry
				switch {
				case strings.HasSuffix(r.URL.Path, "/root"):
					entries = []*github.TreeEntry{entry(".github", "tree", "040000", "github")}
				case strings.HasSuffix(r.URL.Path, "/github"):
					entries = []*github.TreeEntry{entry("chainguard", "tree", "040000", "policy")}
				case strings.HasSuffix(r.URL.Path, "/policy"):
					typ := "tree"
					if tc.parentMode == "120000" {
						typ = "blob"
					}
					entries = []*github.TreeEntry{entry("nested", typ, tc.parentMode, "nested")}
				case strings.HasSuffix(r.URL.Path, "/nested"):
					entries = []*github.TreeEntry{entry("test.sts.yaml", "blob", tc.policyMode, "blob")}
				default:
					t.Errorf("unexpected request %s", r.URL)
					http.NotFound(w, r)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"tree": entries, "truncated": false})
			}))
			err := policyPathIsRegular(context.Background(), client, "foo", "bar", "head", ".github/chainguard/nested/test.sts.yaml")
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, wantError %v", err, tc.wantError)
			}
			if tc.wantError {
				results, err := validatePoliciesForRepo(context.Background(), client, "foo", "bar", "bar", "head", []string{".github/chainguard/nested/test.sts.yaml"}, ".github", ".github/chainguard")
				if err == nil || results[".github/chainguard/nested/test.sts.yaml"] == nil {
					t.Fatalf("validation accepted unsafe path: results=%v error=%v", results, err)
				}
			}
			v := &Validator{}
			snapshot, snapshotErr := v.policyTreeSnapshot(context.Background(), client, "foo", "bar", "head")
			if tc.wantError && tc.parentMode != "120000" && snapshotErr == nil {
				t.Fatalf("snapshot accepted unsafe path: %v", snapshot)
			}
			if tc.parentMode == "120000" && (snapshotErr != nil || len(snapshot) != 0) {
				t.Fatalf("unrelated symlink should be ignored: snapshot=%v error=%v", snapshot, snapshotErr)
			}
			if !tc.wantError && (snapshotErr != nil || snapshot[".github/chainguard/nested/test.sts.yaml"] != "blob") {
				t.Fatalf("snapshot = %v, error = %v", snapshot, snapshotErr)
			}
		})
	}
}

func TestRecursiveAuditNames(t *testing.T) {
	v := &Validator{PolicyDir: "custom/policies"}
	changes := v.policyChangesFromCompare(context.Background(), "repo", []*github.CommitFile{{
		Filename: new("custom/policies/new/foo.sts.yaml"), PreviousFilename: new("custom/policies/old/foo.sts.yaml"), Status: new("renamed"),
	}})
	if len(changes) != 2 || changes[0].Policy != "new/foo" || changes[1].Policy != "old/foo" {
		t.Fatal(fmt.Sprintf("unexpected changes: %+v", changes))
	}
}

func TestLargePRRejectsNestedSymlinkPolicy(t *testing.T) {
	client := discoveryClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entry := func(name, typ, mode, sha string) *github.TreeEntry {
			return &github.TreeEntry{Path: new(name), Type: new(typ), Mode: new(mode), SHA: new(sha)}
		}
		var value any
		switch {
		case strings.HasSuffix(r.URL.Path, "/pulls/7"):
			value = &github.PullRequest{Head: &github.PullRequestBranch{SHA: new("head")}, Base: &github.PullRequestBranch{SHA: new("base")}, ChangedFiles: new(maxPRFiles + 1)}
		case strings.HasSuffix(r.URL.Path, "/git/commits/head"):
			value = &github.Commit{Tree: &github.Tree{SHA: new("root")}}
		default:
			var entries []*github.TreeEntry
			switch {
			case strings.HasSuffix(r.URL.Path, "/git/trees/root"):
				entries = []*github.TreeEntry{entry(".github", "tree", "040000", "github")}
			case strings.HasSuffix(r.URL.Path, "/git/trees/github"):
				entries = []*github.TreeEntry{entry("chainguard", "tree", "040000", "policy")}
			case strings.HasSuffix(r.URL.Path, "/git/trees/policy"):
				entries = []*github.TreeEntry{entry("nested", "tree", "040000", "nested")}
			case strings.HasSuffix(r.URL.Path, "/git/trees/nested"):
				entries = []*github.TreeEntry{entry("test.sts.yaml", "blob", "120000", "link")}
			default:
				t.Errorf("unexpected request %s", r.URL)
				http.NotFound(w, r)
				return
			}
			value = map[string]any{"tree": entries, "truncated": false}
		}
		json.NewEncoder(w).Encode(value)
	}))
	_, err := (&Validator{}).prPolicyChanges(context.Background(), client, "foo", "bar", 7, "head", "foo", "bar", "bar")
	var tooLarge *prTooLargeError
	if !errors.As(err, &tooLarge) || tooLarge.scanErr == nil {
		t.Fatalf("expected failed large PR scan, got %v", err)
	}
}

func TestPolicyVerifierCachesTreesPerValidation(t *testing.T) {
	fixture := regularPolicyFixture("bar", []string{
		".github/chainguard/one.sts.yaml", ".github/chainguard/two.sts.yaml",
		".github/chainguard/nested/three.sts.yaml",
	}, "head")
	client := discoveryClient(t, fixture)
	verifier := &policyPathVerifier{client: client, owner: "foo", repo: "bar", ref: "head"}
	for _, path := range fixture.trees["head"] {
		if err := verifier.verify(context.Background(), path); err != nil {
			t.Fatal(err)
		}
	}
	// One commit, three shared trees, one nested tree.
	if got := fixture.calls.Load(); got != 5 {
		t.Fatalf("Git calls = %d, want 5", got)
	}
}

// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v88/github"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestReadRegularPolicy(t *testing.T) {
	const a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const c = "cccccccccccccccccccccccccccccccccccccccc"
	const d = "dddddddddddddddddddddddddddddddddddddddd"
	blob := gitBlobID([]byte("policy"), 40)
	entry := func(path, mode, typ, sha string) *github.TreeEntry {
		return &github.TreeEntry{Path: &path, Mode: &mode, Type: &typ, SHA: &sha, Size: new(6)}
	}
	oversized := entry("identity.sts.yaml", "100644", "blob", blob)
	oversized.Size = new(maxPolicyBlobSize + 1)
	tests := []struct {
		name      string
		root      *github.Tree
		sub       *github.Tree
		wantFile  bool
		want404   bool
		wantBlob  bool
		blobCode  int
		wantError int
		blobData  string
		blobSize  int
	}{
		{name: "regular", root: &github.Tree{Entries: []*github.TreeEntry{entry("policies", "040000", "tree", c)}, Truncated: new(false)}, sub: &github.Tree{Entries: []*github.TreeEntry{entry("identity.sts.yaml", "100644", "blob", blob)}, Truncated: new(false)}, wantFile: true, wantBlob: true},
		{name: "executable", root: &github.Tree{Entries: []*github.TreeEntry{entry("policies", "040000", "tree", c)}, Truncated: new(false)}, sub: &github.Tree{Entries: []*github.TreeEntry{entry("identity.sts.yaml", "100755", "blob", blob)}, Truncated: new(false)}, wantFile: true, wantBlob: true},
		{name: "parent symlink", root: &github.Tree{Entries: []*github.TreeEntry{entry("policies", "120000", "blob", c)}, Truncated: new(false)}},
		{name: "leaf symlink", root: &github.Tree{Entries: []*github.TreeEntry{entry("policies", "040000", "tree", c)}, Truncated: new(false)}, sub: &github.Tree{Entries: []*github.TreeEntry{entry("identity.sts.yaml", "120000", "blob", blob)}, Truncated: new(false)}},
		{name: "submodule", root: &github.Tree{Entries: []*github.TreeEntry{entry("policies", "160000", "commit", c)}, Truncated: new(false)}},
		{name: "truncated", root: &github.Tree{Entries: []*github.TreeEntry{entry("policies", "040000", "tree", c)}, Truncated: new(true)}},
		{name: "missing metadata", root: &github.Tree{Entries: []*github.TreeEntry{entry("policies", "040000", "tree", c)}}},
		{name: "missing path", root: &github.Tree{Entries: []*github.TreeEntry{entry("other", "040000", "tree", c)}, Truncated: new(false)}, want404: true},
		{name: "nil entry hides path", root: &github.Tree{Entries: []*github.TreeEntry{nil}, Truncated: new(false)}},
		{name: "missing entry path", root: &github.Tree{Entries: []*github.TreeEntry{{Mode: new("040000"), Type: new("tree"), SHA: new(c)}}, Truncated: new(false)}},
		{name: "incomplete unrelated entry", root: &github.Tree{Entries: []*github.TreeEntry{entry("other", "", "tree", c)}, Truncated: new(false)}},
		{name: "duplicate", root: &github.Tree{Entries: []*github.TreeEntry{entry("policies", "040000", "tree", c), entry("policies", "120000", "blob", d)}, Truncated: new(false)}},
		{name: "duplicate unrelated entries", root: &github.Tree{Entries: []*github.TreeEntry{entry("other", "040000", "tree", c), entry("other", "120000", "blob", d)}, Truncated: new(false)}},
		{name: "blob missing", root: &github.Tree{Entries: []*github.TreeEntry{entry("policies", "040000", "tree", c)}, Truncated: new(false)}, sub: &github.Tree{Entries: []*github.TreeEntry{entry("identity.sts.yaml", "100644", "blob", blob)}, Truncated: new(false)}, wantBlob: true, blobCode: 404},
		{name: "rate limited", root: &github.Tree{Entries: []*github.TreeEntry{entry("policies", "040000", "tree", c)}, Truncated: new(false)}, sub: &github.Tree{Entries: []*github.TreeEntry{entry("identity.sts.yaml", "100644", "blob", blob)}, Truncated: new(false)}, wantBlob: true, blobCode: 429, wantError: 429},
		{name: "truncated blob", root: &github.Tree{Entries: []*github.TreeEntry{entry("policies", "040000", "tree", c)}, Truncated: new(false)}, sub: &github.Tree{Entries: []*github.TreeEntry{entry("identity.sts.yaml", "100644", "blob", blob)}, Truncated: new(false)}, wantBlob: true, blobData: "poli", blobSize: 6},
		{name: "forged blob", root: &github.Tree{Entries: []*github.TreeEntry{entry("policies", "040000", "tree", c)}, Truncated: new(false)}, sub: &github.Tree{Entries: []*github.TreeEntry{entry("identity.sts.yaml", "100644", "blob", blob)}, Truncated: new(false)}, wantBlob: true, blobData: "attack", blobSize: 6},
		{name: "oversized blob rejected before fetch", root: &github.Tree{Entries: []*github.TreeEntry{entry("policies", "040000", "tree", c)}, Truncated: new(false)}, sub: &github.Tree{Entries: []*github.TreeEntry{oversized}, Truncated: new(false)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.root.SHA = new(b)
			if tt.sub != nil {
				tt.sub.SHA = new(c)
			}
			blobCalled := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.RawQuery != "" {
					t.Errorf("unexpected query: %s", r.URL.RawQuery)
				}
				switch strings.TrimPrefix(r.URL.Path, "/api/v3") {
				case "/repos/org/repo":
					fmt.Fprint(w, `{"default_branch":"main"}`)
				case "/repos/org/repo/commits/heads/main":
					fmt.Fprintf(w, `{"sha":%q,"commit":{"tree":{"sha":%q}}}`, a, b)
				case "/repos/org/repo/git/trees/" + b:
					json.NewEncoder(w).Encode(tt.root)
				case "/repos/org/repo/git/trees/" + c:
					json.NewEncoder(w).Encode(tt.sub)
				case "/repos/org/repo/git/blobs/" + blob:
					blobCalled = true
					if tt.blobCode != 0 {
						http.Error(w, "failure", tt.blobCode)
						return
					}
					content, size := "policy", 6
					if tt.blobData != "" {
						content, size = tt.blobData, tt.blobSize
					}
					fmt.Fprintf(w, `{"sha":%q,"size":%d,"encoding":"base64","content":%q}`, blob, size, base64.StdEncoding.EncodeToString([]byte(content)))
				default:
					t.Errorf("unexpected request: %s", r.URL.Path)
					http.Error(w, "unexpected", 500)
				}
			}))
			defer server.Close()
			client, err := newGitHubClient(server.Client().Transport, server.URL+"/")
			if err != nil {
				t.Fatal(err)
			}
			file, err := readRegularPolicy(context.Background(), client, "org", "repo", "policies/identity.sts.yaml")
			if (file != nil) != tt.wantFile || blobCalled != tt.wantBlob || isContentsNotFound(err) != tt.want404 {
				t.Fatalf("file=%v err=%v blobCalled=%v", file, err, blobCalled)
			}
			if tt.wantError != 0 {
				if err == nil || !strings.Contains(err.Error(), fmt.Sprint(tt.wantError)) {
					t.Fatalf("want HTTP %d, got %v", tt.wantError, err)
				}
			} else if !tt.want404 && !tt.wantFile && !errors.Is(err, errUnsafePolicyPath) {
				t.Fatalf("want unsafe path error, got %v", err)
			} else if tt.wantFile && err != nil {
				t.Fatal(err)
			}
			if file != nil {
				content, err := file.GetContent()
				if err != nil || content != "policy" {
					t.Fatalf("content=%q err=%v", content, err)
				}
			}
		})
	}
}

// fakePolicyGit exposes immutable tree/blob fixtures for tests that exercise
// policy reads. Paths are full repository-relative paths.
func fakePolicyGit(mux *http.ServeMux, files func(owner, repo string) map[string]string, onBlob func()) {
	sha := func(s string) string { return fmt.Sprintf("%x", sha1.Sum([]byte(s))) }
	const commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	mux.HandleFunc("/repos/{org}/{repo}", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"default_branch":"main"}`)
	})
	mux.HandleFunc("/repos/{org}/{repo}/commits/{ref}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("ref") != "heads/main" {
			http.Error(w, "unexpected ref", http.StatusNotFound)
			return
		}
		fmt.Fprintf(w, `{"sha":%q,"commit":{"tree":{"sha":%q}}}`, commit, sha("tree:"))
	})
	mux.HandleFunc("/repos/{org}/{repo}/git/trees/{sha}", func(w http.ResponseWriter, r *http.Request) {
		paths := files(r.PathValue("org"), r.PathValue("repo"))
		trees := map[string]map[string]*github.TreeEntry{"": {}}
		for filename := range paths {
			parts := strings.Split(filename, "/")
			parent := ""
			for i, part := range parts {
				full := strings.TrimPrefix(parent+"/"+part, "/")
				mode, typ, id := "040000", "tree", sha("tree:"+full)
				if i == len(parts)-1 {
					mode, typ, id = "100644", "blob", gitBlobID([]byte(paths[filename]), 40)
				} else if trees[full] == nil {
					trees[full] = map[string]*github.TreeEntry{}
				}
				trees[parent][part] = &github.TreeEntry{Path: new(part), Mode: new(mode), Type: new(typ), SHA: new(id), Size: new(len(paths[filename]))}
				parent = full
			}
		}
		for path, entries := range trees {
			if sha("tree:"+path) == r.PathValue("sha") {
				keys := make([]string, 0, len(entries))
				for key := range entries {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				list := make([]*github.TreeEntry, 0, len(keys))
				for _, key := range keys {
					list = append(list, entries[key])
				}
				json.NewEncoder(w).Encode(map[string]any{"sha": r.PathValue("sha"), "tree": list, "truncated": false})
				return
			}
		}
		writeGitHubNotFound(w)
	})
	mux.HandleFunc("/repos/{org}/{repo}/git/blobs/{sha}", func(w http.ResponseWriter, r *http.Request) {
		for path, content := range files(r.PathValue("org"), r.PathValue("repo")) {
			_ = path
			id := gitBlobID([]byte(content), 40)
			if id == r.PathValue("sha") {
				if onBlob != nil {
					onBlob()
				}
				json.NewEncoder(w).Encode(github.Blob{SHA: new(id), Size: new(len(content)), Encoding: new("base64"), Content: new(base64.StdEncoding.EncodeToString([]byte(content)))})
				return
			}
		}
		writeGitHubNotFound(w)
	})
}

func TestUnsafeOrgIssuerPathFailsClosed(t *testing.T) {
	const owner = "unsafe-issuer-path"
	cleanupOrgIssuers(t, owner)
	staleOrgIssuers.Add(owner, absentOrgIssuerEntry())
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations/{id}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(github.InstallationToken{Token: new("token"), ExpiresAt: &github.Timestamp{Time: time.Now().Add(time.Hour)}})
	})
	mux.HandleFunc("/repos/{owner}/{repo}", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"default_branch":"main"}`) })
	mux.HandleFunc("/repos/{owner}/{repo}/commits/{ref}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("ref") != "heads/main" {
			t.Errorf("unexpected ref %q", r.PathValue("ref"))
		}
		fmt.Fprint(w, `{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","commit":{"tree":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`)
	})
	mux.HandleFunc("/repos/{owner}/{repo}/git/trees/{sha}", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","truncated":false,"tree":[{"path":".github","mode":"120000","type":"blob","sha":"cccccccccccccccccccccccccccccccccccccccc"}]}`)
	})
	result := (&sts{}).fetchOrgIssuersOnce(t.Context(), newAppsTransport(t, mux), 1234, owner)
	if result.kind != fetchOK || result.entry.state != orgIssuerInvalid || status.Code(result.entry.err) != codes.FailedPrecondition {
		t.Fatalf("unsafe allowlist result = %+v", result)
	}
	if _, ok := staleOrgIssuers.Get(owner); ok {
		t.Fatal("unsafe allowlist retained stale absent entry")
	}
}

func TestPolicyRepository404IsNotAbsence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeGitHubNotFound(w)
	}))
	defer server.Close()
	client, err := newGitHubClient(server.Client().Transport, server.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	_, err = readRegularPolicy(t.Context(), client, "org", "repo", ".github/chainguard/trusted-token-issuers.yaml")
	if !errors.Is(err, errUnsafePolicyPath) || isContentsNotFound(err) {
		t.Fatalf("repository 404 classified as absence: %v", err)
	}
}

func TestGitBlobID(t *testing.T) {
	// Generated by git hash-object and git hash-object in a sha256 repository.
	if got := gitBlobID([]byte("test content\n"), 40); got != "d670460b4b4aece5915caf5c68d12f560a9fe3e4" {
		t.Fatalf("SHA-1 = %s", got)
	}
	if got := gitBlobID([]byte("test content\n"), 64); got != "13b7e821533d3fe3728a3c4560606a65aab99f4390b9df0714f9075c0ef4c2d6" {
		t.Fatalf("SHA-256 = %s", got)
	}
}

func TestPolicyDefaultBranchEscaped(t *testing.T) {
	const root = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/repos/org/repo"):
			fmt.Fprint(w, `{"default_branch":"release/v1"}`)
		case strings.Contains(r.URL.EscapedPath(), "/commits/"):
			if !strings.HasSuffix(r.URL.EscapedPath(), "/commits/heads%2Frelease%2Fv1") {
				t.Errorf("branch escaped path = %q", r.URL.EscapedPath())
			}
			fmt.Fprintf(w, `{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","commit":{"tree":{"sha":%q}}}`, root)
		case strings.HasSuffix(r.URL.Path, "/git/trees/"+root):
			fmt.Fprintf(w, `{"sha":%q,"truncated":false,"tree":[]}`, root)
		default:
			t.Errorf("unexpected request %s", r.URL.EscapedPath())
			w.WriteHeader(500)
		}
	}))
	defer server.Close()
	client, err := newGitHubClient(server.Client().Transport, server.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	_, err = readRegularPolicy(t.Context(), client, "org", "repo", "missing")
	if !isContentsNotFound(err) {
		t.Fatalf("expected missing path: %v", err)
	}
}

func TestPolicyDefaultBranchWinsTagCollision(t *testing.T) {
	const commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const branchTree = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const tagTree = "cccccccccccccccccccccccccccccccccccccccc"
	const branchPolicy = "branch policy"
	const tagPolicy = "tag policy"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/repos/org/repo"):
			fmt.Fprint(w, `{"default_branch":"release/v1"}`)
		case strings.Contains(r.URL.EscapedPath(), "/commits/"):
			tree := tagTree // Unqualified ref resolves to the colliding tag.
			if strings.HasSuffix(r.URL.EscapedPath(), "/commits/heads%2Frelease%2Fv1") {
				tree = branchTree
			}
			fmt.Fprintf(w, `{"sha":%q,"commit":{"tree":{"sha":%q}}}`, commit, tree)
		case strings.Contains(r.URL.Path, "/git/trees/"):
			content, tree := branchPolicy, branchTree
			if strings.HasSuffix(r.URL.Path, tagTree) {
				content, tree = tagPolicy, tagTree
			}
			fmt.Fprintf(w, `{"sha":%q,"truncated":false,"tree":[{"path":"policy","mode":"100644","type":"blob","sha":%q,"size":%d}]}`, tree, gitBlobID([]byte(content), 40), len(content))
		case strings.Contains(r.URL.Path, "/git/blobs/"):
			content := branchPolicy
			if strings.HasSuffix(r.URL.Path, gitBlobID([]byte(tagPolicy), 40)) {
				content = tagPolicy
			}
			fmt.Fprintf(w, `{"sha":%q,"size":%d,"encoding":"base64","content":%q}`, gitBlobID([]byte(content), 40), len(content), base64.StdEncoding.EncodeToString([]byte(content)))
		default:
			t.Errorf("unexpected request %s", r.URL.EscapedPath())
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	client, err := newGitHubClient(server.Client().Transport, server.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	file, err := readRegularPolicy(t.Context(), client, "org", "repo", "policy")
	if err != nil || file == nil {
		t.Fatalf("read policy: file=%v err=%v", file, err)
	}
	content, err := file.GetContent()
	if err != nil || content != branchPolicy {
		t.Fatalf("policy = %q, err = %v; want branch policy", content, err)
	}
}

func TestPolicyBlobResponseLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 2*maxPolicyBlobSize+65537))
	}))
	defer server.Close()
	client, err := newGitHubClient(server.Client().Transport, server.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	_, err = getLimitedPolicyBlob(t.Context(), client, "org", "repo", strings.Repeat("a", 40))
	if !errors.Is(err, errUnsafePolicyPath) {
		t.Fatalf("oversized response = %v", err)
	}
}

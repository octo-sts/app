// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-github/v88/github"
)

func snapshotEntry(name, typ, sha string) *github.TreeEntry {
	mode := "100644"
	if typ == "tree" {
		mode = "040000"
	}
	return &github.TreeEntry{Path: new(name), Type: new(typ), Mode: new(mode), SHA: new(sha)}
}

func snapshotFixture(t *testing.T, trees map[string][]*github.TreeEntry) (*github.Client, map[string]int) {
	t.Helper()
	reads := make(map[string]int)
	client := discoveryClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/git/commits/") {
			json.NewEncoder(w).Encode(&github.Commit{Tree: &github.Tree{SHA: new("root")}})
			return
		}
		sha := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		reads[sha]++
		entries, ok := trees[sha]
		if !ok {
			t.Errorf("unexpected tree %s", sha)
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"tree": entries, "truncated": false})
	}))
	return client, reads
}

func TestSnapshotSharedTreeFanout(t *testing.T) {
	// Every path must be expanded even when several directories share a SHA.
	trees := map[string][]*github.TreeEntry{
		"root":   {snapshotEntry("policies", "tree", "parent")},
		"parent": {snapshotEntry("one", "tree", "shared"), snapshotEntry("two", "tree", "shared")},
		"shared": {snapshotEntry("nested", "tree", "leaf")},
		"leaf":   {snapshotEntry("x.sts.yaml", "blob", "blob")},
	}
	client, reads := snapshotFixture(t, trees)
	files, err := (&Validator{PolicyDir: "policies"}).policyTreeSnapshot(t.Context(), client, "o", "r", "head")
	if err != nil || len(files) != 2 || files["policies/one/nested/x.sts.yaml"] != "blob" || files["policies/two/nested/x.sts.yaml"] != "blob" {
		t.Fatalf("files=%v err=%v", files, err)
	}
	for _, sha := range []string{"root", "parent", "shared", "leaf"} {
		if reads[sha] != 1 {
			t.Errorf("tree %s read %d times, want once", sha, reads[sha])
		}
	}
}

func TestSnapshotPathLimit(t *testing.T) {
	for _, count := range []int{maxPolicySnapshotPaths - 1, maxPolicySnapshotPaths} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			entries := make([]*github.TreeEntry, count)
			for i := range entries {
				entries[i] = snapshotEntry(fmt.Sprintf("%05d.txt", i), "blob", "blob")
			}
			entries[0] = snapshotEntry("valid.sts.yaml", "blob", "blob")
			client, _ := snapshotFixture(t, map[string][]*github.TreeEntry{
				"root": {snapshotEntry("policies", "tree", "policy")}, "policy": entries,
			})
			files, err := (&Validator{PolicyDir: "policies"}).policyTreeSnapshot(t.Context(), client, "o", "r", "head")
			if count == maxPolicySnapshotPaths-1 {
				if err != nil || files["policies/valid.sts.yaml"] != "blob" {
					t.Fatalf("at limit: files=%v err=%v", files, err)
				}
			} else if files != nil || !errors.Is(err, errPolicySnapshotLimit) || !strings.Contains(err.Error(), "exceeds 10000 paths") {
				t.Fatalf("over limit: files=%v err=%v", files, err)
			}
		})
	}
}

func TestSnapshotSharedTreeAmplificationBounded(t *testing.T) {
	// A compact binary DAG expands many paths despite only 9 distinct SHAs.
	trees := map[string][]*github.TreeEntry{
		"root": {snapshotEntry("policies", "tree", "level0")},
	}
	for i := range 8 {
		next := fmt.Sprintf("level%d", i+1)
		trees[fmt.Sprintf("level%d", i)] = []*github.TreeEntry{
			snapshotEntry("a", "tree", next), snapshotEntry("b", "tree", next),
		}
	}
	leaf := make([]*github.TreeEntry, 100)
	for i := range leaf {
		leaf[i] = snapshotEntry(fmt.Sprintf("%03d.txt", i), "blob", "blob")
	}
	trees["level8"] = leaf
	client, reads := snapshotFixture(t, trees)
	files, err := (&Validator{PolicyDir: "policies"}).policyTreeSnapshot(t.Context(), client, "o", "r", "head")
	if files != nil || !errors.Is(err, errPolicySnapshotLimit) || !strings.Contains(err.Error(), "exceeds 10000 paths") {
		t.Fatalf("files=%v err=%v", files, err)
	}
	for sha, count := range reads {
		if count != 1 {
			t.Errorf("tree %s read %d times, want once", sha, count)
		}
	}
}

func TestSnapshotDirectoryLimit(t *testing.T) {
	for _, shared := range []bool{false, true} {
		for _, count := range []int{maxPolicySnapshotDirs - 1, maxPolicySnapshotDirs} {
			t.Run(fmt.Sprintf("shared=%t/count=%d", shared, count), func(t *testing.T) {
				trees := map[string][]*github.TreeEntry{"root": {snapshotEntry("policies", "tree", "policy")}}
				entries := make([]*github.TreeEntry, count)
				for i := range entries {
					sha := fmt.Sprintf("dir%d", i)
					if shared {
						sha = "shared"
					}
					entries[i] = snapshotEntry(fmt.Sprintf("dir%d", i), "tree", sha)
					trees[sha] = []*github.TreeEntry{}
				}
				trees["policy"] = entries
				client, reads := snapshotFixture(t, trees)
				files, err := (&Validator{PolicyDir: "policies"}).policyTreeSnapshot(t.Context(), client, "o", "r", "head")
				if count == maxPolicySnapshotDirs-1 {
					if err != nil || len(files) != 0 {
						t.Fatalf("at limit: files=%v err=%v", files, err)
					}
					if shared && reads["shared"] != 1 {
						t.Fatalf("shared tree reads=%d, want 1", reads["shared"])
					}
				} else if files != nil || !errors.Is(err, errPolicySnapshotLimit) || !strings.Contains(err.Error(), "exceeds 512 directories") || len(reads) != 2 {
					t.Fatalf("over limit: files=%v err=%v tree requests=%d", files, err, len(reads))
				}
			})
		}
	}
}

func TestSnapshotDepthLimit(t *testing.T) {
	for _, depth := range []int{maxPolicySnapshotDepth, maxPolicySnapshotDepth + 1} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			trees := map[string][]*github.TreeEntry{
				"root": {snapshotEntry("policies", "tree", "level0")},
			}
			for i := range depth {
				trees[fmt.Sprintf("level%d", i)] = []*github.TreeEntry{snapshotEntry("dir", "tree", fmt.Sprintf("level%d", i+1))}
			}
			trees[fmt.Sprintf("level%d", depth)] = []*github.TreeEntry{snapshotEntry("valid.sts.yaml", "blob", "blob")}
			client, reads := snapshotFixture(t, trees)
			files, err := (&Validator{PolicyDir: "policies"}).policyTreeSnapshot(t.Context(), client, "o", "r", "head")
			if depth == maxPolicySnapshotDepth {
				if err != nil || len(files) != 1 {
					t.Fatalf("at limit: files=%v err=%v", files, err)
				}
			} else if files != nil || !errors.Is(err, errPolicySnapshotLimit) || !strings.Contains(err.Error(), "exceeds directory depth 32") || reads[fmt.Sprintf("level%d", depth)] != 0 {
				t.Fatalf("over limit: files=%v err=%v reads=%v", files, err, reads)
			}
		})
	}
}

func TestPushSnapshotLimitFailsClosed(t *testing.T) {
	const policy = ".github/chainguard/valid.sts.yaml"
	for _, mode := range []string{"forced", "compare-truncated", "new-ref", "no-common-ancestor"} {
		for _, over := range []string{"after", "before"} {
			if over == "before" && (mode == "new-ref" || mode == "no-common-ancestor") {
				continue
			}
			t.Run(mode+"/"+over, func(t *testing.T) {
				checks, contents := 0, 0
				var conclusion string
				transport := forkCheckSuiteClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					path := r.URL.Path
					switch {
					case strings.Contains(path, "/compare/"):
						if mode == "no-common-ancestor" {
							w.WriteHeader(http.StatusNotFound)
							fmt.Fprint(w, `{"message":"No common ancestor between before and after"}`)
							return
						}
						files := make([]*github.CommitFile, compareFileCap)
						for i := range files {
							files[i] = &github.CommitFile{Filename: new(fmt.Sprintf("other/%d", i)), Status: new("modified")}
						}
						json.NewEncoder(w).Encode(&github.CommitsComparison{Files: files})
					case strings.Contains(path, "/git/commits/"):
						ref := path[strings.LastIndex(path, "/")+1:]
						json.NewEncoder(w).Encode(&github.Commit{Tree: &github.Tree{SHA: new(ref + "-root")}})
					case strings.Contains(path, "/git/trees/"):
						sha := path[strings.LastIndex(path, "/")+1:]
						ref := strings.SplitN(sha, "-", 2)[0]
						var entries []*github.TreeEntry
						switch {
						case strings.HasSuffix(sha, "-root"):
							entries = []*github.TreeEntry{snapshotEntry(".github", "tree", ref+"-github")}
						case strings.HasSuffix(sha, "-github"):
							entries = []*github.TreeEntry{snapshotEntry("chainguard", "tree", ref+"-policy")}
						case strings.HasSuffix(sha, "-policy"):
							entries = []*github.TreeEntry{snapshotEntry("valid.sts.yaml", "blob", "blob")}
							if ref == over {
								for i := range maxPolicySnapshotDirs {
									entries = append(entries, snapshotEntry(fmt.Sprintf("dir%d", i), "tree", "shared"))
								}
							}
						default:
							t.Errorf("unexpected tree %s", sha)
						}
						json.NewEncoder(w).Encode(map[string]any{"tree": entries, "truncated": false})
					case strings.Contains(path, "/contents/"):
						contents++
						json.NewEncoder(w).Encode(largePRContent("issuer: https://token.actions.githubusercontent.com\nsubject: s\n"))
					case strings.HasSuffix(path, "/check-runs"):
						checks++
						var options github.CreateCheckRunOptions
						if err := json.NewDecoder(r.Body).Decode(&options); err != nil {
							t.Error(err)
						}
						conclusion = options.GetConclusion()
						json.NewEncoder(w).Encode(&github.CheckRun{})
					default:
						t.Errorf("unexpected request %s", r.URL)
						http.NotFound(w, r)
					}
				}))
				ce := &fakeCEClient{}
				emitter := newPolicyEmitter(ce, 1, 64)
				v := &Validator{Transport: transport, Emitter: emitter}
				commits := []*github.HeadCommit{{Modified: []string{policy}}}
				before := "before"
				if mode == "new-ref" {
					before = zeroHash
					commits = append(commits, make([]*github.HeadCommit, 19)...)
				}
				event := &github.PushEvent{
					Installation: &github.Installation{ID: new(int64(1111))},
					Repo:         &github.PushEventRepository{Owner: &github.User{Login: new("foo")}, Name: new("bar"), FullName: new("foo/bar"), DefaultBranch: new("main")},
					Ref:          new("refs/heads/main"), Before: &before, After: new("after"), Forced: new(mode == "forced"), Commits: commits,
				}
				_, err := v.handlePush(t.Context(), event)
				events := drainEvents(t, emitter, ce)
				if len(events) == 0 {
					t.Fatal("missing degraded audit marker")
				}
				var marker PolicyEvent
				if err := json.Unmarshal(events[0].Data(), &marker); err != nil {
					t.Fatal(err)
				}
				if marker.Detection != DetectionDegraded || marker.DetectionError == "" || marker.Change != nil {
					t.Fatalf("marker=%+v", marker)
				}
				if over == "after" {
					if !errors.Is(err, errPolicySnapshotLimit) || checks != 0 || contents != 0 || marker.PushError == "" {
						t.Fatalf("after limit: err=%v checks=%d contents=%d marker=%+v", err, checks, contents, marker)
					}
				} else if err != nil || checks != 1 || contents != 1 || conclusion != "success" {
					t.Fatalf("before limit: err=%v checks=%d contents=%d conclusion=%q", err, checks, contents, conclusion)
				}
			})
		}
	}
}

func TestPushRecursiveSnapshotFailures(t *testing.T) {
	const policy = ".github/chainguard/valid.sts.yaml"
	for _, mode := range []string{"forced", "compare"} {
		for _, stage := range []string{"after", "before"} {
			for _, failure := range []string{"nested-truncated", "nested-500", "nested-429", "invalid-mode", "invalid-path", "symlink", "parent-mode", "root-500"} {
				t.Run(mode+"/"+stage+"/"+failure, func(t *testing.T) {
					checks, contents := 0, 0
					rootFailed := false
					var conclusion string
					transport := forkCheckSuiteClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						path := r.URL.Path
						switch {
						case strings.Contains(path, "/compare/"):
							files := make([]*github.CommitFile, compareFileCap)
							for i := range files {
								files[i] = &github.CommitFile{Filename: new(fmt.Sprintf("other/%d", i)), Status: new("modified")}
							}
							json.NewEncoder(w).Encode(&github.CommitsComparison{Files: files})
						case strings.Contains(path, "/git/commits/"):
							ref := path[strings.LastIndex(path, "/")+1:]
							json.NewEncoder(w).Encode(&github.Commit{Tree: &github.Tree{SHA: new(ref + "-root")}})
						case strings.Contains(path, "/git/trees/"):
							sha := path[strings.LastIndex(path, "/")+1:]
							ref := strings.SplitN(sha, "-", 2)[0]
							failed := ref == stage
							var entries []*github.TreeEntry
							switch {
							case strings.HasSuffix(sha, "-root"):
								entries = []*github.TreeEntry{snapshotEntry(".github", "tree", ref+"-github")}
							case strings.HasSuffix(sha, "-github"):
								entries = []*github.TreeEntry{snapshotEntry("chainguard", "tree", ref+"-policy")}
								if failed && failure == "parent-mode" {
									entries[0].Mode = new("100644")
								}
							case strings.HasSuffix(sha, "-policy"):
								if failed && failure == "root-500" && !rootFailed {
									rootFailed = true
									http.Error(w, "root failure", http.StatusInternalServerError)
									return
								}
								entries = []*github.TreeEntry{snapshotEntry("valid.sts.yaml", "blob", "blob")}
								if failed {
									switch failure {
									case "invalid-mode":
										entries[0].Mode = new("bad")
									case "invalid-path":
										entries = append(entries, snapshotEntry("invalid/path", "blob", "blob"))
									case "symlink":
										entries[0].Mode = new("120000")
									default:
										entries = append(entries, snapshotEntry("nested", "tree", ref+"-nested"))
									}
								}
							case strings.HasSuffix(sha, "-nested"):
								switch failure {
								case "nested-500":
									http.Error(w, "nested failure", http.StatusInternalServerError)
									return
								case "nested-429":
									http.Error(w, "rate limit", http.StatusTooManyRequests)
									return
								case "nested-truncated":
									fmt.Fprint(w, `{"tree":[],"truncated":true}`)
									return
								}
							default:
								t.Errorf("unexpected tree %s", sha)
							}
							json.NewEncoder(w).Encode(map[string]any{"tree": entries, "truncated": false})
						case strings.Contains(path, "/contents/"):
							contents++
							json.NewEncoder(w).Encode(largePRContent("issuer: https://token.actions.githubusercontent.com\nsubject: s\n"))
						case strings.HasSuffix(path, "/check-runs"):
							checks++
							var options github.CreateCheckRunOptions
							if err := json.NewDecoder(r.Body).Decode(&options); err != nil {
								t.Error(err)
							}
							conclusion = options.GetConclusion()
							json.NewEncoder(w).Encode(&github.CheckRun{})
						default:
							t.Errorf("unexpected request %s", r.URL)
							http.NotFound(w, r)
						}
					}))
					ce := &fakeCEClient{}
					emitter := newPolicyEmitter(ce, 1, 64)
					v := &Validator{Transport: transport, Emitter: emitter}
					event := &github.PushEvent{
						Installation: &github.Installation{ID: new(int64(1111))},
						Repo:         &github.PushEventRepository{Owner: &github.User{Login: new("foo")}, Name: new("bar"), FullName: new("foo/bar"), DefaultBranch: new("main")},
						Ref:          new("refs/heads/main"), Before: new("before"), After: new("after"), Forced: new(mode == "forced"),
						Commits: []*github.HeadCommit{{Modified: []string{policy}}},
					}
					_, err := v.handlePush(t.Context(), event)
					events := drainEvents(t, emitter, ce)
					if len(events) == 0 {
						t.Fatal("missing audit marker")
					}
					var marker PolicyEvent
					if err := json.Unmarshal(events[0].Data(), &marker); err != nil {
						t.Fatal(err)
					}
					if marker.Detection != DetectionDegraded || marker.DetectionError == "" || marker.Change != nil {
						t.Fatalf("marker=%+v", marker)
					}
					switch {
					case failure == "nested-429":
						if err != nil || checks != 0 || contents != 0 {
							t.Fatalf("rate limit: err=%v checks=%d contents=%d", err, checks, contents)
						}
					case stage == "after" && failure != "root-500":
						if !errors.Is(err, errPolicySnapshotIncomplete) || checks != 0 || contents != 0 || marker.PushError == "" {
							t.Fatalf("after failure: err=%v checks=%d contents=%d marker=%+v", err, checks, contents, marker)
						}
					default:
						if err != nil || checks != 1 || contents != 1 || conclusion != "success" {
							t.Fatalf("fallback: err=%v checks=%d contents=%d conclusion=%q", err, checks, contents, conclusion)
						}
					}
				})
			}
		}
	}
}

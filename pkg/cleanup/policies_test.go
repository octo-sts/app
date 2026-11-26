// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package cleanup

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-github/v88/github"
)

const policyDir = ".github/chainguard"
const snapshotOID = "0123456789abcdef0123456789abcdef01234567"

var changed = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

type entry struct{ name, typ string }

// fakeRepo is one repository the installation can see.
type fakeRepo struct {
	owner, name    string
	archived, fork bool
	// noDir means the repository has no policy directory.
	noDir bool
	// gone means the repository is listed but deleted before it is queried.
	gone    bool
	entries []entry
	// modes overrides default Git modes by policy-root-relative path.
	modes map[string]int
	// dirs maps paths relative to policyDir to their entries.
	dirs map[string][]entry
	// dates maps a relative file path to its last change; files missing here have no
	// history.
	dates map[string]time.Time
	// branch is the default branch, "main" when empty.
	branch string
}

func defaultRepos() []fakeRepo {
	return []fakeRepo{{
		owner: "acme", name: "svc",
		entries: []entry{
			{"README.md", "blob"},
			{"deploy.sts.yaml", "blob"},
			{"nested.sts.yaml", "tree"},
			{"release.sts.yaml", "blob"},
			{".sts.yaml", "blob"},
		},
		dirs:  map[string][]entry{"nested.sts.yaml": {}},
		dates: map[string]time.Time{"deploy.sts.yaml": changed, "release.sts.yaml": changed},
	}, {
		owner: "acme", name: "old", archived: true,
		entries: []entry{{"archived.sts.yaml", "blob"}},
	}, {
		owner: "other", name: "svc",
		entries: []entry{{"foreign.sts.yaml", "blob"}},
	}, {
		owner: "acme", name: "fork", fork: true, branch: "trunk",
		entries: []entry{{"upstream.sts.yaml", "blob"}},
		dates:   map[string]time.Time{"upstream.sts.yaml": changed},
	}, {
		owner: "acme", name: ".github",
		entries: []entry{{"octo-sts-cleanup.sts.yaml", "blob"}},
	}, {
		owner: "acme", name: "empty", noDir: true,
	}, {
		owner: "acme", name: "gone", gone: true,
	}}
}

var (
	snapshotAlias = regexp.MustCompile(`(r\d+): repository\(owner: "([^"]+)", name: "([^"]+)"\) \{ defaultBranchRef`)
	treeAlias     = regexp.MustCompile(`(r\d+): repository\(owner: "([^"]+)", name: "([^"]+)"\) \{ object\(expression: "([^"]+):([^"]+)"\)`)
	historyAlias  = regexp.MustCompile(`(r\d+): repository\(owner: "([^"]+)", name: "([^"]+)"\) \{ object\(expression: "([^"]+)"\) \{ __typename \.\.\. on Commit`)
	fileAlias     = regexp.MustCompile(`(f\d+): history\(first: 1, path: "([^"]+)"\)`)
)

// fakeGitHub serves the installation's repositories over REST, 100 per page,
// and answers the GraphQL policy and history queries from repos. graphqlErr,
// when set, replaces every GraphQL response. It returns the client and a
// counter of GraphQL queries.
func fakeGitHub(t *testing.T, repos []fakeRepo, graphqlErr http.HandlerFunc, restErr bool) (*github.Client, *atomic.Int32) {
	t.Helper()
	byName := map[string]fakeRepo{}
	for _, r := range repos {
		byName[r.owner+"/"+r.name] = r
	}
	queries := &atomic.Int32{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v3/installation/repositories":
			if restErr {
				http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
				return
			}
			page := 1
			fmt.Sscan(r.URL.Query().Get("page"), &page)
			from, to := (page-1)*100, min(page*100, len(repos))
			if to < len(repos) {
				w.Header().Set("Link", fmt.Sprintf(`<%s?page=%d>; rel="next"`, r.URL.Path, page+1))
			}
			var out []string
			for _, fr := range repos[from:to] {
				out = append(out, fmt.Sprintf(`{"name":%q,"owner":{"login":%q},"archived":%t,"fork":%t}`, fr.name, fr.owner, fr.archived, fr.fork))
			}
			fmt.Fprintf(w, `{"total_count":%d,"repositories":[%s]}`, len(repos), strings.Join(out, ","))

		case "/api/graphql":
			queries.Add(1)
			if r.Method != http.MethodPost {
				t.Errorf("graphql method = %s, want POST", r.Method)
			}
			if graphqlErr != nil {
				graphqlErr(w, r)
				return
			}
			var req struct {
				Query string `json:"query"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decoding graphql request: %v", err)
			}
			data, errs := answer(t, byName, req.Query)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "errors": errs})

		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := github.NewClient(github.WithHTTPClient(srv.Client()), github.WithEnterpriseURLs(srv.URL, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	return client, queries
}

// answer builds the data for one GraphQL query, mirroring how GitHub resolves
// a missing repository, directory or file.
func answer(t *testing.T, repos map[string]fakeRepo, query string) (map[string]any, []map[string]any) {
	t.Helper()
	data := map[string]any{}
	var errs []map[string]any
	notFound := func(alias, repo string) {
		data[alias] = nil
		errs = append(errs, map[string]any{"type": "NOT_FOUND", "path": []string{alias}, "message": "Could not resolve to a Repository with the name '" + repo + "'."})
	}

	for _, m := range snapshotAlias.FindAllStringSubmatch(query, -1) {
		alias, full := m[1], m[2]+"/"+m[3]
		r, ok := repos[full]
		if !ok || r.gone {
			notFound(alias, full)
			continue
		}
		data[alias] = map[string]any{"defaultBranchRef": map[string]any{"name": cmp.Or(r.branch, "main"), "target": map[string]string{"__typename": "Commit", "oid": snapshotOID}}}
	}
	for _, m := range treeAlias.FindAllStringSubmatch(query, -1) {
		if !strings.Contains(query, "entries { name type mode }") {
			t.Errorf("tree query omits entry modes: %s", query)
		}
		alias, full, oid, dir := m[1], m[2]+"/"+m[3], m[4], m[5]
		if oid != snapshotOID {
			t.Errorf("tree expression for %s uses commit %s, want %s", full, oid, snapshotOID)
		}
		rel := ""
		if dir != policyDir {
			var ok bool
			rel, ok = strings.CutPrefix(dir, policyDir+"/")
			if !ok {
				t.Errorf("tree expression for %s = HEAD:%s, not under HEAD:%s", full, dir, policyDir)
			}
		}
		r, ok := repos[full]
		switch {
		case !ok || r.gone:
			notFound(alias, full)
		case r.noDir:
			data[alias] = map[string]any{"object": nil}
		default:
			dirEntries := r.entries
			if rel != "" {
				var ok bool
				dirEntries, ok = r.dirs[rel]
				if !ok {
					data[alias] = map[string]any{"object": nil}
					continue
				}
			}
			entries := []map[string]any{}
			for _, e := range dirEntries {
				mode := map[string]int{"blob": 0100644, "tree": 0040000, "commit": 0160000}[e.typ]
				key := e.name
				if rel != "" {
					key = rel + "/" + e.name
				}
				if override, ok := r.modes[key]; ok {
					mode = override
				}
				entries = append(entries, map[string]any{"name": e.name, "type": e.typ, "mode": mode})
			}
			data[alias] = map[string]any{"object": map[string]any{"__typename": "Tree", "entries": entries}}
		}
	}

	if n := len(fileAlias.FindAllString(query, -1)); n > historyPerQuery {
		t.Errorf("query asks for %d history lookups, more than %d", n, historyPerQuery)
	}

	// Each repository block lists its files on the following lines.
	blocks := historyAlias.FindAllStringSubmatchIndex(query, -1)
	for i, b := range blocks {
		alias, full := query[b[2]:b[3]], query[b[4]:b[5]]+"/"+query[b[6]:b[7]]
		if oid := query[b[8]:b[9]]; oid != snapshotOID {
			t.Errorf("history expression for %s uses commit %s, want %s", full, oid, snapshotOID)
		}
		end := len(query)
		if i+1 < len(blocks) {
			end = blocks[i+1][0]
		}
		r, ok := repos[full]
		if !ok || r.gone {
			notFound(alias, full)
			continue
		}
		target := map[string]any{"__typename": "Commit"}
		for _, f := range fileAlias.FindAllStringSubmatch(query[b[1]:end], -1) {
			name, ok := strings.CutPrefix(f[2], policyDir+"/")
			if !ok {
				t.Errorf("history path %q is not under %s", f[2], policyDir)
			}
			nodes := []map[string]string{}
			if d, ok := r.dates[name]; ok {
				nodes = append(nodes, map[string]string{"committedDate": d.Format(time.RFC3339)})
			}
			target[f[1]] = map[string]any{"nodes": nodes}
		}
		data[alias] = map[string]any{"object": target}
	}
	return data, errs
}

func TestListPolicies(t *testing.T) {
	client, queries := fakeGitHub(t, defaultRepos(), nil, false)
	got, err := ListPolicies(t.Context(), client, "acme", policyDir)
	if err != nil {
		t.Fatalf("ListPolicies() = %v", err)
	}
	want := []Policy{
		{Repo: "svc", Identity: "deploy", LastChanged: changed, DefaultBranch: "main", SnapshotSHA: snapshotOID},
		{Repo: "svc", Identity: "release", LastChanged: changed, DefaultBranch: "main", SnapshotSHA: snapshotOID},
		{Repo: "fork", Identity: "upstream", LastChanged: changed, DefaultBranch: "trunk", SnapshotSHA: snapshotOID},
		{Repo: ".github", Identity: "octo-sts-cleanup", DefaultBranch: "main", SnapshotSHA: snapshotOID},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListPolicies() =\n%+v\nwant\n%+v", got, want)
	}
	// One query per directory level, then one for the history.
	if n := queries.Load(); n != 4 {
		t.Errorf("GraphQL queries = %d, want 4", n)
	}
}

func TestListPoliciesNested(t *testing.T) {
	repos := []fakeRepo{{
		owner: "acme", name: "svc", branch: "trunk",
		entries: []entry{{"deploy.sts.yaml", "blob"}, {"team", "tree"}, {"other", "tree"}, {"link", "commit"}},
		dirs: map[string][]entry{
			"team":                      {{"deploy.sts.yaml", "blob"}, {"deep", "tree"}, {".sts.yaml", "blob"}},
			"team/deep":                 {{"deploy.sts.yaml", "blob"}, {"folder.sts.yaml", "tree"}},
			"team/deep/folder.sts.yaml": {{"policy.sts.yaml", "blob"}},
			"other":                     {{"deploy.sts.yaml", "blob"}, {"notes.yaml", "blob"}},
		},
		dates: map[string]time.Time{
			"deploy.sts.yaml":                           changed,
			"team/deploy.sts.yaml":                      changed.Add(time.Hour),
			"team/deep/deploy.sts.yaml":                 changed.Add(2 * time.Hour),
			"team/deep/folder.sts.yaml/policy.sts.yaml": changed.Add(3 * time.Hour),
			"other/deploy.sts.yaml":                     changed.Add(4 * time.Hour),
		},
	}}
	client, _ := fakeGitHub(t, repos, nil, false)
	got, err := ListPolicies(t.Context(), client, "acme", policyDir)
	if err != nil {
		t.Fatalf("ListPolicies() = %v", err)
	}
	want := []Policy{
		{Repo: "svc", Identity: "deploy", LastChanged: changed, DefaultBranch: "trunk", SnapshotSHA: snapshotOID},
		{Repo: "svc", Identity: "team/deploy", LastChanged: changed.Add(time.Hour), DefaultBranch: "trunk", SnapshotSHA: snapshotOID},
		{Repo: "svc", Identity: "other/deploy", LastChanged: changed.Add(4 * time.Hour), DefaultBranch: "trunk", SnapshotSHA: snapshotOID},
		{Repo: "svc", Identity: "team/deep/deploy", LastChanged: changed.Add(2 * time.Hour), DefaultBranch: "trunk", SnapshotSHA: snapshotOID},
		{Repo: "svc", Identity: "team/deep/folder.sts.yaml/policy", LastChanged: changed.Add(3 * time.Hour), DefaultBranch: "trunk", SnapshotSHA: snapshotOID},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListPolicies() =\n%+v\nwant\n%+v", got, want)
	}
}

func TestListPoliciesIgnoresSymlinks(t *testing.T) {
	repos := []fakeRepo{{
		owner: "acme", name: "svc",
		entries: []entry{{"normal.sts.yaml", "blob"}, {"exec.sts.yaml", "blob"}, {"link.sts.yaml", "blob"}, {"linked-dir", "blob"}, {"sub", "tree"}, {"submodule", "commit"}},
		dirs: map[string][]entry{
			"sub": {{"nested.sts.yaml", "blob"}, {"link.sts.yaml", "blob"}},
			// A symlink must never be traversed even when its target has policies.
			"linked-dir": {{"target.sts.yaml", "blob"}},
		},
		modes: map[string]int{"exec.sts.yaml": 0100755, "link.sts.yaml": 0120000, "linked-dir": 0120000, "sub/link.sts.yaml": 0120000},
		dates: map[string]time.Time{"normal.sts.yaml": changed, "exec.sts.yaml": changed, "sub/nested.sts.yaml": changed},
	}}
	client, queries := fakeGitHub(t, repos, nil, false)
	got, err := ListPolicies(t.Context(), client, "acme", policyDir)
	want := []Policy{
		{Repo: "svc", Identity: "normal", LastChanged: changed, DefaultBranch: "main", SnapshotSHA: snapshotOID},
		{Repo: "svc", Identity: "exec", LastChanged: changed, DefaultBranch: "main", SnapshotSHA: snapshotOID},
		{Repo: "svc", Identity: "sub/nested", LastChanged: changed, DefaultBranch: "main", SnapshotSHA: snapshotOID},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ListPolicies() = %+v, %v; want %+v", got, err, want)
	}
	if queries.Load() != 4 {
		t.Errorf("queries = %d, want 4 (snapshot, root, sub, history)", queries.Load())
	}
}

func TestListPoliciesManyDirectories(t *testing.T) {
	r := fakeRepo{owner: "acme", name: "svc", dirs: map[string][]entry{}, dates: map[string]time.Time{}}
	for i := range batchSize + 1 {
		dir := fmt.Sprintf("dir-%d", i)
		r.entries = append(r.entries, entry{dir, "tree"})
		r.dirs[dir] = []entry{{"policy.sts.yaml", "blob"}}
		r.dates[dir+"/policy.sts.yaml"] = changed
	}
	client, queries := fakeGitHub(t, []fakeRepo{r}, nil, false)
	got, err := ListPolicies(t.Context(), client, "acme", policyDir)
	if err != nil {
		t.Fatalf("ListPolicies() = %v", err)
	}
	if len(got) != batchSize+1 {
		t.Fatalf("ListPolicies() returned %d policies, want %d", len(got), batchSize+1)
	}
	for i, p := range got {
		want := Policy{Repo: "svc", Identity: fmt.Sprintf("dir-%d/policy", i), LastChanged: changed, DefaultBranch: "main", SnapshotSHA: snapshotOID}
		if p != want {
			t.Fatalf("policy %d = %+v, want %+v", i, p, want)
		}
	}
	if n := queries.Load(); n != 5 {
		t.Errorf("GraphQL queries = %d, want 5", n)
	}
}

func TestListPoliciesNestedDirectoryError(t *testing.T) {
	repos := []fakeRepo{{owner: "acme", name: "svc", entries: []entry{{"sub", "tree"}}}}
	byName := map[string]fakeRepo{"acme/svc": repos[0]}
	var calls atomic.Int32
	client, _ := fakeGitHub(t, repos, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) > 2 {
			fmt.Fprint(w, `{"data":null,"errors":[{"type":"RATE_LIMITED","message":"API rate limit exceeded"}]}`)
			return
		}
		var req struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		data, errs := answer(t, byName, req.Query)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "errors": errs})
	}, false)
	got, err := ListPolicies(t.Context(), client, "acme", policyDir)
	if err == nil || !strings.Contains(err.Error(), "cleanup: listing .github/chainguard in acme: graphql: API rate limit exceeded") || got != nil {
		t.Fatalf("ListPolicies() = %v, %v; want nil and listing error", got, err)
	}
}

func TestListPoliciesPinnedSnapshot(t *testing.T) {
	repos := []fakeRepo{{
		owner: "acme", name: "svc", branch: "main",
		entries: []entry{{"team", "tree"}},
		dirs:    map[string][]entry{"team": {{"deploy.sts.yaml", "blob"}}},
		dates:   map[string]time.Time{"team/deploy.sts.yaml": changed},
	}}
	byName := map[string]fakeRepo{"acme/svc": repos[0]}
	var calls atomic.Int32
	client, _ := fakeGitHub(t, repos, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		n := calls.Add(1)
		// Simulate the default branch moving after snapshot resolution. Only
		// the captured commit retains the original policy and its history.
		if n > 1 && (strings.Contains(req.Query, "HEAD:") || strings.Contains(req.Query, "defaultBranchRef")) {
			t.Errorf("query after branch moved uses live branch: %s", req.Query)
		}
		data, errs := answer(t, byName, req.Query)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "errors": errs})
	}, false)
	got, err := ListPolicies(t.Context(), client, "acme", policyDir)
	want := []Policy{{Repo: "svc", Identity: "team/deploy", LastChanged: changed, DefaultBranch: "main", SnapshotSHA: snapshotOID}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ListPolicies() = %+v, %v; want %+v", got, err, want)
	}
	if calls.Load() != 4 {
		t.Errorf("queries = %d, want 4", calls.Load())
	}
}

func TestListPoliciesEmptyRepository(t *testing.T) {
	repos := []fakeRepo{{owner: "acme", name: "empty"}}
	client, queries := fakeGitHub(t, repos, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"data":{"r0":{"defaultBranchRef":null}}}`)
	}, false)
	got, err := ListPolicies(t.Context(), client, "acme", policyDir)
	if err != nil || len(got) != 0 || queries.Load() != 1 {
		t.Fatalf("ListPolicies() = %+v, %v; queries = %d, want no policies and one query", got, err, queries.Load())
	}
}

func TestListPoliciesMalformedResponses(t *testing.T) {
	tests := []struct {
		name     string
		call     int32
		response string
		want     string
	}{
		{"missing snapshot alias", 1, `{"data":{}}`, "missing snapshot response"},
		{"unexplained null snapshot", 1, `{"data":{"r0":null}}`, "malformed snapshot"},
		{"missing snapshot field", 1, `{"data":{"r0":{}}}`, "malformed snapshot"},
		{"invalid snapshot oid", 1, `{"data":{"r0":{"defaultBranchRef":{"name":"main","target":{"__typename":"Commit","oid":"HEAD"}}}}}`, "malformed snapshot"},
		{"missing root alias", 2, `{"data":{}}`, "missing directory response"},
		{"null repository", 2, `{"data":{"r0":null}}`, "missing directory response"},
		{"missing object", 2, `{"data":{"r0":{}}}`, "malformed directory response"},
		{"root not tree", 2, `{"data":{"r0":{"object":{"__typename":"Blob"}}}}`, "malformed directory response"},
		{"missing entries", 2, `{"data":{"r0":{"object":{"__typename":"Tree"}}}}`, "malformed directory response"},
		{"null entries", 2, `{"data":{"r0":{"object":{"__typename":"Tree","entries":null}}}}`, "malformed directory response"},
		{"empty entry", 2, `{"data":{"r0":{"object":{"__typename":"Tree","entries":[{"name":"","type":"blob"}]}}}}`, "invalid directory entry"},
		{"slash entry", 2, `{"data":{"r0":{"object":{"__typename":"Tree","entries":[{"name":"../escape","type":"tree"}]}}}}`, "invalid directory entry"},
		{"dot entry", 2, `{"data":{"r0":{"object":{"__typename":"Tree","entries":[{"name":"..","type":"tree"}]}}}}`, "invalid directory entry"},
		{"invalid type", 2, `{"data":{"r0":{"object":{"__typename":"Tree","entries":[{"name":"x","type":"other"}]}}}}`, "invalid directory entry"},
		{"duplicate entry", 2, `{"data":{"r0":{"object":{"__typename":"Tree","entries":[{"name":"x","type":"blob","mode":33188},{"name":"x","type":"blob","mode":33188}]}}}}`, "invalid directory entry"},
		{"missing mode", 2, `{"data":{"r0":{"object":{"__typename":"Tree","entries":[{"name":"x.sts.yaml","type":"blob"}]}}}}`, "invalid mode"},
		{"null mode", 2, `{"data":{"r0":{"object":{"__typename":"Tree","entries":[{"name":"x.sts.yaml","type":"blob","mode":null}]}}}}`, "invalid mode"},
		{"zero mode", 2, `{"data":{"r0":{"object":{"__typename":"Tree","entries":[{"name":"x.sts.yaml","type":"blob","mode":0}]}}}}`, "invalid mode"},
		{"string mode", 2, `{"data":{"r0":{"object":{"__typename":"Tree","entries":[{"name":"x.sts.yaml","type":"blob","mode":"100644"}]}}}}`, "malformed directory response"},
		{"tree with blob mode", 2, `{"data":{"r0":{"object":{"__typename":"Tree","entries":[{"name":"x","type":"tree","mode":33188}]}}}}`, "invalid mode"},
		{"blob with tree mode", 2, `{"data":{"r0":{"object":{"__typename":"Tree","entries":[{"name":"x.sts.yaml","type":"blob","mode":16384}]}}}}`, "invalid mode"},
		{"commit with symlink mode", 2, `{"data":{"r0":{"object":{"__typename":"Tree","entries":[{"name":"x","type":"commit","mode":40960}]}}}}`, "invalid mode"},
		{"invalid nested mode", 3, `{"data":{"r0":{"object":{"__typename":"Tree","entries":[{"name":"x.sts.yaml","type":"blob","mode":33152}]}}}}`, "invalid mode"},
		{"missing nested directory", 3, `{"data":{"r0":{"object":null}}}`, "missing nested directory"},
		{"missing nested repository", 3, `{"data":{"r0":null}}`, "missing directory response"},
		{"malformed nested tree", 3, `{"data":{"r0":{"object":{"__typename":"Tree","entries":null}}}}`, "malformed directory response"},
		{"missing history object", 4, `{"data":{"r0":{"object":null}}}`, "malformed history response"},
		{"missing history field", 4, `{"data":{"r0":{"object":{"__typename":"Commit"}}}}`, "malformed history"},
		{"missing history nodes", 4, `{"data":{"r0":{"object":{"__typename":"Commit","f0":{}}}}}`, "malformed history"},
	}
	repos := []fakeRepo{{owner: "acme", name: "svc", entries: []entry{{"sub", "tree"}}, dirs: map[string][]entry{"sub": {{"p.sts.yaml", "blob"}}}, dates: map[string]time.Time{"sub/p.sts.yaml": changed}}}
	byName := map[string]fakeRepo{"acme/svc": repos[0]}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			client, _ := fakeGitHub(t, repos, func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == tt.call {
					fmt.Fprint(w, tt.response)
					return
				}
				var req struct {
					Query string `json:"query"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				data, errs := answer(t, byName, req.Query)
				_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "errors": errs})
			}, false)
			got, err := ListPolicies(t.Context(), client, "acme", policyDir)
			if err == nil || !strings.Contains(err.Error(), tt.want) || got != nil {
				t.Fatalf("ListPolicies() = %+v, %v; want nil and error containing %q", got, err, tt.want)
			}
		})
	}
}

func TestListPoliciesBatches(t *testing.T) {
	// 120 repositories make three batches; only the first two hold policies,
	// so the third needs no history query.
	repos := make([]fakeRepo, 0, 120)
	for i := range 120 {
		r := fakeRepo{owner: "acme", name: fmt.Sprintf("repo-%03d", i), noDir: true}
		if i < 2*batchSize {
			r = fakeRepo{owner: "acme", name: r.name, entries: []entry{{"p.sts.yaml", "blob"}}, dates: map[string]time.Time{"p.sts.yaml": changed}}
		}
		repos = append(repos, r)
	}
	client, queries := fakeGitHub(t, repos, nil, false)
	got, err := ListPolicies(t.Context(), client, "acme", policyDir)
	if err != nil {
		t.Fatalf("ListPolicies() = %v", err)
	}
	if len(got) != 2*batchSize {
		t.Fatalf("ListPolicies() returned %d policies, want %d", len(got), 2*batchSize)
	}
	for i, p := range got {
		if want := fmt.Sprintf("repo-%03d", i); p.Repo != want || p.Identity != "p" || !p.LastChanged.Equal(changed) || p.DefaultBranch != "main" {
			t.Fatalf("policy %d = %+v, want %s/p changed %v", i, p, want, changed)
		}
	}
	if n := queries.Load(); n != 8 {
		t.Errorf("GraphQL queries = %d, want 8 (three snapshot queries, three directory queries, two history queries)", n)
	}
}

func TestListPoliciesManyPolicies(t *testing.T) {
	// 280 policies in two repositories need three history queries, and the
	// first repository's policies span two of them.
	repos := []fakeRepo{{owner: "acme", name: ".github", dates: map[string]time.Time{}}, {owner: "acme", name: "svc", dates: map[string]time.Time{}}}
	for i, n := range []int{250, 30} {
		for j := range n {
			name := fmt.Sprintf("p%03d.sts.yaml", j)
			repos[i].entries = append(repos[i].entries, entry{name, "blob"})
			repos[i].dates[name] = changed.Add(time.Duration(i*1000+j) * time.Minute)
		}
	}
	client, queries := fakeGitHub(t, repos, nil, false)
	got, err := ListPolicies(t.Context(), client, "acme", policyDir)
	if err != nil {
		t.Fatalf("ListPolicies() = %v", err)
	}
	if len(got) != 280 {
		t.Fatalf("ListPolicies() returned %d policies, want 280", len(got))
	}
	for k, p := range got {
		i, j := 0, k
		if k >= 250 {
			i, j = 1, k-250
		}
		want := Policy{Repo: repos[i].name, Identity: fmt.Sprintf("p%03d", j), LastChanged: changed.Add(time.Duration(i*1000+j) * time.Minute), DefaultBranch: "main", SnapshotSHA: snapshotOID}
		if p != want {
			t.Fatalf("policy %d = %+v, want %+v", k, p, want)
		}
	}
	if n := queries.Load(); n != 5 {
		t.Errorf("GraphQL queries = %d, want 5 (one snapshot, one directory query, three history queries)", n)
	}
}

func TestListPoliciesErrors(t *testing.T) {
	tests := []struct {
		name       string
		graphqlErr http.HandlerFunc
		restErr    bool
		wantErr    string
	}{{
		name:    "repository listing fails",
		restErr: true,
		wantErr: "listing repositories",
	}, {
		name: "graphql request fails",
		graphqlErr: func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"message":"boom"}`, http.StatusBadGateway)
		},
		wantErr: "listing .github/chainguard in acme",
	}, {
		name: "graphql returns an error other than NOT_FOUND",
		graphqlErr: func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, `{"data":null,"errors":[{"type":"RATE_LIMITED","message":"API rate limit exceeded"}]}`)
		},
		wantErr: "API rate limit exceeded",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := fakeGitHub(t, defaultRepos(), tt.graphqlErr, tt.restErr)
			_, err := ListPolicies(t.Context(), client, "acme", policyDir)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ListPolicies() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestListPoliciesHistoryError(t *testing.T) {
	// The directory query succeeds and the history query fails.
	byName := map[string]fakeRepo{}
	for _, r := range defaultRepos() {
		byName[r.owner+"/"+r.name] = r
	}
	client, _ := fakeGitHub(t, defaultRepos(), func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if !strings.Contains(req.Query, "history(first:") {
			data, errs := answer(t, byName, req.Query)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "errors": errs})
			return
		}
		fmt.Fprint(w, `{"data":null,"errors":[{"type":"INTERNAL","message":"something went wrong"}]}`)
	}, false)
	_, err := ListPolicies(t.Context(), client, "acme", policyDir)
	if err == nil || !strings.Contains(err.Error(), "last changes in acme") {
		t.Fatalf("ListPolicies() = %v, want error containing %q", err, "last changes in acme")
	}
}

// slowHistory answers GraphQL queries from repos, except that a query with
// more than limit history lookups gets a 502, as GitHub does for a query that
// runs too long.
func slowHistory(t *testing.T, repos []fakeRepo, limit int) http.HandlerFunc {
	byName := map[string]fakeRepo{}
	for _, r := range repos {
		byName[r.owner+"/"+r.name] = r
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if len(fileAlias.FindAllString(req.Query, -1)) > limit {
			http.Error(w, `{"message":"Bad Gateway"}`, http.StatusBadGateway)
			return
		}
		data, errs := answer(t, byName, req.Query)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "errors": errs})
	}
}

func TestListPoliciesSplitsSlowHistory(t *testing.T) {
	// 280 policies make history chunks of 100, 100 and 80. With queries over
	// 25 lookups timing out, each chunk splits twice: 100 -> 50 -> 25 takes
	// seven queries, and so does 80 -> 40 -> 20.
	repos := []fakeRepo{{owner: "acme", name: ".github", dates: map[string]time.Time{}}, {owner: "acme", name: "svc", dates: map[string]time.Time{}}}
	for i, n := range []int{250, 30} {
		for j := range n {
			name := fmt.Sprintf("p%03d.sts.yaml", j)
			repos[i].entries = append(repos[i].entries, entry{name, "blob"})
			repos[i].dates[name] = changed.Add(time.Duration(i*1000+j) * time.Minute)
		}
	}
	client, queries := fakeGitHub(t, repos, slowHistory(t, repos, 25), false)
	got, err := ListPolicies(t.Context(), client, "acme", policyDir)
	if err != nil {
		t.Fatalf("ListPolicies() = %v", err)
	}
	if len(got) != 280 {
		t.Fatalf("ListPolicies() returned %d policies, want 280", len(got))
	}
	for k, p := range got {
		i, j := 0, k
		if k >= 250 {
			i, j = 1, k-250
		}
		want := Policy{Repo: repos[i].name, Identity: fmt.Sprintf("p%03d", j), LastChanged: changed.Add(time.Duration(i*1000+j) * time.Minute), DefaultBranch: "main", SnapshotSHA: snapshotOID}
		if p != want {
			t.Fatalf("policy %d = %+v, want %+v", k, p, want)
		}
	}
	if n := queries.Load(); n != 23 {
		t.Errorf("GraphQL queries = %d, want 23 (one snapshot, one directory query, 21 history queries)", n)
	}
}

func TestListPoliciesSingleLookupTimesOut(t *testing.T) {
	// A lookup that times out on its own can't be split further, so the
	// listing fails rather than treat the file as unchanged.
	client, _ := fakeGitHub(t, defaultRepos(), slowHistory(t, defaultRepos(), 0), false)
	_, err := ListPolicies(t.Context(), client, "acme", policyDir)
	if err == nil || !strings.Contains(err.Error(), "last changes in acme") {
		t.Fatalf("ListPolicies() = %v, want error containing %q", err, "last changes in acme")
	}
}

func TestGraphqlURL(t *testing.T) {
	for base, want := range map[string]string{
		"https://api.github.com/":            "https://api.github.com/graphql",
		"https://ghes.example.com/api/v3/":   "https://ghes.example.com/api/graphql",
		"https://ghes.example.com/x/api/v3/": "https://ghes.example.com/x/api/graphql",
	} {
		u, err := url.Parse(base)
		if err != nil {
			t.Fatal(err)
		}
		if got := graphqlURL(u); got != want {
			t.Errorf("graphqlURL(%s) = %s, want %s", base, got, want)
		}
	}
}

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{
		"svc":            `"svc"`,
		`we"ird\name`:    `"we\"ird\\name"`,
		"line\nbreak":    `"line\nbreak"`,
		"HEAD:.github/x": `"HEAD:.github/x"`,
	} {
		if got := quote(in); got != want {
			t.Errorf("quote(%q) = %s, want %s", in, got, want)
		}
	}
}

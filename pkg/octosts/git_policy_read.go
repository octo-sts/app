// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/go-github/v88/github"
)

// readRegularPolicy resolves every path component in immutable Git trees.
// A missing entry is represented as a 404 so existing absence handling remains
// intact. Unsafe or incomplete responses are never treated as absence.
var errUnsafePolicyPath = errors.New("unsafe or incomplete policy Git path")

// The former Contents API read was limited to 1 MiB. Reject large objects
// before requesting their blob, avoiding Git's 100 MiB blob response limit.
const maxPolicyBlobSize = 1 << 20

func readRegularPolicy(ctx context.Context, client *github.Client, owner, repo, policyPath string) (*github.RepositoryContent, error) {
	parts := strings.Split(policyPath, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, errUnsafePolicyPath
		}
	}

	repository, _, err := client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		if isContentsNotFound(err) || isPolicyConflict(err) {
			return nil, errUnsafePolicyPath // inaccessible repository is not an absent policy
		}
		return nil, err
	}
	if repository == nil || repository.GetDefaultBranch() == "" {
		return nil, errUnsafePolicyPath
	}
	// Qualify the branch so a same-named tag cannot select another commit.
	commit, _, err := client.Repositories.GetCommit(ctx, owner, repo, url.PathEscape("heads/"+repository.GetDefaultBranch()), nil)
	if err != nil {
		if isContentsNotFound(err) || isPolicyConflict(err) {
			return nil, errUnsafePolicyPath // absence of the policy is unproven
		}
		return nil, err
	}
	if commit == nil || !isGitObjectID(commit.GetSHA()) || commit.Commit == nil || commit.Commit.Tree == nil || !isGitObjectID(commit.Commit.Tree.GetSHA()) {
		return nil, errUnsafePolicyPath
	}
	treeSHA := commit.Commit.Tree.GetSHA()
	for i, part := range parts {
		tree, _, err := client.Git.GetTree(ctx, owner, repo, treeSHA, false)
		if err != nil {
			if isContentsNotFound(err) || isPolicyConflict(err) {
				return nil, errUnsafePolicyPath // missing object is not a missing path
			}
			return nil, err
		}
		if tree == nil || tree.GetSHA() != treeSHA || tree.Truncated == nil || tree.GetTruncated() || tree.Entries == nil {
			return nil, errUnsafePolicyPath
		}
		var entry *github.TreeEntry
		seen := make(map[string]struct{}, len(tree.Entries))
		for _, candidate := range tree.Entries {
			if candidate == nil || candidate.Path == nil || candidate.GetPath() == "" || strings.Contains(candidate.GetPath(), "/") || candidate.GetPath() == "." || candidate.GetPath() == ".." || candidate.Mode == nil || candidate.Type == nil || !isGitObjectID(candidate.GetSHA()) || !validGitTreeEntry(candidate) {
				return nil, errUnsafePolicyPath
			}
			if _, ok := seen[candidate.GetPath()]; ok {
				return nil, errUnsafePolicyPath
			}
			seen[candidate.GetPath()] = struct{}{}
			if candidate.GetPath() == part {
				if entry != nil {
					return nil, errUnsafePolicyPath
				}
				entry = candidate
			}
		}
		if entry == nil {
			return nil, &github.ErrorResponse{Response: &http.Response{StatusCode: http.StatusNotFound}, Message: "policy path not found in Git tree"}
		}
		if !isGitObjectID(entry.GetSHA()) {
			return nil, errUnsafePolicyPath
		}
		if i < len(parts)-1 {
			if entry.GetType() != "tree" || entry.GetMode() != "040000" {
				return nil, errUnsafePolicyPath
			}
			treeSHA = entry.GetSHA()
			continue
		}
		if entry.GetType() != "blob" || (entry.GetMode() != "100644" && entry.GetMode() != "100755") {
			return nil, errUnsafePolicyPath
		}
		if entry.Size == nil || entry.GetSize() < 0 || entry.GetSize() > maxPolicyBlobSize {
			return nil, errUnsafePolicyPath
		}
		blob, err := getLimitedPolicyBlob(ctx, client, owner, repo, entry.GetSHA())
		if err != nil {
			if isContentsNotFound(err) || isPolicyConflict(err) {
				return nil, errUnsafePolicyPath
			}
			return nil, err
		}
		if blob == nil || blob.Content == nil || blob.Size == nil || blob.GetSize() != entry.GetSize() || blob.GetEncoding() != "base64" || blob.GetSHA() != entry.GetSHA() {
			return nil, errUnsafePolicyPath
		}
		content, err := base64.StdEncoding.DecodeString(blob.GetContent())
		if err != nil || len(content) != blob.GetSize() || gitBlobID(content, len(entry.GetSHA())) != entry.GetSHA() {
			return nil, errUnsafePolicyPath
		}
		return &github.RepositoryContent{Content: blob.Content, Encoding: blob.Encoding}, nil
	}
	return nil, errUnsafePolicyPath
}

// A conflict can mean an empty or inaccessible repository, not a missing path.
func isPolicyConflict(err error) bool {
	var response *github.ErrorResponse
	return errors.As(err, &response) && response.Response != nil && response.Response.StatusCode == http.StatusConflict
}

// Cap the HTTP body too: an upstream can return more data than its tree entry
// advertises. Leave room for base64 line breaks and JSON metadata.
func getLimitedPolicyBlob(ctx context.Context, client *github.Client, owner, repo, sha string) (*github.Blob, error) {
	req, err := client.NewRequest(ctx, http.MethodGet, fmt.Sprintf("repos/%s/%s/git/blobs/%s", url.PathEscape(owner), url.PathEscape(repo), sha), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.BareDo(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	const limit = 2*maxPolicyBlobSize + 65536
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, errUnsafePolicyPath
	}
	var blob *github.Blob
	if err := json.Unmarshal(data, &blob); err != nil {
		return nil, errUnsafePolicyPath
	}
	return blob, nil
}

func gitBlobID(content []byte, length int) string {
	data := append([]byte(fmt.Sprintf("blob %d\x00", len(content))), content...)
	if length == 40 {
		id := sha1.Sum(data)
		return hex.EncodeToString(id[:])
	}
	id := sha256.Sum256(data)
	return hex.EncodeToString(id[:])
}

func validGitTreeEntry(entry *github.TreeEntry) bool {
	switch entry.GetMode() {
	case "040000":
		return entry.GetType() == "tree"
	case "100644", "100755", "120000":
		return entry.GetType() == "blob"
	case "160000":
		return entry.GetType() == "commit"
	default:
		return false
	}
}

func isGitObjectID(sha string) bool {
	if len(sha) != 40 && len(sha) != 64 {
		return false
	}
	for _, c := range sha {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

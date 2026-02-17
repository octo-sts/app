// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package ghinstall provides a Manager abstraction for looking up GitHub App
// installations by owner. It encapsulates an LRU cache of installation IDs
// and handles paginated listing of installations via the GitHub API.
//
// Construct a Manager with [New] and inject it into consumers that need to
// resolve an owner name to a GitHub App installation.
package ghinstall

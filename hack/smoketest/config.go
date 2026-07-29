// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"sigs.k8s.io/yaml"
)

type Config struct {
	Domain string     `json:"domain"`
	Tests  []TestCase `json:"tests"`
}

type TestCase struct {
	Name          string  `json:"name"`
	Scope         string  `json:"scope"`
	Identity      string  `json:"identity"`
	ExpectFailure bool    `json:"expect_failure"`
	ExpectedError string  `json:"expected_error"`
	Verify        *Verify `json:"verify,omitempty"`
	StickyRepeat  int     `json:"sticky_repeat,omitempty"`
}

type Verify struct {
	ContentsRead     *ContentsReadVerify `json:"contents_read,omitempty"`
	IssuesRead       *RepoVerify         `json:"issues_read,omitempty"`
	PullRequestsRead *RepoVerify         `json:"pull_requests_read,omitempty"`
}

type ContentsReadVerify struct {
	Org  string `json:"org"`
	Repo string `json:"repo"`
	Path string `json:"path"`
}

type RepoVerify struct {
	Org  string `json:"org"`
	Repo string `json:"repo"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.UnmarshalStrict(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if cfg.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if len(cfg.Tests) == 0 {
		return nil, fmt.Errorf("at least one test is required")
	}
	for i, tc := range cfg.Tests {
		if tc.Name == "" {
			return nil, fmt.Errorf("test[%d]: name is required", i)
		}
		if tc.Scope == "" {
			return nil, fmt.Errorf("test[%d] %q: scope is required", i, tc.Name)
		}
		if tc.Identity == "" {
			return nil, fmt.Errorf("test[%d] %q: identity is required", i, tc.Name)
		}
	}

	return &cfg, nil
}

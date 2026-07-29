// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/chainguard-dev/clog"
)

func main() {
	configPath := flag.String("config", "", "path to smoke test YAML config file")
	flag.Parse()

	if *configPath == "" {
		fmt.Fprintf(os.Stderr, "Usage: smoketest -config <path>\n")
		os.Exit(1)
	}

	ctx := clog.WithLogger(context.Background(), clog.New(slog.Default().Handler()))

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}

	clog.FromContext(ctx).Infof("running %d smoke tests against %s", len(cfg.Tests), cfg.Domain)

	results := RunTests(ctx, cfg)

	passed, failed := 0, 0
	for _, r := range results {
		if r.Passed {
			passed++
		} else {
			failed++
		}
	}

	clog.FromContext(ctx).Infof("results: %d passed, %d failed, %d total", passed, failed, len(results))

	if failed > 0 {
		os.Exit(1)
	}
}

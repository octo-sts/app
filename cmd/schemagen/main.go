// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:generate go run . -o ../../pkg/octosts
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/invopop/jsonschema"
	"github.com/octo-sts/app/pkg/octosts"
)

var outputFlag = flag.String("o", "", "output directory")

func main() {
	flag.Parse()

	if *outputFlag == "" {
		log.Fatal("output path is required")
	}

	r := new(jsonschema.Reflector)
	if err := r.AddGoComments("github.com/octo-sts/app/pkg/octosts", "../../pkg/octosts"); err != nil {
		log.Fatal(err)
	}

	for _, t := range []any{
		octosts.TrustPolicy{},
		octosts.OrgTrustPolicy{},
	} {
		path := filepath.Join(*outputFlag, fmt.Sprintf("%T.json", t))
		out, err := os.Create(path)
		if err != nil {
			log.Fatal(err)
		}
		defer out.Close()

		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")

		if err := enc.Encode(r.Reflect(t)); err != nil {
			// nolint:gocritic
			log.Fatal(err)
		}
	}
}

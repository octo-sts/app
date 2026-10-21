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
		octosts.OrgTrustedIssuers{},
	} {
		path := filepath.Join(*outputFlag, fmt.Sprintf("%T.json", t))
		out, err := os.Create(path)
		if err != nil {
			log.Fatal(err)
		}
		defer out.Close()

		schema := r.Reflect(t)
		// Constrain each permission to the levels Compile accepts, so editors
		// flag a typo like "writ" before it reaches a check run.
		if perms, ok := schema.Definitions["InstallationPermissions"]; ok {
			for p := perms.Properties.Oldest(); p != nil; p = p.Next() {
				p.Value.Enum = make([]any, 0, len(octosts.PermissionLevels))
				for _, l := range octosts.PermissionLevels {
					p.Value.Enum = append(p.Value.Enum, l)
				}
			}
		}

		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")

		if err := enc.Encode(schema); err != nil {
			// nolint:gocritic
			log.Fatal(err)
		}
	}
}

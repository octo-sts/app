/*
Copyright 2024 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"context"

	"github.com/chainguard-dev/terraform-infra-common/pkg/prober"

	octoprober "github.com/octo-sts/app/pkg/prober"
)

func main() {
	ctx := context.Background()
	prober.Go(ctx, prober.Func(octoprober.Func))
}

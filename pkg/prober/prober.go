/*
Copyright 2024 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package prober

import (
	"context"
	"log"
)

func Func(ctx context.Context) error {
	log.Print("Got a probe!")
	return nil
}

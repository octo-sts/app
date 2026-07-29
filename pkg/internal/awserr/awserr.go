// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package awserr provides helpers for handling AWS SDK errors safely.
package awserr

import (
	"errors"
	"fmt"

	smithy "github.com/aws/smithy-go"
)

// Sanitize replaces an AWS SDK error with one containing only the error code,
// stripping the message which may contain resource ARNs and AWS account
// identifiers. Errors that are not AWS API errors are returned unchanged.
func Sanitize(err error) error {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return fmt.Errorf("%s", apiErr.ErrorCode()) //nolint:err113
	}
	return err
}

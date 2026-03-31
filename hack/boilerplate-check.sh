#!/usr/bin/env bash

# Copyright 2024 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# check_boilerplate verifies a single file has the correct boilerplate header.
# The year in the Copyright line is treated as a wildcard.
check_boilerplate() {
  local file="$1" ext="$2"
  local boilerplate="${REPO_ROOT}/hack/boilerplate/boilerplate.${ext}.txt"
  if [ ! -f "$boilerplate" ]; then
    return 0
  fi

  local nlines
  nlines=$(wc -l < "$boilerplate")

  local expected actual header
  expected=$(sed 's/Copyright [0-9]\{4\}/Copyright YYYY/' "$boilerplate")
  # Read extra lines to account for Go build directives / shebangs before boilerplate.
  header=$(head -n $((nlines + 5)) "$file")

  # For Go files, skip leading //go:build and blank lines before checking.
  if [ "$ext" = "go" ]; then
    header=$(echo "$header" | sed '/^\/\/ *go:build/d; /^$/d' | head -n "$nlines")
  else
    header=$(echo "$header" | head -n "$nlines")
  fi

  actual=$(echo "$header" | sed 's/Copyright [0-9]\{4\}/Copyright YYYY/')

  if [ "$expected" != "$actual" ]; then
    echo "FAIL: $file (missing or incorrect boilerplate)"
    return 1
  fi
  return 0
}

failed=0
for file in "$@"; do
  ext="${file##*.}"
  check_boilerplate "$file" "$ext" || failed=1
done
exit $failed

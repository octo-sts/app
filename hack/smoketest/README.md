# Octo STS Smoke Tests

A standalone Go tool that runs smoke tests against a live Octo STS deployment. It
validates both successful token exchanges and known-bad scenarios such as missing
trust policies or mismatched OIDC tokens.

## Requirements

**This tool must be run from a GitHub Actions workflow.** It uses GitHub Actions
OIDC tokens for authentication, which are only available inside Actions runners
with the `id-token: write` permission. It will not work locally or in other CI
environments.

The workflow must include:

```yaml
permissions:
  id-token: write
```

## Quick Start

### 1. Build the tool

```bash
go build -o smoketest ./hack/smoketest/
```

### 2. Create a config file

Create a YAML file describing your test cases (see [Configuration Reference](#configuration-reference)
below or the per-environment configs in `hack/smoketest/testdata/`):

```yaml
domain: octo-sts.dev

tests:
  - name: "valid exchange"
    scope: octo-sts/prober
    identity: smoke-test

  - name: "missing policy"
    scope: octo-sts/prober
    identity: does-not-exist
    expect_failure: true
    expected_error: "unable to find trust policy"
```

### 3. Run from a GitHub Actions workflow

```yaml
jobs:
  smoke-test:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: .go-version
      - run: go build -o smoketest ./hack/smoketest/
      - run: ./smoketest -config hack/smoketest/testdata/example.yaml
```

## How It Works

For each test case, the tool:

1. **Mints a GitHub Actions OIDC token** with the `audience` set to the
   configured `domain`. This uses the `ACTIONS_ID_TOKEN_REQUEST_URL` and
   `ACTIONS_ID_TOKEN_REQUEST_TOKEN` environment variables that GitHub Actions
   provides to workflows with `id-token: write`.

2. **Exchanges the OIDC token** with the Octo STS endpoint at
   `https://{domain}` using the `chainguard.dev/sdk/sts` client. The exchange
   targets the configured `scope` (repository) and `identity` (trust policy
   name).

3. **Checks the result** against expectations:
   - If `expect_failure: true`, the tool asserts that the exchange returned an
     error. If `expected_error` is set, it checks that the error message contains
     that substring.
   - If `expect_failure: false` (the default), the tool asserts that the exchange
     succeeded and a token was returned.

4. **Runs optional verifications** if a `verify` block is present. This uses the
   returned GitHub token to make real API calls, confirming the token actually has
   the expected permissions.

5. **Revokes the token** after use. Every successfully exchanged token is revoked
   via `DELETE https://api.github.com/installation/token` to clean up rather than
   letting it expire.

Each test runs independently. A failure in one test does not skip subsequent
tests. The tool exits 0 if all tests pass, 1 if any fail.

## Configuration Reference

The config file is YAML with two top-level fields:

### Top-Level Fields

| Field    | Type   | Required | Description                                        |
|----------|--------|----------|----------------------------------------------------|
| `domain` | string | yes      | Octo STS deployment domain (e.g. `octo-sts.dev`)  |
| `tests`  | list   | yes      | List of test cases to run                          |

### Test Case Fields

| Field            | Type   | Required | Default | Description                                           |
|------------------|--------|----------|---------|-------------------------------------------------------|
| `name`           | string | yes      |         | Human-readable name for the test (used in log output) |
| `scope`          | string | yes      |         | Target repository scope (e.g. `octo-sts/prober`)     |
| `identity`       | string | yes      |         | Trust policy identity name                            |
| `expect_failure` | bool   | no       | `false` | If `true`, expect the exchange to fail                |
| `expected_error` | string | no       |         | Substring to match in the error message               |
| `verify`         | object | no       |         | Optional verification block (see below)               |
| `sticky_repeat`  | int    | no       | `0`     | Create a check run, then exchange N-1 more times and update it to verify same app |

### Verify Block

The `verify` block is optional and only meaningful for tests where
`expect_failure` is `false`. It describes GitHub API calls to make with the
returned token to confirm it has the expected permissions.

All sub-fields are optional. Include only the verifications relevant to the trust
policy being tested.

#### `contents_read`

Reads a file from a repository. Confirms the token has `contents: read`.

| Field  | Type   | Required | Description                             |
|--------|--------|----------|-----------------------------------------|
| `org`  | string | yes      | Repository owner                        |
| `repo` | string | yes      | Repository name                         |
| `path` | string | yes      | File path to read (e.g. `README.md`)    |

Example:
```yaml
verify:
  contents_read:
    org: octo-sts
    repo: prober
    path: .github/chainguard/smoke-test.sts.yaml
```

#### `issues_read`

Lists issues on a repository. Confirms the token has `issues: read`.

| Field  | Type   | Required | Description      |
|--------|--------|----------|------------------|
| `org`  | string | yes      | Repository owner |
| `repo` | string | yes      | Repository name  |

Example:
```yaml
verify:
  issues_read:
    org: octo-sts
    repo: prober
```

#### `pull_requests_read`

Lists pull requests on a repository. Confirms the token has `pull_requests: read`.

| Field  | Type   | Required | Description      |
|--------|--------|----------|------------------|
| `org`  | string | yes      | Repository owner |
| `repo` | string | yes      | Repository name  |

Example:
```yaml
verify:
  pull_requests_read:
    org: octo-sts
    repo: prober
```

### Sticky Routing Verification

The `sticky_repeat` field tests that multi-app sticky routing is working for
`checks: write` policies. It exploits the GitHub check-run ownership constraint:
only the app that created a check run can update it. The test exchanges a token,
creates a check run on the target repo, then exchanges N-1 more times and
updates the same check run with each token. If any update fails with 403, a
different app was used — proving sticky routing is broken.

This requires a trust policy with `checks: write` and `contents: read`
permissions, and a deployment with multiple GitHub Apps and a sticky store
configured.

```yaml
- name: "checks:write sticky routing"
  scope: octo-sts/prober
  identity: smoke-test-checks
  sticky_repeat: 3
```

## Switching Between Staging and Prod

Change the `domain` field to target different deployments. You can maintain
separate config files per environment:

```
hack/smoketest/testdata/staging.yaml   # domain: staging.octo-sts.dev
hack/smoketest/testdata/prod.yaml      # domain: octo-sts.dev
```

Or parameterize it in your workflow using `sed`, `envsubst`, or similar.

## Prerequisites

For tests to work, the following must already be in place:

1. **Trust policies must exist.** Each test case references a trust policy by
   `identity` name. The corresponding `.github/chainguard/{identity}.sts.yaml`
   file must exist in the target repository's default branch.

2. **The Octo STS GitHub App must be installed.** The App must be installed on
   the organization/repository referenced by `scope`, with access to the
   relevant repositories.

3. **Trust policies must match the GitHub Actions OIDC token.** For positive
   test cases (where the exchange should succeed), the trust policy's issuer,
   subject, and any claim patterns must match the OIDC token produced by the
   GitHub Actions workflow running the smoke tests.

## Negative Test Scenarios

The tool supports several categories of negative tests:

### Missing STS Policy

Tests that a non-existent identity is correctly rejected:

```yaml
- name: "missing STS policy"
  scope: octo-sts/prober
  identity: does-not-exist
  expect_failure: true
  expected_error: "unable to find trust policy"
```

### App Not Installed

Tests that a scope where the app is not installed is rejected:

```yaml
- name: "app not installed"
  scope: some-org/no-app-here
  identity: anything
  expect_failure: true
  expected_error: "no installation found"
```

### Bad OIDC Match

Tests that a trust policy which doesn't match the calling workflow's OIDC token
is rejected. Create a trust policy with a subject or issuer that won't match
the Actions token:

```yaml
- name: "OIDC subject mismatch"
  scope: octo-sts/prober
  identity: wrong-subject-policy
  expect_failure: true
  expected_error: "token does not match trust policy"
```

Where `wrong-subject-policy.sts.yaml` contains a subject that doesn't match the
calling workflow (e.g. `subject: repo:some-other-org/some-other-repo:ref:refs/heads/main`).

## Adding New Verification Types

To add a new verification type (e.g. `actions_read`):

1. Add a new struct field to `Verify` in `config.go`
2. Add the corresponding API call in `runVerifications()` in `runner.go`
3. Document the new field in this README

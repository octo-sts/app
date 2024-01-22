# `octo-sts`: an STS for Github

This repository holds a Github App called `octo-sts` that acts like a Security
Token Service (STS) for the Github API. Using this App, workloads running
essentially anywhere that can produce OIDC tokens can federate with this App's
STS API in order to produce short-lived tokens for interacting with Github.

**_The ultimate goal of this App is to wholly eliminate the need for Github
Personal Access Tokens (aka PATs)._**

> _[The full design document.](inky.wtf/github-sts)_

## Setting up workload trust

For the App to produce credentials that work with resources in your organization
it must be installed into the organization and have access to any repositories
that you will want workloads to be able to interact with.  Unfortunately due to
limitations with Github Apps, the App must ask for a superset of the permissions
needed for federation, so the full set of permissions the App requests will be
large, but with one exception (`contents: read` reading policy files) the App
only creates tokens with these scopes based on the "trust policies" you have
configured.

### The Trust Policy

Trust policies are checked into `.github/chainguard/{name}.sts.yaml`, and
consist of a few key parts:
1. The claim matching criteria for federation,
2. The permissions to grant the identity, and
3. (for Org-level policies) The list of repositories to grant access.

Here is a simple example that allows the Github actions workflows in
`chainguard-dev/foo` running on the `main` branch to read the repo contents and
interact with issues:

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:chainguard-dev/foo:ref:refs/heads/main

permissions:
  contents: read
  issues: write
```

The Trust Policy can also match the issuer, subject, and even custom claims with
regular expressions.  For example:

```yaml
issuer: https://accounts.google.com
subject_pattern: '[0-9]+'
claim_pattern:
  email: '.*@chainguard.dev'

permissions:
  contents: read
```

This policy will allow OIDC tokens from Google accounts of folks with a
Chainguard email address to federate and read the repo contents.

### Federating a token

The Github App implements the Chainguard `SecurityTokenService` GRPC service
definition [here](https://github.com/chainguard-dev/sdk/blob/main/proto/platform/oidc/v1/oidc.platform.proto#L13-L28).

If a `${TOKEN}` suitable for federation is sent like so:
```
curl -H "Authorization: Bearer ${TOKEN}" \
  "https://octo-sts.dev/sts/exchange?scope=${REPO}&identity=${NAME}"
```

The App will attempt to load the trust policy from
`.github/chainguard/${NAME}.sts.yaml` from `${REPO}` and if the provided `${TOKEN}`
satisfies those rules, it will return a token with the permissions in the trust
policy.

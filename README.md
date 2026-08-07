# `octo-sts`: an STS for GitHub

This repository holds a GitHub App called `octo-sts` that acts like a Security
Token Service (STS) for the GitHub API. Using this App, workloads running
essentially anywhere that can produce OIDC tokens can federate with this App's
STS API in order to produce short-lived tokens for interacting with GitHub.

**_The ultimate goal of this App is to wholly eliminate the need for GitHub
Personal Access Tokens (aka PATs)._**

The original [blog post](https://www.chainguard.dev/unchained/the-end-of-github-pats-you-cant-leak-what-you-dont-have) and the page on [Chainguard Academy](https://edu.chainguard.dev/open-source/octo-sts/overview/).

## Setting up workload trust

For the App to produce credentials that work with resources in your organization
it must be installed into the organization and have access to any repositories
that you will want workloads to be able to interact with. Unfortunately due to
limitations with GitHub Apps, the App must ask for a superset of the permissions
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

Here is a simple example that allows the GitHub actions workflows in
`chainguard-dev/foo` running on the `main` branch to read the repo contents and
interact with issues:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/octo-sts/app/refs/heads/main/pkg/octosts/octosts.TrustPolicy.json

issuer: https://token.actions.githubusercontent.com
subject: repo:chainguard-dev/foo:ref:refs/heads/main

permissions:
  contents: read
  issues: write
```

The Trust Policy can also match the issuer, subject, and even custom claims with
regular expressions. For example:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/octo-sts/app/refs/heads/main/pkg/octosts/octosts.TrustPolicy.json

issuer: https://accounts.google.com
subject_pattern: "[0-9]+"
claim_pattern:
  email: ".*@chainguard.dev"

permissions:
  contents: read
```

This policy will allow OIDC tokens from Google accounts of folks with a
Chainguard email address to federate and read the repo contents.

#### Autocomplete

[JSONSchemas](https://json-schema.org/) are available to aid in IDE autocompletion:

- [TrustPolicy](./pkg/octosts/octosts.TrustPolicy.json)
- [OrgTrustPolicy](pkg/octosts/octosts.OrgTrustPolicy.json)
- [OrgTrustedIssuers](pkg/octosts/octosts.OrgTrustedIssuers.json)

##### VSCode

We recommend using [vscode-yaml](https://github.com/redhat-developer/vscode-yaml?tab=readme-ov-file).
This will read the `# yaml-language-server: $schema=...` header and provide code completion.

### Organization Trusted Token Issuers

An organization restricts which OIDC issuers can federate with its repositories.
Add `<ORG_POLICY_REPO>/.github/chainguard/trusted-token-issuers.yaml` to the
organization's policy repository (`.github` by default; see `ORG_POLICY_REPO`
below). octo-sts rejects a token with an issuer that the file does not permit.
It rejects the token before it reads the trust policy.

#### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ORG_POLICY_REPO` | `.github` | Repository within the organization that holds the org-issuer allowlist. Must exist and be accessible to the App before enforcement takes effect. |

> **Warning: migration hazard.** If you set `ORG_POLICY_REPO=my-policies` while
> the allowlist is still in `.github`, octo-sts reads `my-policies` instead.
> That file does not exist yet, so the read returns 404. A 404 is treated as
> "no allowlist" — meaning **all issuers are permitted** for that organization,
> silently. Create or move the allowlist into the new repository and protect it
> **before** flipping `ORG_POLICY_REPO`.

> **Note: two-binary config skew.** The exchange service and the webhook
> validator each read `ORG_POLICY_REPO` from their own deployment config. If
> you set `ORG_POLICY_REPO` on only one of the two, the webhook validates a
> different repository than the exchange enforces. Update both deployments
> together.

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/octo-sts/app/refs/heads/main/pkg/octosts/octosts.OrgTrustedIssuers.json

# "enforce" (the default) rejects a token that the allowlist does not permit.
# "audit" permits them and records each one the allowlist rejects.
mode: enforce

# octo-sts matches these exactly. A trailing slash makes a different issuer.
issuers:
  - https://token.actions.githubusercontent.com
  - https://accounts.google.com

# octo-sts matches these as anchored regexps against the whole issuer URL.
# Escape a literal dot. octo-sts rejects a wildcard that can match "/".
issuer_patterns:
  - https://oidc\.eks\.[a-z0-9-]+\.amazonaws\.com/id/[A-Z0-9]+
```

octo-sts matches an entry in `issuers` exactly. It matches an entry in
`issuer_patterns` as an anchored regular expression against the whole issuer URL.
An issuer passes if it matches either list. Matching is case-sensitive, so write
the scheme and the host in lowercase.

**octo-sts rejects a pattern that can match `/`.** The `/` character separates the
host from the path. A pattern that matches `/` can therefore reach past the host.
Anchors at both ends do not prevent this, because a pattern can stay loose in the
middle.

octo-sts parses each pattern with the same parser that Go's `regexp` package uses.
It then applies two rules:

- It rejects a character class or a `.` that can match `/`, at any position. This
  covers `\S`, `[^\n]`, `[[:ascii:]]` and a range such as `[.-9]`.
- It rejects a literal `/` inside a repetition, an optional group, or an
  alternation. A group such as `([a-z0-9.-]+/)*` repeats across separators.

A literal `/` at a fixed position is correct. Every issuer with a path has one.

These rules catch a common mistake: a pattern that spans into another domain.
`https://.*.example.com` reads as "any subdomain of example.com". It also permits
`https://evil.attacker-example.com`, because the unescaped `.` before `example`
matches `-`. It also permits `https://totally-evil.com/x.example.com`, where an
attacker controls the whole host.

Write a literal dot as `\.`. Give an explicit character class for the part that
varies. `https://[a-z0-9-]+\.example\.com` expresses "subdomains of example.com",
and octo-sts accepts it. The error message names the pattern that failed.

Write a path one segment at a time, with literal separators. Use
`https://example\.com/realms/[a-z0-9-]+`. Do not use
`https://example\.com/[a-z0-9/-]+`. octo-sts deliberately gives you no way to match
a path of variable depth.

**This is a best-effort guard, not a guarantee.** It catches accidents. It does not
stop a determined author. Write your patterns as narrowly as you can. An
organization owner writes this file, and the control serves that owner. An
over-broad pattern is therefore an unwise choice, not an attack.

**No file means no restriction.** An organization that adds no file sees no change.

#### Rolling it out

1. Commit the file with `mode: audit`. octo-sts rejects nothing in audit mode.
2. Read the logs and the exchange events. octo-sts records each token that the
   allowlist does not permit.
3. Check that your list is complete.
4. Remove the `mode` line to enforce.

Audit mode does not protect you against a broken file or a failed lookup.

#### Requirement: the App must be able to read the policy repository

octo-sts reads the allowlist with a short-lived `contents: read` token. The token
is scoped to the `ORG_POLICY_REPO` repository (`.github` by default).
**Enforcement silently does not apply if octo-sts cannot read that repository.**
The most common cause is an App that is installed on selected repositories only.

octo-sts cannot report which cause it hit. GitHub answers a token request for an
inaccessible repository with one 422 status. That status does not separate "the
repository does not exist" from "you do not have access".

Grant the App access to the policy repository before you rely on this control.

#### When the lookup fails

| Situation | Result |
| --- | --- |
| File absent | octo-sts permits all issuers |
| No App can read `ORG_POLICY_REPO` | octo-sts permits all issuers and logs a warning. It first re-reads the installation list from GitHub, without its local cache. See effect 4 below |
| Rate limited, or GitHub unavailable | octo-sts uses the last known good allowlist. If there is none, it rejects the exchange |
| File present but invalid | octo-sts uses the last known good allowlist. If there is none, it rejects every exchange in the organization |

This caching creates four timing effects.

1. After you *narrow* the allowlist, octo-sts can still serve the previous, broader
   list for up to one hour. This happens whenever GitHub returns an error.
2. After you *fix* an invalid file, rejections can continue for up to five minutes.
   The cached result must expire first.
3. When you *enable* the allowlist, octo-sts can permit all issuers for up to one
   hour.
4. After you install the App, enforcement can take a few minutes to start.

Plan for effect 3. "No file" is itself a valid last known good state. An
organization that adds its **first** allowlist during a GitHub incident can
therefore keep permitting all issuers for up to one hour. This behavior is
deliberate. It keeps the organizations that do not use this feature working through
the incident. One successful read replaces the state. Check that enforcement
started. Do not assume it started.

Effect 4 has a different cause. Before octo-sts concludes that no installation can
read the policy repository, it re-reads the installation list from GitHub without
its local cache. GitHub does not list a new installation at once. octo-sts cannot
see an installation that GitHub has not yet propagated.

#### Hardening

This control is only as strong as write access to the policy repository.

- **Create the policy repository before you need it.** GitHub does not reserve
  repository names. In an organization without this repository, any member who can
  create a repository becomes the sole author of this control. Restrict who can
  create repositories.

- **Protect the default branch of the policy repository.** Make the
  `Trust Policy Validation` check a **required** status check. The check validates
  this file on every pull request. It only reports. It blocks nothing until you make
  it required.

- **Add a CODEOWNERS entry** for the file.

- **Scope organization-level trust policies with `repositories:`.** An
  organization-level policy that grants `contents: write` without a `repositories:`
  restriction covers every repository the installation can see. That includes the
  policy repository. A federated identity can then rewrite the allowlist that
  constrains it. Any permission that writes, renames, or deletes the allowlist file
  defeats this control. **Deletion of the file fails open.**

- **`.github-private` is not consulted.** The file must live in `ORG_POLICY_REPO`.

### Federating a token

The GitHub App implements the Chainguard `SecurityTokenService` GRPC service
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

### Release cadence

Our release cadence at this moment is set to when is needed, meaning if we have a bug fix or a new feature
we will might make a new release.

### Multi-App Routing

When multiple GitHub Apps are configured (`GITHUB_APP_IDS` has more than one
entry), OctoSTS distributes token exchanges across installations using
capacity-aware fairshare routing. Trust policies with `checks: write` require
sticky routing — the same `(scope, identity)` pair must always receive a token
from the same installation because GitHub check runs can only be updated by the
app that created them.

#### Sticky Store

The sticky store persists these `(scope, identity) -> installation` mappings so
they survive process restarts and deploys. Without it, checks:write policies fall
back to round-robin (non-sticky) routing which may break check-run updates.

**Firestore backend** (recommended for GCP deployments):

| Variable | Default | Description |
|----------|---------|-------------|
| `OCTOSTS_STICKY_STORE` | (empty) | Set to `firestore` to enable |
| `OCTOSTS_STICKY_STORE_FIRESTORE_PROJECT` | running GCP project | Firestore GCP project |
| `OCTOSTS_STICKY_STORE_FIRESTORE_COLLECTION` | `sticky-routes` | Firestore collection name |
| `OCTOSTS_STICKY_STORE_FIRESTORE_TTL` | `1h` | TTL for inactive mappings |

Active mappings have their TTL refreshed on every use, so they never expire.
Only mappings unused for the TTL duration are automatically cleaned up.

Single-app deployments (`GITHUB_APP_IDS` has one entry) do not need sticky
routing and can ignore these settings.

### GitHub Enterprise Server (GHES)

OctoSTS can be deployed against a GitHub Enterprise Server instance by setting
the `GITHUB_BASE_URL` environment variable to your GHES API endpoint:

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_BASE_URL` | (empty — uses `https://api.github.com`) | GitHub API base URL for GHES (e.g. `https://github.example.com/api/v3`) |

The URL must use HTTPS. When set, all GitHub API interactions (installation
lookups, trust policy reads, token exchanges, and token revocations) will target
the configured endpoint instead of the public GitHub API.

### Best Practices

To ensure secure and effective use of octo-sts, follow these recommended practices:

#### Repository Security

- **Enable branch protection**: Configure branch protection rules on your main/default branch to prevent direct commits and require pull request reviews before merging changes. This prevents OctoSTS clients from bypassing security controls by directly merging changes to main without review.

- **Restrict who can approve pull requests**: Limit pull request approval permissions to trusted team members or repository administrators.

- **Restrict trusted token issuers**: Use the [organization-wide allowlist](#organization-trusted-token-issuers) so that only approved identity providers can federate with your repositories. Without it, anyone who can write a trust policy can point `issuer:` at a provider they control.

### Trust Policy Management

- **Principle of least privilege**: Grant only the minimum permissions necessary for your workloads to function. Start with read-only permissions and add write permissions only when required.

- **Scope policies narrowly**: Create specific trust policies for different workloads rather than using broad, catch-all policies.

- **Regular policy reviews**: Periodically review and audit your trust policies (`.github/chainguard/*.sts.yaml`) to ensure they still align with your security requirements.

- **Use specific subject matching**: Prefer exact subject matches over broad patterns when possible. For example, use `repo:org/repo:ref:refs/heads/main` instead of `repo:org/repo:.*`.

#### Token Management

- **Rotate regularly**: While octo-sts tokens are short-lived, ensure your OIDC token sources (like GitHub Actions) are properly configured and rotated according to best practices.

- **Secure OIDC token handling**: Ensure your workloads properly secure and handle OIDC tokens before exchanging them with octo-sts.

### Permission updates

Sometimes we need to add or remove a GitHub Permission in order to add/remove permissions that will be include in the
octo-sts token for the users. Due to the nature of GitHub Apps, OctoSTS must request all permissions it might need to use, even if you don't want to use them for your particular installation or policy.

To avoid disruptions for the users, making them to review and approve the changes in the installed GitHub App we
will apply permissions changes for the `octo-sts app` quarterly at any day during the quarter.

An issue will be created to explain what permissions is being added or removed.

Special cases will be discussed in a GitHub issue in https://github.com/octo-sts/app/issues and we might apply more than
one change during the quarter.

### Octo-STS GitHub Permissions

The following permissions are the currently enabled in octo-Sts and will be available when installing the GitHub APP

#### Repository Permissions

- **Actions**: `Read/Write`
- **Administration** : `Read-only`
- **Attestations**: `No Access`
- **Checks**: `Read/Write`
- **Code Scanning Alerts**: `Read/Write`
- **Codespaces**: `No Access`
- **Codespaces lifecycle admin**: `No Access`
- **Codespaces metadata**: `No Access`
- **Codespaces secrets**: `No Access`
- **Commit statuses**: `Read/Write`
- **Contents**: `Read/Write`
- **Custom properties**: `No Access`
- **Dependabot alerts**: `No Access`
- **Dependabot secrets**: `No Access`
- **Deployments**: `Read/Write`
- **Discussions**: `Read/Write`
- **Environments**: `Read/Write`
- **Issues**: `Read/Write`
- **Merge queues**: `No Access`
- **Metadata (Mandatory)**: `Read-only`
- **Packages**: `Read/Write`
- **Pages**: `Read/Write`
- **Projects**: `Read/Write`
- **Pull requests**: `Read/Write`
- **Repository security advisories**: `No Access`
- **Secret scanning alerts**: `No Access`
- **Secrets**: `No Access`
- **Single file**: `No Access`
- **Variables**: `No Access`
- **Webhooks**: `No Access`
- **Workflows**: `Read/Write`

#### Organization Permissions

- **API Insights**: `Read-only`
- **Administration**: `Read/Write`
- **Blocking users**: `No Access`
- **Custom organizations roles**: `Read and write`
- **Custom properties**: `No Access`
- **Custom repository roles**: `Read and write`
- **Events**: `Read-only`
- **GitHub Copilot Business**: `No Access`
- **Knowledge bases**: `No Access`
- **Members**: `Read/Write`
- **Organization codespaces**: `No Access`
- **Organization codespaces secrets**: `No Access`
- **Organization codespaces settings**: `No Access`
- **Organization dependabot secrets**: `No Access`
- **Personal access token requests**: `No Access`
- **Personal access tokens**: `No Access`
- **Plan**: `No Access`
- **Projects**: `Read/Write`
- **Secrets**: `No Access`
- **Self-hosted runners**: `No Access`
- **Team discussions**: `No Access`
- **Variables**: `No Access`
- **Webhooks**: `No Access`

#### Account Permissions:

- **Block another user**: `No Access`
- **Codespaces user secrets**: `No Access`
- **Copilot Chat**: `No Access`
- **Email addresses**: `No Access`
- **Events**: `No Access`
- **Followers**: `No Access`
- **GPG keys**: `No Access`
- **Gists**: `No Access`
- **Git SSH keys**: `No Access`
- **Interaction limits**: `No Access`
- **Plan**: `No Access`
- **Profile**: `No Access`
- **SSH signing keys**: `No Access`
- **Starring**: `No Access`
- **Watching**: `No Access`

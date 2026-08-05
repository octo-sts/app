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

An organization can restrict which OIDC issuers are allowed to federate with any
of its repositories by adding `.github/chainguard/trusted-token-issuers.yaml` to
its `.github` repository. A token whose issuer is not permitted is rejected
before its trust policy is ever read.

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/octo-sts/app/refs/heads/main/pkg/octosts/octosts.OrgTrustedIssuers.json

# "enforce" (the default) rejects tokens whose issuer is not permitted.
# "audit" permits them and records what would have been rejected.
mode: enforce

# Matched exactly. Note that a trailing slash makes a distinct issuer.
issuers:
  - https://token.actions.githubusercontent.com
  - https://accounts.google.com

# Anchored regular expressions matched against the whole issuer URL.
# Literal dots must be escaped, and wildcards that can match "/" are rejected.
issuer_patterns:
  - https://oidc\.eks\.[a-z0-9-]+\.amazonaws\.com/id/[A-Z0-9]+
```

Entries in `issuers` are matched exactly; entries in `issuer_patterns` are
anchored regular expressions that must match the entire issuer URL. An issuer is
permitted if it matches either list. Matching is case-sensitive, so entries must
be lowercase in their scheme and host.

**Patterns are checked for wildcards that can match `/`.** Anchoring a pattern
to both ends does not help when it is loose in the middle: `/` separates the host
from the path, so any atom that can match it lets a pattern reach past the host
entirely. Each single-character atom in a pattern — a bare `.`, an escaped class
such as `\S`, or a bracket expression such as `[^\n]` or `[[:ascii:]]` — is
compiled on its own and tested against `/`, and the pattern is rejected if any of
them matches. A literal `/` is fine; every issuer with a path has one.

This catches the common mistake of writing a pattern that spans into another
domain. `https://.*.example.com` reads as "any subdomain of example.com" but also
permits `https://evil.attacker-example.com`, because the unescaped `.` before
`example` matches `-`, and `https://totally-evil.com/x.example.com`, where the
host is wholly attacker-controlled. Write literal dots as `\.` and give an
explicit character class for the part that varies —
`https://[a-z0-9-]+\.example\.com` expresses "subdomains of example.com" and
rejects both. A rejected file reports an error naming the pattern.

A class that itself contains `/` is rejected for the same reason, so write a
path one segment at a time with literal separators —
`https://example\.com/realms/[a-z0-9-]+` rather than
`https://example\.com/[a-z0-9/-]+`. There is deliberately no way to match a
path of variable depth.

**This is a best-effort guard, not a guarantee.** It catches accidents, not a
determined author — write patterns as narrowly as you can. The file is written
by an organization owner, who is the principal this control serves, so an
over-broad pattern is an unwise choice rather than an attack.

**No file means no restriction.** Organizations that do not add one see no change
in behavior.

#### Rolling it out

Commit the file with `mode: audit` first. Nothing is rejected, and every token
that *would* have been rejected is logged and recorded on the exchange event, so
you can confirm the list is complete before enforcing. Remove the `mode` line to
enforce. Note that audit mode does not protect you against a broken file or a
failed lookup.

#### Requirement: the App must be able to read `.github`

The allowlist is read with a short-lived `contents: read` token scoped to the
`.github` repository. If octo-sts cannot read that repository — most often
because the App is installed on selected repositories only — **enforcement
silently does not apply.** GitHub answers a token request for an inaccessible
repository with a single 422 that cannot distinguish "does not exist" from "not
granted" from "permissions not granted", so octo-sts cannot report which case it
hit. Grant the App access to `.github` before relying on this control.

#### When the lookup fails

| Situation | Result |
| --- | --- |
| File absent | All issuers permitted |
| App cannot read `.github` | All issuers permitted, logged as a warning |
| Rate limited, or GitHub unavailable | Last known good allowlist; if there is none, the exchange is rejected |
| File present but invalid | Last known good allowlist; if there is none, every exchange in the organization is rejected |

This caching has three timing consequences. After *narrowing* the allowlist, the
previous broader list can still be served for up to an hour whenever GitHub
errors. After *fixing* an invalid file, rejections can persist for up to five
minutes while the cached result expires.

The one to plan for is *enabling* the allowlist. "No file" is itself valid last
known good state, so an organization adding its **first** allowlist while GitHub
is degraded can keep permitting all issuers for up to an hour. This is
deliberate: it is what keeps the organizations that do not use this feature
working through a GitHub incident. One successful read replaces it. Confirm
enforcement actually took effect after enabling rather than assuming it did.

#### Hardening

This control is only as trustworthy as write access to `org/.github`.

- **Create `org/.github` before you need it.** The name is not reserved, so in an
  organization without one, any member who can create a repository can become the
  sole author of this control. Restrict member repository creation.

- **Protect its default branch**, and make the `Trust Policy Validation` check a
  **required** status check. It validates this file on every pull request, but it
  only reports — it blocks nothing unless it is required.

- **Add a CODEOWNERS entry** for the file.

- **Scope organization-level trust policies with `repositories:`.** An
  organization-level policy granting `contents: write` with no `repositories:`
  restriction covers every repository the installation can see, `.github`
  included — so a federated identity could rewrite the very allowlist meant to
  constrain it. Any permission that can write, rename, or delete `org/.github`
  defeats this control, and **deleting the file fails open.**

- **`.github-private` is not consulted.** The file must live in `.github`.

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

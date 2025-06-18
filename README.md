# `octo-sts`: an STS for GitHub

This repository holds a GitHub App called `octo-sts` that acts like a Security
Token Service (STS) for the GitHub API. Using this App, workloads running
essentially anywhere that can produce OIDC tokens can federate with this App's
STS API in order to produce short-lived tokens for interacting with GitHub.

**_The ultimate goal of this App is to wholly eliminate the need for GitHub
Personal Access Tokens (aka PATs)._**

The original [blog post](https://www.chainguard.dev/unchained/the-end-of-github-pats-you-cant-leak-what-you-dont-have).

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
issuer: https://token.actions.githubusercontent.com
subject: repo:chainguard-dev/foo:ref:refs/heads/main

permissions:
  contents: read
  issues: write
```

The Trust Policy can also match the issuer, subject, and even custom claims with
regular expressions. For example:

```yaml
issuer: https://accounts.google.com
subject_pattern: '[0-9]+'
claim_pattern:
  email: '.*@chainguard.dev'

permissions:
  contents: read
```

It's also possible to set a static JWKS JSON document for verifying the token
signature. This is useful for cases where the OIDC discovery endpoint is not
reachable from the Internet, e.g. a Kubernetes cluster with a private API
server/OIDC discovery endpoint. Example:

```yaml
issuer: https://kubernetes.default.svc.cluster.local
audience: https://kubernetes.default.svc.cluster.local
subject: system:serviceaccount:my-app:my-app
jwks: |
  {
    "keys": [
      {
        "use": "sig",
        "kty": "RSA",
        "kid": "LHVGP8kqzN1MuKRMTsroIcR-7hdicXWdpaquEWcAh9Q",
        "alg": "RS256",
        "n": "s5XuFpodwhj6my_gTUHDKbHmQIx-3Tf40OduMZRWlU6_B_nSdjX01kS1UQSGw_G5eVQARooI-tY1vj3bBwn4dEEFa2TlnNnAJca0hj2Izef8A8Uw-mT0fgGI4Hs3xS84Mn_WXNlKXEiPLiFyOGNr0GQBKZDyTps8JUlvnwuWCv1gkzudUHa8B0i8ITSEUclK9_LqZj4zXUAN0Wj_4DVfI_PQ0IHci9K5Q9bgCV0j1EvTsyrwGyLFwyhktUmNhjREAfgYmxvbIRhPSP4YuO2Et1KM7YmjA75cQ9oE3i-QLrOZDripyMRop5RmWttQCEdEWLQWPzBd7aZ5CLbmZuIlIQ",
        "e": "AQAB"
      }
    ]
  }

permissions:
  contents: read
```

This policy will allow OIDC tokens from Google accounts of folks with a
Chainguard email address to federate and read the repo contents.

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

### Best Practices

To ensure secure and effective use of octo-sts, follow these recommended practices:

#### Repository Security

- **Enable branch protection**: Configure branch protection rules on your main/default branch to prevent direct commits and require pull request reviews before merging changes. This prevents OctoSTS clients from bypassing security controls by directly merging changes to main without review.

- **Restrict who can approve pull requests**: Limit pull request approval permissions to trusted team members or repository administrators.

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
- **Pages**: `No Access`
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

- **API Insights**: `No Access`
- **Administration**: `Read/Write`
- **Blocking users**: `No Access`
- **Custom organizations roles**: `No Access`
- **Custom properties**: `No Access`
- **Custom repository roles**: `No Access`
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

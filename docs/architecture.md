# octo-sts architecture: token-exchange sequence

How a token exchange flows through octo-sts, including the important calls and
every cache it touches, for both a single-App deployment and a multi-App
deployment (several GitHub Apps sharing load behind a round-robin manager).

The diagrams reflect the exchange path in `pkg/octosts` (`Exchange` →
`lookupInstallAndTrustPolicy` → `checkOrgTrustedIssuers` → `lookupTrustPolicy` →
`getExchangeInstall` → mint) and the installation manager in `pkg/ghinstall`.

## Caches

| Cache | Key → value | TTL | Purpose |
|---|---|---|---|
| **Install cache** (per App, `pkg/ghinstall`) | positive: owner → installation id · negative: owner → "not installed" | positive: none · negative: ~5 min | avoid a `ListInstallations` walk on every call |
| **Org-issuer LRU** (`pkg/octosts`, + single-flight) | owner → allowlist decision | 5 min fresh · ~1 h stale | avoid re-reading the org allowlist per exchange |
| **Trust-policy LRU** (`pkg/octosts`) | (owner, repo, identity) → policy YAML (and a negative entry) | LRU, with a stale-on-rate-limit fallback | avoid re-reading `.sts.yaml` per exchange |
| **Sticky store** (Firestore or in-memory) | route key → installation id | ~1 h | pin a `checks:write` identity to one App so check-run ownership is stable |

## Single application instance

```mermaid
sequenceDiagram
    autonumber
    actor C as Caller (CI / workload)
    participant S as octo-sts (Exchange)
    participant J as OIDC IdP (JWKS, provider cache)
    participant IC as Install cache
    participant OI as Org-issuer LRU
    participant TP as Trust-policy LRU
    participant GH as GitHub App API

    C->>S: Exchange(OIDC token, scope, identity)
    S->>J: verify token signature + claims
    J-->>S: issuer, subject
    Note over S: validate scope and identity present

    S->>TP: get(owner,repo,identity)
    alt negative-cache hit
        TP-->>S: not found
        S-->>C: NotFound (stop)
    end

    S->>IC: Get(owner)
    alt negative-cache hit (not installed)
        IC-->>S: NotFound
        S-->>C: NotFound (stop)
    else miss
        S->>GH: ListInstallations
        GH-->>S: installation id
        S->>IC: setInstalled(id)
    end

    Note over S,GH: Org trusted-issuer allowlist
    S->>OI: orgIssuerLookup(owner)
    alt cache hit
        OI-->>S: decision
    else miss (single-flight per owner)
        S->>GH: mint .github token + read trusted-token-issuers.yaml
        GH-->>S: file / 404 / 422
        S->>OI: cache decision (5m + ~1h stale)
    end
    Note over S: absent→allow · listed→allow · enforce+unlisted→DENY

    S->>TP: lookupTrustPolicy(key)
    alt cache hit
        TP-->>S: policy YAML
    else miss
        S->>GH: mint contents:read token + read <identity>.sts.yaml (revoked after)
        GH-->>S: YAML (404 → negative cache)
        S->>TP: cache policy
    end

    Note over S: CheckToken — does issuer/subject match the trust policy?
    S->>GH: mint scoped token (policy repos + permissions)
    GH-->>S: installation access token
    S-->>C: scoped GitHub token
```

## Multiple application instances (round-robin over N Apps)

The OIDC verify, `CheckToken`, and final mint are identical to the single-App
flow. The differences are App selection, cross-App enumeration for the allowlist,
cross-App retry, and sticky routing.

```mermaid
sequenceDiagram
    autonumber
    actor C as Caller (CI / workload)
    participant S as octo-sts (Exchange)
    participant RR as Round-robin Manager
    participant OI as Org-issuer LRU
    participant TP as Trust-policy LRU
    participant SK as Sticky store
    participant A1 as App 1 (cache + API)
    participant AN as App N (cache + API)

    C->>S: Exchange(OIDC token, scope, identity)
    Note over S: verify OIDC, validate scope/identity, trust-policy neg-cache check

    Note over S,AN: Pick an install (capacity-aware)
    S->>RR: Get(owner, scope, identity)
    RR->>A1: installed? (install cache / ListInstallations)
    RR->>AN: installed? (install cache / ListInstallations)
    RR-->>S: pickByQuota → App k (most remaining quota)

    Note over S,AN: Org allowlist — ask EVERY App who can read .github
    S->>OI: orgIssuerLookup(owner)
    alt cache hit
        OI-->>S: decision
    else miss (single-flight per owner)
        S->>RR: GetAll(owner)
        RR->>A1: installs (positive + negative cache)
        RR->>AN: installs (positive + negative cache)
        RR-->>S: union of observed installs
        loop each install until definitive
            S->>A1: mint .github token + read allowlist
            A1-->>S: file / 404(absent) / 422(blind) / ratelimited
        end
        alt all blind, none failed
            Note over S,RR: confirm before concluding "no allowlist applies"
            S->>RR: GetAllFresh(owner) (bypass negative cache)
            RR->>AN: fresh ListInstallations
            RR-->>S: installs a negative cache had hidden
            S->>AN: mint + read allowlist on newly-found installs
        end
        S->>OI: cache decision (5m + ~1h stale)
    end
    Note over S: fail CLOSED if the allowlist cannot be established

    Note over S,AN: Trust-policy read, retry across Apps on rate limit
    S->>TP: lookupTrustPolicy(key)
    alt cache miss
        S->>A1: mint contents:read + read <identity>.sts.yaml
        A1-->>S: 403/429 rate-limited
        S->>AN: retry read on another App
        AN-->>S: policy YAML
        S->>TP: cache policy
    end

    Note over S,SK: checks:write must stay on ONE App (check-run ownership)
    alt policy grants checks:write
        S->>SK: Get(routekey)
        alt sticky hit
            SK-->>S: installation id → same App
        else miss
            S->>RR: Get → assign App (consistent-hash / quota)
            S->>SK: Put(routekey, id)
        end
    end

    S->>A1: mint scoped token (policy repos + permissions)
    A1-->>S: installation access token
    S-->>C: scoped GitHub token
```

## Single vs multiple: the differences that matter

- **Install selection.** Single: the one App, or `NotFound`. Multi: `pickByQuota`
  selects the App with the most remaining rate-limit quota.
- **Allowlist enumeration.** Single walks one App. Multi must walk **every** App
  via `GetAll`, and confirms a "no allowlist applies" verdict with `GetAllFresh`,
  which bypasses the negative install cache. Without that confirmation, an App
  installed to turn enforcement on could be hidden by the negative cache and flip
  an enforcing org to allow-all. The per-owner single-flight keeps a cold-cache
  burst from stampeding this enumeration.
- **Rate-limit resilience.** Multi retries the trust-policy read on a different
  App when one is rate-limited; single cannot.
- **`checks:write` routing.** Only meaningful with multiple Apps: GitHub lets only
  the App that created a check run update it, so the sticky store pins the identity
  to one App across exchanges.
- **Fail-closed posture.** In enforce mode, if the allowlist cannot be established
  (errors, incomplete enumeration), the exchange is denied rather than allowed.

# IAM Middleware Contract

## Introduction

IAM Middleware is a shared Go library that every API service embeds to enforce
access. It is the request-time half of the authorization model: the IAM API
owns the records ([`contract.md`](contract.md)), `ds-go-policy` owns matching
and effect resolution ([`policy/iam-policy-contract.md`](policy/iam-policy-contract.md)),
and the middleware owns **resolving the caller's policy set, keeping it fresh,
and turning a decision into an HTTP verdict**. There is no standalone PDP
service: the policy set is fetched from the IAM API (or resolved in-process,
inside ds-iam itself — see [Data plane](#data-plane)), compiled once, cached
in process, and evaluated locally. The engine is a pure function of
`(policies, request)`, so a remote PDP could replace local evaluation later
without touching a single service call site.

The middleware sits after authentication and before the handler. It consumes
what is already in the request context — the verified `sub` and tenant — and
what only the service knows: the action, the resource CRN, and the context
attributes. It never verifies tokens, never builds CRNs, and never authors
policy. One library, one behavior, in every service.

## Surface

The library exposes three things, split so the fetch/cache concern and the
decision concern sit where each belongs.

**The resolver middleware** runs on every protected route. It resolves the
compiled policy set for `(tenant, sub)` — from cache or from the policy
source — and stores it in the request context. It makes no decision by itself; a principal
with an empty set passes through and every later check denies.

**`Decide`** is the point check, called in the handler at the moment the
resource CRN is known:

```go
decision := iam.Decide(ctx, iam.Request{
    Action:   "file:getFile",
    Resource: resourceCRN,
    Context:  map[string]string{"owner_id": ownerID},
})
if !decision.Allowed {
    return httperror.Forbidden(...)   // decision.Reason carries the matched sid or "implicit deny"
}
```

**`Constrain`** is the list-shaped check: it returns the surviving allow/deny
patterns for an action, which a storage adapter (e.g. `sqlfilter`) turns into
a WHERE clause. Point checks and list filters share one matcher, so they can
never disagree. A list endpoint must never loop `Decide` over rows.

Both calls read the compiled set the resolver stored in context — after the
resolver has run, a decision is a pure in-memory evaluation with no I/O on the
request path.

## Data plane

The middleware never talks to storage directly; it resolves policy sets
through one small seam:

```go
// PolicyFetcher returns the engine documents in force for (tenant, principal),
// plus a strong tag over the set. When the offered etag still matches, the
// source answers NotModified: no documents, no recompile.
type PolicyFetcher interface {
    FetchPolicies(ctx context.Context, tenantID, principalID, authorization, etag string) (FetchResult, error)
}
```

Everything above the seam — cache, ages, compile, `Decide`, `Constrain` — is
fetcher-agnostic. Two implementations exist, and choosing one is the only
per-service wiring difference.

**The HTTP fetcher** is the default, used by every service except ds-iam. It
reads exactly one IAM endpoint:

```text
GET {iam}/principal/{principal_id}/policies/
```

`principal_id` is the token `sub`, verbatim. The IAM API resolves the grant
path — active memberships → active groups → bindings → active policies,
tenant-owned or managed public — and returns ready-to-compile engine documents
(`id`, `version`, `statements`). The middleware performs no joins and no
placeholder handling: the reserved `aic` tenant token is matched natively by
the engine at evaluation time.

The response carries a strong `ETag` over the set's policy ids and
modification times; revalidation is `If-None-Match`, and a `304` costs no body
and no recompile. An empty set is a valid answer (`200`, `policies: []`) and
is cached like any other — absence of grants is default-deny, not an error.
The call forwards `authorization` — the caller's own bearer, captured verbatim
from the request — so the IAM API's tenant scoping applies unchanged and the
middleware needs no credentials of its own; the `tenantID` argument is unused,
because the bearer already scopes the tenant.

**The in-process fetcher** exists because ds-iam enforces access with the same
middleware, and the service calling itself over HTTPS would be a needless hop
and a circular dependency — an overload would degrade resolution, which would
add load. ds-iam owns the tables and already owns the resolution logic, so its
fetcher is a thin adapter over `PrincipalService.EffectivePolicies` — the same
code path the HTTP endpoint serves, so the two fetchers cannot disagree on
what a principal's set is. It resolves from `tenantID` directly and ignores
`authorization`; the tag is computed with the same id + modified-time hash the
endpoint uses for its `ETag`. Nothing else changes: the compiled set is still
cached with the same ages, because the cost being amortized is
`engine.Compile`, not the fetch.

## Cache

A policy set is slow-changing data read on every request, and the expensive
step is `engine.Compile` — parsing CRN patterns and validating condition
operators — not the fetch. The cache therefore holds the **compiled** set,
keyed by `(tenant, principal)`, with the `ETag` and a fetch timestamp. A
compiled set is a Go object graph; this tier does not move out of process, and
two service replicas simply cache independently.

Each entry has two ages:

- **TTL** (order of minutes): past it, the entry must be revalidated against
  the policy source before use. An unchanged set (`304`, or a matching tag)
  resets the clock without a recompile.
- **Max-stale** (order of tens of minutes): the hard bound. Past it, the entry
  is unusable even if the policy source is down.

Within the TTL every request is a pure cache hit, so the correctness property
— **revocation lag** — is bounded by the TTL. A grant that appears late is
harmless; a revoked grant that survives is not, which is why the TTL is short.

## Failure policy

Decisions fail closed; availability degrades before correctness does.

| Situation | Behavior |
|---|---|
| Set resolved, statement denies or nothing matches | `403`, reason logged (`sid` or implicit deny) |
| Policy source unreachable, cached entry within max-stale | Serve from stale cache; revalidation retries on a short cooldown |
| Policy source unreachable, no entry or past max-stale | `503` — an outage, not a denial, and callers must be able to tell them apart |
| Policy set fails to compile | The whole set is refused (`503`) and logged loudly — excluding only the bad document could drop a `deny` and silently widen access. The IAM API's 422 validation makes this a should-never invariant, not a live path |

The middleware never fails open: there is no configuration that turns an
unresolved policy set into an allow.

Rollout risk is managed by environment, not by a mode switch: each service is
deployed against dev before prod, so enforcement is exercised end to end
before it guards production traffic.

## Configuration

| Key | Meaning | Default |
|---|---|---|
| `iam_base_url` | IAM API prefix, e.g. `https://…/api/iam/v1` (HTTP fetcher only) | — (required) |
| `cache_life_window` | How long the service-owned cache retains entries (for bigcache, its `LifeWindow`); must be at least `cache_max_stale`, refused at startup otherwise | — (required) |
| `cache_ttl` | Revalidation age of a cached set | `60s` |
| `cache_max_stale` | Hard bound for serving when the policy source is unreachable | `30m` |
| `fetch_timeout` | Budget for one data-plane call | `3s` |

## Deviations from the governance draft

Three places where this contract deliberately departs from the governance
draft, with the reasoning on record:

- **No event-driven invalidation (yet).** The draft's Kafka eviction bounds
  revocation lag by event latency; this implementation bounds it by a
  deliberately short TTL (60s) instead — simpler, no consumer to operate, and
  the lag is already tighter than the draft's 5m TTL backstop. The seam for
  events exists: `Evict(tenant, principal)` drops one cached set, which is
  what ds-iam calls synchronously on its own writes (zero revocation lag for
  the writes it observes) and what a future consumer would call per `member`
  event. Tenant-wide eviction for `group`/`policy` events is the one piece
  that remains future work.
- **No shadow mode.** Rollout risk is managed by environment: each service is
  deployed against dev before prod, so enforcement is exercised end to end
  before it guards production traffic. Denials are logged at `Info` with
  action and reason, which provides the observability shadow mode existed for.
- **Compile failure refuses the whole set.** The draft excludes the failing
  document; excluding a `deny` document would silently widen access — the one
  direction an authorization system must never fail. The IAM API's 422
  validation makes the case should-never either way, so the stricter behavior
  costs nothing.

## Ownership

| Concern | Owner |
|---|---|
| Token verification, `sub` and tenant in context | Auth middleware (upstream) |
| Building the canonical CRN and context attributes | The service, at the call site |
| Fetching, caching, and compiling the policy set | **IAM Middleware** |
| Matching and effect resolution (`Compile`, `Decide`, `Constrain`) | `ds-go-policy` |
| The records and the data-plane endpoint | IAM API |

The seam to remember: the service knows *what is being touched*, the
middleware knows *what the caller may touch*, and neither can do the other's
job.

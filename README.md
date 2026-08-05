# ds-go-iam-middleware

![Build](https://github.com/grasp-labs/ds-go-iam-middleware/actions/workflows/ci.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/grasp-labs/ds-go-iam-middleware)](https://goreportcard.com/report/github.com/grasp-labs/ds-go-iam-middleware)
[![codecov](https://codecov.io/gh/grasp-labs/ds-go-iam-middleware/branch/main/graph/badge.svg)](https://codecov.io/gh/grasp-labs/ds-go-iam-middleware)
[![GitHub release](https://img.shields.io/github/v/release/grasp-labs/ds-go-iam-middleware)](https://github.com/grasp-labs/ds-go-iam-middleware/releases)
![License](https://img.shields.io/github/license/grasp-labs/ds-go-iam-middleware?cacheSeconds=60)

Echo middleware that authorizes requests against the IAM service.

Policy semantics live in [ds-go-policy](https://github.com/grasp-labs/ds-go-policy). This module resolves the principal, fetches and caches their policies, and exposes the decision to handlers through `context.Context`.

## Wiring

```go
authz, err := iam.New(iam.Config{
    Fetcher:         &iam.HTTPFetcher{BaseURL: cfg.IAMURL},
    Cache:           app.Cache,       // your *bigcache.BigCache
    CacheLifeWindow: cacheLifeWindow, // the LifeWindow app.Cache was built with
    Principal:       iamPrincipal,
})
if err != nil {
    return err
}
e.Use(authz.Handler())
```

`Principal` is `func(context.Context) (iam.Principal, error)` — read the ID and tenant from whatever your auth middleware already put in the context. This package never validates credentials.

`CacheLifeWindow` is required and must be at least `MaxStale` (default 30m). Serving through an IAM outage reads cache entries up to `MaxStale` old, and a cache that evicts sooner would silently shorten that tolerance to its own window — so `New` refuses the mismatch at startup instead. Pass the same constant your cache was built from; if your API's cache keeps the common 10-minute window, either raise it to 30m or set `MaxStale` to 10m deliberately.

`Handler` captures the request's `Authorization` header and forwards it verbatim when the principal's policies are fetched, so the IAM API's own tenant scoping applies and the service configures no credentials for this middleware.

With [ds-go-echo-middleware](https://github.com/grasp-labs/ds-go-echo-middleware), the authentication middleware has already normalised the token into a principal, so the adapter is:

```go
func iamPrincipal(ctx context.Context) (iam.Principal, error) {
    p, ok := requestctx.GetPrincipal(ctx)
    if !ok {
        return iam.Principal{}, iam.ErrNoPrincipal
    }
    return iam.Principal{ID: p.ID, TenantID: p.TenantID.String()}, nil
}
```

`p.ID` is the token's `sub` — the same value the IAM API keys a principal by — and `p.TenantID` is parsed from `rsc` during authentication, so a token that fails to yield a tenant never reaches this middleware. Order the stack accordingly: request id, authentication, then `authz.Handler()`.

## Handlers

```go
resource, err := crn.Build(tenantID, ownerID, "file", "", "file", path)
if err != nil {
    return httperror.BadRequest(err)
}

d := iam.Decide(ctx, iam.Request{
    Action:   "file:getFile",
    Resource: resource,
    Context:  map[string]string{"owner_id": ownerID},
})

switch {
case errors.Is(d.Err, iam.ErrNoPrincipal), errors.Is(d.Err, iam.ErrTokenRejected):
    return httperror.Unauthorized()
case errors.Is(d.Err, iam.ErrNoMiddleware), errors.Is(d.Err, iam.ErrPrincipalRejected):
    return httperror.Internal(d.Err)
case d.Err != nil:
    return httperror.Unavailable(d.Err)
case !d.Allowed:
    return httperror.Forbidden(d.Reason) // matched Sid, or "implicit deny"
}
```

`Decide` returns no error, so no error path can be mistaken for permission.

## List endpoints

A list or search has no concrete resource to point `Decide` at, and looping it over rows checks only what the query already returned. `Constrain` is the list-shaped half: it reduces the policy set to the allow/deny patterns that survive for the action, and an adapter from ds-go-policy turns them into a filter the storage layer enforces.

```go
import "github.com/grasp-labs/ds-go-policy/adapter/sqlfilter"

cons, err := iam.Constrain(ctx, "file:listFiles", nil)
if err != nil {
    return mapIAMError(err) // same buckets as a Decide error; do not run the query
}

where, args, err := sqlfilter.Where(cons, sqlfilter.Mapping{
    Tenant:     "tenant_id",
    Type:       "type",
    Resource:   sqlfilter.ResourceColumn{Path: "path"},
    Conditions: map[string]string{"status": "status"}, // row attribute -> column
})
if err != nil {
    return httperror.Internal(err) // pattern the adapter cannot express: fail closed
}

db.Where(where, args...).Find(&files)
```

Unlike `Decide`, `Constrain` returns an error — a filter has no fail-closed zero value, and an unresolved policy set must abort the query rather than return an empty (or worse, unfiltered) result. Point checks and list filters share one matcher in ds-go-policy, so they can never disagree.

The buckets matter more than the sentinels. A request that could not be decided must not read as a denial: `403` says "you may not", `503` says "we could not tell", and a caller retrying the first forever is a bug you will not see in the logs.

| Error | Status | Meaning |
|---|---|---|
| `ErrNoPrincipal` | 401 | The request was never identified. |
| `ErrTokenRejected` | 401 | IAM refused the forwarded token — usually expired since our own auth check. |
| `ErrNoMiddleware` | 500 | `Decide` ran on a route that skipped `Handler`. A wiring bug. |
| `ErrPrincipalRejected` | 500 | IAM will not accept the principal id. Permanent; retrying cannot fix it. |
| `ErrPolicySourceUnavailable` | 503 | Transport failure, `429`, or `5xx` — and no cached set young enough to serve stale. |
| `ErrPolicySetMismatch` | 503 | IAM answered with another principal's set. |

## How it works

Two cache layers. `Cache` (bigcache) holds raw policy JSON, keyed by principal. An in-process map holds `*engine.Compiled`, keyed by a content hash of the response. The second layer is not an optimisation: `Cache` stores bytes, so without it every cache *hit* would re-run `Unmarshal` and `engine.Compile`. The hash rather than the `ETag` is deliberate — that map is shared by every principal in the process, and equal bytes are safe to share where equal validators would not be.

Lazy. `Handler` does no I/O. Policies load on the first `Decide`, so routes that authorize nothing cost nothing and survive an IAM outage.

Deduplicated. Cold lookups for the same principal collapse via `singleflight`, detached from the request so a client disconnect cannot cancel a fetch others are waiting on.

Fail closed. No principal, a token IAM refuses, IAM unreachable, policies that will not compile — all give `Allowed: false` with `Err` set. There is no configuration that turns an unresolved policy set into an allow.

Fail static. When the IAM service is unreachable, a set fetched less than `MaxStale` ago (default 30m) keeps answering: availability degrades before correctness does, and only for principals who already held a set. A failed revalidation starts a short cooldown so an outage costs one fetch round trip per principal per cooldown, not one per request. Past `MaxStale` the outage surfaces as `ErrPolicySourceUnavailable` — a `503`, not a `403`. A `401` or `422` from IAM is an answer about the caller, never papered over with a stale set.

Checked. The policy set echoes the principal it belongs to, and a set naming anyone else is refused rather than compiled.

Evictable. `Evict(tenantID, principalID)` drops one cached set so the next request resolves it afresh — for a service that observes its own permission-changing writes (ds-iam), calling it synchronously means zero revocation lag for those writes.

Revocation lag equals `TTL` (default 60s) while IAM is reachable. During an outage it can grow to `MaxStale` for a principal whose set was already cached — the price of staying up.

## Testing handlers

```go
ctx, err := iam.NewTestContext(context.Background(),
    iam.Principal{ID: "user-1", TenantID: tenantID}, policyJSON)
```

## License

Apache 2.0
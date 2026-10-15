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
import (
    "github.com/grasp-labs/ds-go-iam-middleware/adapter/echoiam"
    "github.com/grasp-labs/ds-go-iam-middleware/iam"
)

authz, err := iam.New(iam.Config{
    Fetcher:         &iam.HTTPFetcher{BaseURL: cfg.IAMURL},
    Cache:           app.Cache,       // your *bigcache.BigCache
    CacheLifeWindow: cacheLifeWindow, // the LifeWindow app.Cache was built with
    Principal:       echoiam.ResolvePrincipal,
})
if err != nil {
    return err
}
e.Use(authz.Handler())
```

`Principal` is `func(context.Context) (iam.Principal, error)` — read the ID and tenant from whatever your auth middleware already put in the context. This package never validates credentials.

`ServiceID` is an optional opt-in: set it in `Config` (e.g. `ServiceID: "file"`) and compilation keeps actions for this service or `*`, while `Constrain` keeps allow and deny resource patterns for this service or `*`. The file service compiles `file:getFile` but drops `state:getJobs`. It sits above the fetcher seam, so it works for either policy source; left unset, the whole set is unchanged.

`CacheLifeWindow` is required and must be at least `MaxStale` (default 30m). Serving through an IAM outage reads cache entries up to `MaxStale` old, and a cache that evicts sooner would silently shorten that tolerance to its own window — so `New` refuses the mismatch at startup instead. Pass the same constant your cache was built from; if your API's cache keeps the common 10-minute window, either raise it to 30m or set `MaxStale` to 10m deliberately.

`Handler` captures the request's `Authorization` header and forwards it verbatim when the principal's policies are fetched, so the IAM API's own tenant scoping applies and the service configures no credentials for this middleware.

With [ds-go-echo-middleware v3](https://github.com/grasp-labs/ds-go-echo-middleware), use `echoiam.ResolvePrincipal` as shown above. It reads the normalized identity from `requestctx.GetPrincipal`, preserves the subject verbatim, and converts the tenant UUID to a string. A missing identity, empty subject, or zero tenant returns `iam.ErrNoPrincipal`. It reads only the normalized principal; legacy claims alone do not satisfy it.

The adapter does not authenticate requests or fetch policies. Order the stack accordingly: request id, authentication, then `authz.Handler()`. Services using another authentication implementation can continue supplying their own `Config.Principal` callback.

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
| `ErrAccessDenied` | 403 | The guard or converter refused access. |
| `ErrNoPrincipal` | 401 | The request was never identified. |
| `ErrTokenRejected` | 401 | IAM refused the forwarded token — usually expired since our own auth check. |
| `ErrNoMiddleware` | 500 | `Decide` ran on a route that skipped `Handler`. A wiring bug. |
| `ErrPrincipalRejected` | 500 | IAM will not accept the principal id. Permanent; retrying cannot fix it. |
| `ErrPolicySourceUnavailable` | 503 | Transport failure, `429`, or `5xx` — and no cached set young enough to serve stale. |
| `ErrPolicySetMismatch` | 503 | IAM answered with another principal's set. |
| `ErrPolicyResolution` | 503 fallback | `Decide` and `Constrain` wrap policy fetch, decode, and compile failures. Check the specific errors above first; causes remain available through `errors.Is` and `errors.As`. |

## Declarative guards

`Guard[Result]` binds an action to point checks and a service-owned converter.
`Require(ctx, req)` calls `Decide` with the guard's action, preserving other request
fields. It returns `nil` for an allow, wraps `ErrAccessDenied` for a denial, and
returns decision errors unchanged. It does not use `Convert`.

`Constrain(ctx)` calls `Constrain` with no request attributes, then passes the
complete constraints to `Convert`.
The converter enforces the allow/deny patterns and produces the service's query
scope or other result, including when no allow matches.

Services can supply their own converters and specialize the guard in their
`authz` package with `type Guard = iam.Guard[repo.Scope]`.

Set `Action` and, for `Constrain`, a non-nil `Convert`. Do not modify shared
guards. A policy resolution failure skips conversion and returns the result's
zero value and the error from `Constrain`. Converter results and errors pass
through unchanged. Use `Constrain` directly when request attributes are needed; keep
checks on proposed write values and service-specific tracing in the service.

## GORM scopes

`adapter/gormfilter` provides the shared SQL-to-GORM converter. The service owns
the `sqlfilter.Mapping`, including its resource columns, condition allowlist, and
publication rules:

```go
import (
    "github.com/grasp-labs/ds-go-iam-middleware/adapter/gormfilter"
    "github.com/grasp-labs/ds-go-iam-middleware/iam"
)

var listGuard = iam.Guard[gormfilter.Scope]{
    Action:  "config:listDataset",
    Convert: gormfilter.Via(datasetMapping),
}

scope, err := listGuard.Constrain(ctx)
if err != nil {
    return err // map errors.Is(err, iam.ErrAccessDenied) to 403
}
db.Scopes(scope).Find(&datasets)
```

`Scope` is an alias of `func(*gorm.DB) *gorm.DB`. Services can use the same alias
for their repository scopes. Apply the scope to counts and writes as well as
reads, alongside any additional service restrictions.

For a service that assembles its own predicate, `Bind` applies the completed SQL
to the supplied query:

```go
scope, err := gormfilter.Bind(where, args...)
```

Check SQL generation errors before calling `Bind`. SQL must come from trusted
code; values go through the heterogeneous `args ...any`. Both helpers group the
predicate so additional filters cannot widen an `OR` grant. They return
`iam.ErrAccessDenied` for the closed clause identified by `sqlfilter.IsClosed`.
Empty SQL is rejected as invalid input, and translation errors pass through
unchanged. `Bind` does not parse or validate arbitrary SQL.

Custom converters and point-check wrappers can use the same `iam.ErrAccessDenied`
for permission denials. Policy-loading failures wrap `ErrPolicyResolution` and
their original cause. Ordinary `Decide` denials still have `Allowed: false` and
`Err: nil`.

## Authorization audit events

Create one publisher with the service's existing Kafka producer, compliance
topic, and event source, then install the Echo adapter after authentication and
before `authz.Handler()`:

```go
import "github.com/grasp-labs/ds-go-iam-middleware/audit"

publisher, err := audit.New(producer, complianceTopic, "ds.core.file.v1")
if err != nil {
    return err
}
e.Use(authentication, echoiam.Audit(publisher), authz.Handler())
```

The adapter observes `iam.Decide`, failed `iam.Constrain` calls, and completed
`iam.Guard.Constrain` conversions. It publishes a failed final IAM outcome when
the request finishes with a failed HTTP status. A later successful check clears
an earlier refusal. Use guards to include converter denials and errors. Calling
`iam.Constrain` and converting its result yourself only observes policy-loading
failures. Unrelated HTTP errors and successful requests emit no authorization
event. Existing authentication middleware continues to own login events.

Events use the SDK `EventJson` envelope. `authz.denied` covers policy denials,
`ErrAccessDenied`, `ErrNoPrincipal`, and `ErrTokenRejected`; other failures use
`authz.error`. The payload preserves `status_code`, `subject`, `error` (nullable),
`path`, `user_agent`, and `remote_addr`, and adds `action`, `reason`, and an optional
concrete `resource` CRN. Identity comes from the verified principal. The path is
the Echo route pattern, without query parameters or tokens. Request and session
IDs are preserved; metadata is an empty object and the envelope checksum is the
MD5 of the serialized payload. A non-empty `X-Message` header is preserved in the
envelope's optional `message` field, as in the entitlement middleware.

The adapter uses the written response status when available. For returned errors,
it follows Echo's default error handler, including treating wrapped errors as
HTTP 500. Custom error handling must write the response before returning for its
status to be reflected in the event.

Publishing is asynchronous and best effort, with a three-second timeout detached
from request cancellation. Send errors are logged and never change the HTTP
response. Pending sends are not drained at shutdown. The framework-independent
`audit.Publisher.Publish` method sends synchronously for other adapters.

## How it works

Two cache layers. `Cache` (bigcache) holds raw policy JSON, keyed by principal. An in-process map holds `*engine.Compiled`, keyed by a content hash of the response. The second layer is not an optimisation: `Cache` stores bytes, so without it every cache *hit* would re-run `Unmarshal` and `engine.Compile`. The hash rather than the `ETag` is deliberate — that map is shared by every principal in the process, and equal bytes are safe to share where equal validators would not be.

Lazy. `Handler` does no I/O. Policies load on the first `Decide` or `Constrain`, so routes that authorize nothing cost nothing and survive an IAM outage.

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

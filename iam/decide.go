package iam

import (
	"context"
	"sync"

	"github.com/grasp-labs/ds-go-policy/crn"
	"github.com/grasp-labs/ds-go-policy/engine"
)

type Request struct {
	// Action is "{service}:{operationId}", e.g. "file:getFile".
	Action string

	// Resource is typed, not a string, so a handler cannot pass a wildcard
	// resource that would match a wildcard Allow. Build it with crn.Build.
	Resource crn.CRN

	// Context supplies request attributes that policy conditions test.
	Context map[string]string
}

type Decision struct {
	Allowed bool

	// Reason is the matching statement's Sid, or "implicit deny".
	Reason string

	// Err is set when no decision could be reached: no principal, the token
	// refused by IAM, IAM unreachable, policies that will not compile. Allowed
	// is then false.
	//
	// An unreachable policy source is an outage rather than a denial, so it
	// must not reach the caller as 403. The three buckets:
	//
	//	switch {
	//	case errors.Is(d.Err, iam.ErrNoPrincipal),
	//		errors.Is(d.Err, iam.ErrTokenRejected):
	//		return httperror.Unauthorized()
	//	case errors.Is(d.Err, iam.ErrNoMiddleware),
	//		errors.Is(d.Err, iam.ErrPrincipalRejected):
	//		return httperror.Internal(d.Err)
	//	case d.Err != nil:
	//		return httperror.Unavailable(d.Err)
	//	case !d.Allowed:
	//		return httperror.Forbidden(d.Reason)
	//	}
	Err error
}

// ctxKey is private, so nothing outside this package can forge the value.
type ctxKey struct{}

// holder is the per-request state Handler puts in the context. Policies load on
// the first Decide, so a route that authorizes nothing does no I/O and is
// unaffected by an IAM outage.
type holder struct {
	mw        *Middleware
	principal Principal
	err       error

	// authorization is the caller's Authorization header, forwarded verbatim
	// when their policies are fetched. The IAM API applies its own tenant
	// scoping to it, so this middleware needs no credentials of its own.
	authorization string

	mu  sync.Mutex
	set *engine.Compiled
}

// newContext resolves the principal and attaches the per-request state.
//
// Handler and NewTestContext both go through here, so a context built for a
// test behaves exactly like a served one. A missing principal is recorded
// rather than rejected, so this need not know which routes are public — it
// surfaces as ErrNoPrincipal from the first Decide.
//
// A principal without a tenant is refused the same way: the tenant scopes the
// cache key, so accepting an empty one would let two tenants' entries collide.
func (m *Middleware) newContext(ctx context.Context, authorization string) context.Context {
	h := &holder{mw: m, authorization: authorization}
	h.principal, h.err = m.cfg.Principal(ctx)
	if h.err == nil && (h.principal.ID == "" || h.principal.TenantID == "") {
		h.err = ErrNoPrincipal
	}
	return context.WithValue(ctx, ctxKey{}, h)
}

func (h *holder) load(ctx context.Context) (*engine.Compiled, error) {
	if h.err != nil {
		return nil, h.err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.set == nil {
		set, err := h.mw.load(ctx, h.principal.TenantID, h.principal.ID, h.authorization)
		if err != nil {
			return nil, err
		}
		h.set = set
	}
	return h.set, nil
}

// Decide answers one authorization question for the principal on ctx.
//
// It returns no error: every failure is a Decision with Allowed false, so no
// error path can be mistaken for permission.
func Decide(ctx context.Context, req Request) Decision {
	h, ok := ctx.Value(ctxKey{}).(*holder)
	if !ok {
		return Decision{Reason: ErrNoMiddleware.Error(), Err: ErrNoMiddleware}
	}

	set, err := h.load(ctx)
	if err != nil {
		h.mw.cfg.Logger.Error("iam: cannot authorize",
			"principal_id", h.principal.ID, "action", req.Action, "error", err)
		return Decision{Reason: err.Error(), Err: err}
	}

	d := set.Decide(engine.Request{
		Action:   req.Action,
		Resource: req.Resource,
		Context:  req.Context,
	})
	// Info, not Debug: the deny rate is the signal watched during a rollout,
	// and it must be visible at a production log level. Volume is bounded by
	// the 403 rate, not the request rate.
	if !d.Allowed {
		h.mw.cfg.Logger.Info("iam: denied",
			"principal_id", h.principal.ID, "action", req.Action, "reason", d.Reason)
	}
	return Decision{Allowed: d.Allowed, Reason: d.Reason}
}

// Constrain is the list-shaped check: it reduces the principal's policy set to
// the allow/deny resource patterns that survive for action, for a storage
// adapter (e.g. ds-go-policy/adapter/sqlfilter) to turn into a query filter.
// Point checks and list filters share one matcher, so a list endpoint must
// never loop Decide over rows.
//
// attrs supplies the request attributes that are already known (the same kind
// of values Decide takes in Request.Context); a statement whose condition on
// such an attribute fails is dropped up front. Conditions on attributes that
// live on the rows themselves stay attached to the returned patterns for the
// adapter to translate.
//
// Unlike Decide this returns an error, because a filter has no fail-closed
// zero value: empty Constraints means "nothing visible", which is only correct
// when the policy set actually resolved. On error, map it exactly like a
// Decide error (401/500/503) and do not run the query.
func Constrain(ctx context.Context, action string, attrs map[string]string) (engine.Constraints, error) {
	h, ok := ctx.Value(ctxKey{}).(*holder)
	if !ok {
		return engine.Constraints{}, ErrNoMiddleware
	}

	set, err := h.load(ctx)
	if err != nil {
		h.mw.cfg.Logger.Error("iam: cannot constrain",
			"principal_id", h.principal.ID, "action", action, "error", err)
		return engine.Constraints{}, err
	}

	// The principal's tenant resolves any platform ("aic") patterns, so the
	// adapter only ever sees concrete tenants.
	constraints := set.Constrain(action, h.principal.TenantID, attrs)
	if h.mw.cfg.ServiceID != "" {
		constraints = scopeToService(constraints, h.mw.cfg.ServiceID)
	}
	return constraints, nil
}

// scopeToService drops resource patterns another service owns, keeping only
// those for serviceID or the wildcard service. It mirrors filterByService on
// the resource side: a trim for the query adapter, not a change to any verdict.
func scopeToService(constraints engine.Constraints, serviceID string) engine.Constraints {
	return constraints.Filter(func(match engine.ResourceMatch) bool {
		service := match.Pattern.Service()
		return service == serviceID || service == crn.Wildcard
	})
}

// PrincipalFromContext returns the principal Handler resolved for this request.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	h, ok := ctx.Value(ctxKey{}).(*holder)
	if !ok || h.err != nil {
		return Principal{}, false
	}
	return h.principal, true
}

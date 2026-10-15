package iam

import (
	"context"
	"fmt"

	"github.com/grasp-labs/ds-go-policy/engine"
)

// Guard binds an IAM action to point checks and a service-owned constraints converter.
// Configure it before use and do not modify a shared guard.
type Guard[Result any] struct {
	Action string

	// Convert must be non-nil for Constrain and enforce the allow/deny constraints,
	// including when no allow matches. Require does not use it.
	Convert func(engine.Constraints) (Result, error)
}

// Require authorizes req using the guard's action, replacing req.Action.
// It returns ErrAccessDenied for a denial and decision errors unchanged.
func (g Guard[Result]) Require(ctx context.Context, req Request) error {
	req.Action = g.Action
	decision := Decide(ctx, req)
	if decision.Err != nil {
		return decision.Err
	}
	if !decision.Allowed {
		return fmt.Errorf("%w: action %s: %s", ErrAccessDenied, g.Action, decision.Reason)
	}
	return nil
}

// Constrain resolves the action's constraints without request attributes and
// returns the converter's result and error unchanged.
func (g Guard[Result]) Constrain(ctx context.Context) (Result, error) {
	constraints, err := Constrain(ctx, g.Action, nil)
	if err != nil {
		var zero Result
		return zero, err
	}

	result, err := g.Convert(constraints)
	decision := Decision{Allowed: err == nil, Err: err}
	if err != nil {
		decision.Reason = err.Error()
	}
	observeDecision(ctx, Request{Action: g.Action}, decision)
	return result, err
}

package iam

import (
	"context"

	"github.com/grasp-labs/ds-go-policy/engine"
)

// Guard binds an IAM action to a service-owned constraints converter.
// Configure both fields before use and do not modify a shared guard.
type Guard[Result any] struct {
	Action string

	// Convert must be non-nil and enforce the allow/deny constraints, including
	// when no allow matches. Guard does not interpret the returned result.
	Convert func(engine.Constraints) (Result, error)
}

// Constrain resolves the action's constraints without request attributes and
// returns the converter's result and error unchanged.
func (g Guard[Result]) Constrain(ctx context.Context) (Result, error) {
	constraints, err := Constrain(ctx, g.Action, nil)
	if err != nil {
		var zero Result
		return zero, err
	}

	return g.Convert(constraints)
}

package iam

import "context"

type decisionObserverKey struct{}

// WithDecisionObserver observes completed point checks, failed constraints, and
// guard conversions. The observer must be safe for concurrent calls.
func WithDecisionObserver(ctx context.Context, observer func(Request, Decision)) context.Context {
	return context.WithValue(ctx, decisionObserverKey{}, observer)
}

func observeDecision(ctx context.Context, req Request, decision Decision) {
	if observer, _ := ctx.Value(decisionObserverKey{}).(func(Request, Decision)); observer != nil {
		observer(req, decision)
	}
}

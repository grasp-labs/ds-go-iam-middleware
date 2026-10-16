package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/grasp-labs/ds-go-policy/engine"
)

func TestDecisionObserver(t *testing.T) {
	converterErr := errors.New("conversion failed")
	for _, test := range []struct {
		name              string
		run               func(context.Context)
		missingMiddleware bool
		wantCalls         int
		wantAllowed       bool
		wantErr           error
	}{
		{"point grant", func(ctx context.Context) {
			Decide(ctx, Request{Action: "file:updateFile", Resource: resource(t, "projectx/app.json")})
		}, false, 1, true, nil},
		{"point denial", func(ctx context.Context) {
			Decide(ctx, Request{Action: "file:shareFile", Resource: resource(t, "projectx/app.json")})
		}, false, 1, false, nil},
		{"matched deny reason", func(ctx context.Context) {
			Decide(ctx, Request{Action: "file:updateFile", Resource: resource(t, "projectx/secrets/db.json")})
		}, false, 1, false, nil},
		{"point missing middleware", func(ctx context.Context) {
			Decide(ctx, Request{Action: "file:getFile"})
		}, true, 1, false, ErrNoMiddleware},
		{"constraints success", func(ctx context.Context) {
			_, _ = Constrain(ctx, "file:getFile", nil)
		}, false, 0, false, nil},
		{"guard missing middleware", func(ctx context.Context) {
			_, _ = (Guard[int]{Action: "file:getFile", Convert: func(engine.Constraints) (int, error) {
				t.Fatal("converter called without middleware")
				return 0, nil
			}}).Constrain(ctx)
		}, true, 1, false, ErrNoMiddleware},
		{"guard converter denial", func(ctx context.Context) {
			_, _ = (Guard[int]{Action: "file:getFile", Convert: func(engine.Constraints) (int, error) {
				return 0, ErrAccessDenied
			}}).Constrain(ctx)
		}, false, 1, false, ErrAccessDenied},
		{"guard converter error preserves result", func(ctx context.Context) {
			result, err := (Guard[int]{Action: "file:getFile", Convert: func(engine.Constraints) (int, error) {
				return 42, converterErr
			}}).Constrain(ctx)
			if result != 42 || err != converterErr {
				t.Fatalf("converter result changed: %d, %v", result, err)
			}
		}, false, 1, false, converterErr},
		{"guard success", func(ctx context.Context) {
			_, _ = (Guard[int]{Action: "file:getFile", Convert: func(engine.Constraints) (int, error) {
				return 42, nil
			}}).Constrain(ctx)
		}, false, 1, true, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			if !test.missingMiddleware {
				var err error
				ctx, err = NewTestContext(ctx, Principal{ID: "user-1", TenantID: tenantID}, fixture(t))
				if err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			var got Decision
			ctx = WithDecisionObserver(ctx, func(req Request, decision Decision) {
				calls++
				got = decision
				if req.Action == "" {
					t.Error("observer lost action")
				}
			})
			test.run(ctx)
			if calls != test.wantCalls || got.Allowed != test.wantAllowed || !errors.Is(got.Err, test.wantErr) {
				t.Fatalf("observation = (%d calls, %+v), want (%d, allowed=%t, err=%v)", calls, got, test.wantCalls, test.wantAllowed, test.wantErr)
			}
			if calls > 0 && !got.Allowed && got.Reason == "" {
				t.Error("failed decision lost its reason")
			}
			if test.name == "matched deny reason" && got.Reason != "protect-projectx-secrets" {
				t.Errorf("observer lost matching statement: %q", got.Reason)
			}
		})
	}
}

func TestGuardObservesPolicyFailureOnce(t *testing.T) {
	ctx, err := NewTestContext(t.Context(), Principal{ID: "user-1", TenantID: tenantID}, []byte(`{`))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	var observed Decision
	ctx = WithDecisionObserver(ctx, func(req Request, decision Decision) {
		calls++
		observed = decision
		if req.Action != "file:listFiles" {
			t.Errorf("observed action = %q", req.Action)
		}
	})
	_, err = (Guard[int]{Action: "file:listFiles", Convert: func(engine.Constraints) (int, error) {
		t.Fatal("converter ran after policy failure")
		return 0, nil
	}}).Constrain(ctx)
	if calls != 1 || observed.Err != err || !errors.Is(err, ErrPolicyResolution) {
		t.Fatalf("policy failure observed %d times: decision=%+v, err=%v", calls, observed, err)
	}
}

package iam

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/grasp-labs/ds-go-policy/engine"
)

func TestGuardRequire(t *testing.T) {
	ctx, err := NewTestContext(t.Context(),
		Principal{ID: "user-1", TenantID: tenantID}, fixture(t))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		action string
		req    Request
		reason string
	}{
		{"allow overrides request action", "file:getFile", Request{
			Action: "file:shareFile", Resource: resource(t, "projectx/app.json"),
			Context: map[string]string{"status": "active"},
		}, ""},
		{"deny overrides request action", "file:shareFile", Request{
			Action: "file:getFile", Resource: resource(t, "projectx/app.json"),
			Context: map[string]string{"status": "active"},
		}, "implicit deny"},
		{"condition fails", "file:getFile", Request{
			Resource: resource(t, "projectx/app.json"), Context: map[string]string{"status": "archived"},
		}, "implicit deny"},
		{"explicit deny", "file:updateFile", Request{
			Resource: resource(t, "projectx/secrets/db.json"),
		}, "protect-projectx-secrets"},
		{"outside granted prefix", "file:updateFile", Request{
			Resource: resource(t, "other/app.json"),
		}, "implicit deny"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			guard := Guard[struct{}]{Action: tc.action}
			err := guard.Require(ctx, tc.req)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("Require = %v, want nil", err)
				}
				return
			}
			want := "iam: access denied: action " + tc.action + ": " + tc.reason
			if !errors.Is(err, ErrAccessDenied) || err.Error() != want {
				t.Fatalf("Require = %v, want %q wrapping ErrAccessDenied", err, want)
			}
		})
	}

	guard := Guard[struct{}]{
		Action: "file:updateFile",
		Convert: func(engine.Constraints) (struct{}, error) {
			t.Fatal("Require called converter")
			return struct{}{}, nil
		},
	}
	if err := guard.Require(ctx, Request{Resource: resource(t, "projectx/app.json")}); err != nil {
		t.Fatalf("Require = %v, want nil", err)
	}
}

func TestGuardRequireWithoutPrincipal(t *testing.T) {
	withoutPrincipal, err := NewTestContext(t.Context(), Principal{}, fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want error
	}{
		{"missing middleware", t.Context(), ErrNoMiddleware},
		{"missing principal", withoutPrincipal, ErrNoPrincipal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			guard := Guard[struct{}]{Action: "file:getFile"}
			err := guard.Require(tc.ctx, Request{Resource: resource(t, "projectx/app.json")})
			if !errors.Is(err, tc.want) || errors.Is(err, ErrAccessDenied) {
				t.Fatalf("Require = %v, want %v without ErrAccessDenied", err, tc.want)
			}
		})
	}
}

func TestGuardConstrain(t *testing.T) {
	ctx, err := NewTestContext(t.Context(),
		Principal{ID: "user-1", TenantID: tenantID}, fixture(t))
	if err != nil {
		t.Fatal(err)
	}

	for _, action := range []string{"file:listFiles", "file:updateFile", "file:shareFile"} {
		t.Run(action, func(t *testing.T) {
			want, err := Constrain(ctx, action, nil)
			if err != nil {
				t.Fatal(err)
			}

			var received engine.Constraints
			calls := 0
			guard := Guard[string]{
				Action: action,
				Convert: func(constraints engine.Constraints) (string, error) {
					received = constraints
					calls++
					return "converted", nil
				},
			}

			got, err := guard.Constrain(ctx)
			if err != nil || got != "converted" {
				t.Fatalf("Constrain = (%q, %v), want (converted, nil)", got, err)
			}
			if calls != 1 {
				t.Fatalf("converter calls = %d, want 1", calls)
			}
			if !reflect.DeepEqual(received, want) {
				t.Fatalf("converter constraints = %+v, want %+v", received, want)
			}
		})
	}
}

func TestGuardConstrainStopsBeforeConversionOnFailure(t *testing.T) {
	withoutPrincipal, err := NewTestContext(t.Context(), Principal{}, fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	invalidPolicy, err := NewTestContext(t.Context(), Principal{ID: "user-1", TenantID: tenantID}, []byte(`{
		"principal_id": "user-1",
		"policies": [{"statements": [{
			"effect": "allow", "actions": ["file:listFiles"], "resources": ["malformed"]
		}]}]
	}`))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		ctx  context.Context
		want error
	}{
		{"missing middleware", t.Context(), ErrNoMiddleware},
		{"missing principal", withoutPrincipal, ErrNoPrincipal},
		{"invalid policy", invalidPolicy, engine.ErrInvalidPattern},
		{"token rejected", nil, ErrTokenRejected},
		{"principal rejected", nil, ErrPrincipalRejected},
		{"unavailable", nil, ErrPolicySourceUnavailable},
		{"mismatched principal", nil, ErrPolicySetMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := tc.ctx
			if ctx == nil {
				m, err := New(Config{
					Fetcher:         &flakyFetcher{fail: tc.want},
					Cache:           NewMapCache(),
					CacheLifeWindow: DefaultCacheMaxStale,
					Principal: func(context.Context) (Principal, error) {
						return Principal{ID: "user-1", TenantID: tenantID}, nil
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				ctx = m.newContext(t.Context(), "")
			}
			guard := Guard[int]{
				Action: "file:listFiles",
				Convert: func(engine.Constraints) (int, error) {
					t.Fatal("converter called after policy resolution failed")
					return 42, nil
				},
			}

			got, err := guard.Constrain(ctx)
			if got != 0 || !errors.Is(err, tc.want) {
				t.Fatalf("Constrain = (%d, %v), want (0, %v)", got, err, tc.want)
			}
			wantResolution := !errors.Is(tc.want, ErrNoMiddleware) && !errors.Is(tc.want, ErrNoPrincipal)
			if errors.Is(err, ErrPolicyResolution) != wantResolution {
				t.Fatalf("Constrain error = %v, want policy resolution marker %v", err, wantResolution)
			}
		})
	}
}

func TestGuardConstrainPreservesConverterResultOnError(t *testing.T) {
	ctx, err := NewTestContext(t.Context(),
		Principal{ID: "user-1", TenantID: tenantID}, fixture(t))
	if err != nil {
		t.Fatal(err)
	}

	cause := errors.New("unsupported create constraint")
	wantErr := errors.Join(ErrPolicyNotEnforceable, cause)
	guard := Guard[int]{
		Action: "file:listFiles",
		Convert: func(engine.Constraints) (int, error) {
			return 42, wantErr
		},
	}

	got, err := guard.Constrain(ctx)
	if got != 42 || !errors.Is(err, wantErr) {
		t.Fatalf("Constrain = (%d, %v), want (42, %v)", got, err, wantErr)
	}
	if !errors.Is(err, ErrPolicyNotEnforceable) || !errors.Is(err, cause) {
		t.Fatalf("converter error lost its classification or cause: %v", err)
	}
	if errors.Is(err, ErrAccessDenied) || errors.Is(err, ErrPolicyResolution) {
		t.Fatalf("unenforceable policy marked as access denied or resolution failure: %v", err)
	}
}

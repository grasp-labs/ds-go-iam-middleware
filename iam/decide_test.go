package iam

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/grasp-labs/ds-go-policy/crn"
	"github.com/grasp-labs/ds-go-policy/engine"
)

// Must match the tenant in testdata/file-access.json.
const (
	tenantID = "11111111-1111-4111-8111-111111111111"
	ownerID  = "22222222-2222-4222-8222-222222222222"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/file-access.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func resource(t *testing.T, path string) crn.CRN {
	t.Helper()
	c, err := crn.Build(tenantID, ownerID, "file", "", "file", path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDecide(t *testing.T) {
	ctx, err := NewTestContext(context.Background(),
		Principal{ID: "user-1", TenantID: tenantID}, fixture(t))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		action  string
		path    string
		attrs   map[string]string
		allowed bool
	}{
		{"allow", "file:getFile", "projectx/app.json", map[string]string{"status": "active"}, true},
		{"condition fails", "file:getFile", "projectx/app.json", map[string]string{"status": "archived"}, false},
		{"explicit deny wins", "file:updateFile", "projectx/secrets/db.json", nil, false},
		{"action not granted", "file:shareFile", "projectx/app.json", map[string]string{"status": "active"}, false},
		{"outside granted prefix", "file:updateFile", "other/app.json", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := Decide(ctx, Request{Action: tc.action, Resource: resource(t, tc.path), Context: tc.attrs})
			if d.Err != nil {
				t.Fatalf("Err = %v", d.Err)
			}
			if d.Allowed != tc.allowed {
				t.Fatalf("Allowed = %v, want %v (reason: %s)", d.Allowed, tc.allowed, d.Reason)
			}
		})
	}
}

// Decide must pass the principal's tenant to the engine, as Constrain does:
// the tenant resolves the platform token and confines every pattern to the
// caller. A platform-issued document written with the token has to answer for
// whoever holds it, and must not reach another tenant's resources.
func TestDecideResolvesTheTenantToken(t *testing.T) {
	const other = "33333333-3333-4333-8333-333333333333"

	set := []byte(`{
		"principal_id": "user-1",
		"policies": [{
			"id": "6f0c1d2e-5a7b-4c8d-9e0f-1a2b3c4d5e6f",
			"name": "platform-issued",
			"version": "1.0.0",
			"statements": [{
				"sid": "read-own-files",
				"effect": "allow",
				"actions": ["file:getFile"],
				"resources": ["crn:aic:*:file::file:**"]
			}]
		}]
	}`)

	ctx, err := NewTestContext(context.Background(),
		Principal{ID: "user-1", TenantID: tenantID}, set)
	if err != nil {
		t.Fatal(err)
	}

	if d := Decide(ctx, Request{Action: "file:getFile", Resource: resource(t, "reports/q1.csv")}); !d.Allowed {
		t.Errorf("own resource = denied (%s), want allowed: the token must resolve to the caller", d.Reason)
	}

	foreign, err := crn.Build(other, ownerID, "file", "", "file", "reports/q1.csv")
	if err != nil {
		t.Fatal(err)
	}
	if d := Decide(ctx, Request{Action: "file:getFile", Resource: foreign}); d.Allowed {
		t.Error("another tenant's resource = allowed, want denied: the token is not a wildcard")
	}
}

// A published row is reachable on an allow for the action alone: publication is
// the grant, so no pattern names the row. Without this a point read would refuse
// a row the equivalent list returns.
func TestDecidePublishedResourceNeedsNoPattern(t *testing.T) {
	const platformTenant = "44444444-4444-4444-8444-444444444444"

	set := []byte(`{
		"principal_id": "user-1",
		"policies": [{
			"id": "7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
			"name": "own-files-only",
			"version": "1.0.0",
			"statements": [{
				"sid": "read-own-files",
				"effect": "allow",
				"actions": ["file:getFile"],
				"resources": ["crn:aic:*:file::file:**"]
			}]
		}]
	}`)

	ctx, err := NewTestContext(context.Background(),
		Principal{ID: "user-1", TenantID: tenantID}, set)
	if err != nil {
		t.Fatal(err)
	}

	published, err := crn.Build(platformTenant, ownerID, "file", "", "file", "catalog/shared.csv")
	if err != nil {
		t.Fatal(err)
	}

	if d := Decide(ctx, Request{Action: "file:getFile", Resource: published}); d.Allowed {
		t.Error("unmarked platform row = allowed, want denied: no pattern reaches it")
	}
	if d := Decide(ctx, Request{Action: "file:getFile", Resource: published, ResourcePublished: true}); !d.Allowed {
		t.Errorf("published platform row = denied (%s), want allowed: publication is the grant", d.Reason)
	}
	if d := Decide(ctx, Request{Action: "file:deleteFile", Resource: published, ResourcePublished: true}); d.Allowed {
		t.Error("published row, ungranted action = allowed, want denied: publication is no action grant")
	}
}

// The fixture allows file:listFiles over the whole tree where status is
// "active" and denies everything under projectx/secrets/. Constraining for
// listFiles must keep exactly those two, with the row-level status condition
// still attached to the allow pattern for the adapter.
func TestConstrain(t *testing.T) {
	ctx, err := NewTestContext(context.Background(),
		Principal{ID: "user-1", TenantID: tenantID}, fixture(t))
	if err != nil {
		t.Fatal(err)
	}

	cons, err := Constrain(ctx, "file:listFiles", nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(cons.Allow) != 1 {
		t.Fatalf("Allow = %d matches, want 1: %+v", len(cons.Allow), cons.Allow)
	}
	if len(cons.Deny) != 1 {
		t.Fatalf("Deny = %d matches, want 1: %+v", len(cons.Deny), cons.Deny)
	}
	if _, ok := cons.Allow[0].Conditions["StringEquals"]["status"]; !ok {
		t.Errorf("allow match lost its row-level status condition: %+v", cons.Allow[0].Conditions)
	}
	if got := cons.Allow[0].Pattern.Tenant(); got != tenantID {
		t.Errorf("allow pattern tenant = %q, want %q", got, tenantID)
	}

	// An action no statement grants constrains to nothing visible.
	cons, err = Constrain(ctx, "file:shareFile", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cons.Allow) != 0 {
		t.Errorf("ungranted action Allow = %d matches, want 0", len(cons.Allow))
	}
}

func constraintServices(matches []engine.ResourceMatch) []string {
	services := make([]string, 0, len(matches))
	for _, match := range matches {
		services = append(services, match.Pattern.Service())
	}
	return services
}

func TestConstrainFiltersResourcesByService(t *testing.T) {
	policyJSON := fmt.Appendf(nil, `{
		"principal_id": "user-1",
		"policies": [{
			"id": "service-resources",
			"version": "1.0.0",
			"statements": [
				{
					"sid": "allow-services",
					"effect": "allow",
					"actions": ["*"],
					"resources": [
						"crn:%[1]s:*:file::file:**",
						"crn:%[1]s:*:*::file:**",
						"crn:%[1]s:*:state::file:**"
					]
				},
				{
					"sid": "deny-services",
					"effect": "deny",
					"actions": ["*"],
					"resources": [
						"crn:%[1]s:*:file::file:private/**",
						"crn:%[1]s:*:*::file:shared/**",
						"crn:%[1]s:*:state::file:archived/**"
					]
				}
			]
		}]
	}`, tenantID)

	tests := []struct {
		name      string
		serviceID string
		wantAllow []string
		wantDeny  []string
	}{
		{
			name:      "configured",
			serviceID: "file",
			wantAllow: []string{"file", crn.Wildcard},
			wantDeny:  []string{"file", crn.Wildcard},
		},
		{
			name:      "disabled",
			wantAllow: []string{"file", crn.Wildcard, "state"},
			wantDeny:  []string{"file", crn.Wildcard, "state"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, err := NewTestContextWithServiceID(
				context.Background(),
				Principal{ID: "user-1", TenantID: tenantID},
				policyJSON,
				test.serviceID,
			)
			if err != nil {
				t.Fatal(err)
			}

			constraints, err := Constrain(ctx, "file:listFiles", nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := constraintServices(constraints.Allow); !slices.Equal(got, test.wantAllow) {
				t.Errorf("allow services = %v, want %v", got, test.wantAllow)
			}
			if got := constraintServices(constraints.Deny); !slices.Equal(got, test.wantDeny) {
				t.Errorf("deny services = %v, want %v", got, test.wantDeny)
			}
		})
	}
}

func TestConstrainWithoutPrincipal(t *testing.T) {
	ctx, err := NewTestContext(context.Background(), Principal{}, fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Constrain(ctx, "file:listFiles", nil); !errors.Is(err, ErrNoPrincipal) {
		t.Fatalf("err = %v, want ErrNoPrincipal", err)
	}
}

func TestConstrainWithoutMiddleware(t *testing.T) {
	if _, err := Constrain(context.Background(), "file:listFiles", nil); !errors.Is(err, ErrNoMiddleware) {
		t.Fatalf("err = %v, want ErrNoMiddleware", err)
	}
}

func TestDecideWithoutPrincipal(t *testing.T) {
	ctx, err := NewTestContext(context.Background(), Principal{}, fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	d := Decide(ctx, Request{Action: "file:getFile", Resource: resource(t, "projectx/app.json")})
	if d.Allowed || !errors.Is(d.Err, ErrNoPrincipal) {
		t.Fatalf("got %+v, want denied with ErrNoPrincipal", d)
	}
}

// A principal without a tenant is refused: the tenant scopes the cache key,
// so accepting an empty one would let two tenants' entries collide.
func TestDecideWithoutTenant(t *testing.T) {
	ctx, err := NewTestContext(context.Background(), Principal{ID: "user-1"}, fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	d := Decide(ctx, Request{Action: "file:getFile", Resource: resource(t, "projectx/app.json")})
	if d.Allowed || !errors.Is(d.Err, ErrNoPrincipal) {
		t.Fatalf("got %+v, want denied with ErrNoPrincipal", d)
	}
}

func TestDecideWithoutMiddleware(t *testing.T) {
	d := Decide(context.Background(), Request{Action: "file:getFile", Resource: resource(t, "projectx/app.json")})
	if d.Allowed || !errors.Is(d.Err, ErrNoMiddleware) {
		t.Fatalf("got %+v, want denied with ErrNoMiddleware", d)
	}
}

type countingFetcher struct {
	raw   []byte
	calls int
}

func (f *countingFetcher) FetchPolicies(context.Context, string, string, string, string) (FetchResult, error) {
	f.calls++
	return FetchResult{Raw: f.raw, ETag: `"v1"`}, nil
}

// Within the TTL nothing is fetched, and the compiled set is reused rather than
// recompiled — the latter is the point of the second cache layer.
func TestLoadCaches(t *testing.T) {
	f := &countingFetcher{raw: fixture(t)}
	now := time.Now().UTC()

	m, err := New(Config{
		Fetcher:         f,
		Cache:           NewMapCache(),
		CacheLifeWindow: DefaultCacheMaxStale,
		Principal:       func(context.Context) (Principal, error) { return Principal{ID: "user-1", TenantID: tenantID}, nil },
		TTL:             time.Minute,
		Logger:          slog.New(slog.DiscardHandler),
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	first, err := m.load(context.Background(), tenantID, "user-1", "Bearer t")
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.load(context.Background(), tenantID, "user-1", "Bearer t")
	if err != nil {
		t.Fatal(err)
	}

	if f.calls != 1 {
		t.Errorf("fetches = %d, want 1", f.calls)
	}
	if first != second {
		t.Error("compiled set was rebuilt for unchanged bytes")
	}

	now = now.Add(2 * time.Minute)
	if _, err := m.load(context.Background(), tenantID, "user-1", "Bearer t"); err != nil {
		t.Fatal(err)
	}
	if f.calls != 2 {
		t.Errorf("fetches after TTL = %d, want 2", f.calls)
	}
}

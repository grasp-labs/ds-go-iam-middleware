package iam

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/grasp-labs/ds-go-policy/engine"
	"github.com/grasp-labs/ds-go-policy/policy"
)

// flakyFetcher succeeds until fail is set, then returns it.
type flakyFetcher struct {
	mu    sync.Mutex
	raw   []byte
	fail  error
	calls int
}

func (f *flakyFetcher) FetchPolicies(context.Context, string, string, string, string) (FetchResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.fail != nil {
		return FetchResult{}, f.fail
	}
	return FetchResult{Raw: f.raw, ETag: `"v1"`}, nil
}

func (f *flakyFetcher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func newStaleTestMiddleware(t *testing.T, f *flakyFetcher, now *time.Time) *Middleware {
	t.Helper()
	m, err := New(Config{
		Fetcher:         f,
		Cache:           NewMapCache(),
		CacheLifeWindow: 10 * time.Minute,
		Principal:       func(context.Context) (Principal, error) { return Principal{ID: "user-1", TenantID: tenantID}, nil },
		TTL:             time.Minute,
		MaxStale:        10 * time.Minute,
		Logger:          slog.New(slog.DiscardHandler),
		Now:             func() time.Time { return *now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// An unreachable policy source serves the cached set until it is MaxStale old,
// with a cooldown between retries, and answers unavailable past the bound.
func TestLoadServesStaleDuringOutage(t *testing.T) {
	f := &flakyFetcher{raw: fixture(t)}
	now := time.Now().UTC()
	m := newStaleTestMiddleware(t, f, &now)
	ctx := context.Background()

	fresh, err := m.load(ctx, tenantID, "user-1", "Bearer t")
	if err != nil {
		t.Fatal(err)
	}

	// The source goes down; past the TTL the entry is served stale.
	f.fail = fmt.Errorf("%w: connection refused", ErrPolicySourceUnavailable)
	now = now.Add(2 * time.Minute)
	stale, err := m.load(ctx, tenantID, "user-1", "Bearer t")
	if err != nil {
		t.Fatalf("within MaxStale, want stale set, got error: %v", err)
	}
	if stale != fresh {
		t.Error("stale serve rebuilt the compiled set")
	}
	if f.count() != 2 {
		t.Fatalf("fetches = %d, want 2 (one success, one failed revalidation)", f.count())
	}

	// Within the cooldown no fetch is retried.
	if _, err := m.load(ctx, tenantID, "user-1", "Bearer t"); err != nil {
		t.Fatal(err)
	}
	if f.count() != 2 {
		t.Errorf("fetches within cooldown = %d, want 2", f.count())
	}

	// Past the cooldown the source is retried, fails again, still serves stale.
	now = now.Add(revalidateCooldown + time.Second)
	if _, err := m.load(ctx, tenantID, "user-1", "Bearer t"); err != nil {
		t.Fatal(err)
	}
	if f.count() != 3 {
		t.Errorf("fetches after cooldown = %d, want 3", f.count())
	}

	// Past MaxStale the outage surfaces instead of the stale set.
	now = now.Add(10 * time.Minute)
	if _, err := m.load(ctx, tenantID, "user-1", "Bearer t"); !errors.Is(err, ErrPolicySourceUnavailable) {
		t.Fatalf("past MaxStale, want ErrPolicySourceUnavailable, got %v", err)
	}
}

// Recovery: a successful revalidation resets the clock and the failure state.
func TestLoadRecoversAfterOutage(t *testing.T) {
	f := &flakyFetcher{raw: fixture(t)}
	now := time.Now().UTC()
	m := newStaleTestMiddleware(t, f, &now)
	ctx := context.Background()

	if _, err := m.load(ctx, tenantID, "user-1", "Bearer t"); err != nil {
		t.Fatal(err)
	}

	f.fail = fmt.Errorf("%w: connection refused", ErrPolicySourceUnavailable)
	now = now.Add(2 * time.Minute)
	if _, err := m.load(ctx, tenantID, "user-1", "Bearer t"); err != nil {
		t.Fatal(err)
	}

	f.fail = nil
	now = now.Add(revalidateCooldown + time.Second)
	if _, err := m.load(ctx, tenantID, "user-1", "Bearer t"); err != nil {
		t.Fatal(err)
	}

	// Fresh again: within the TTL of the recovery fetch, nothing is fetched.
	before := f.count()
	now = now.Add(30 * time.Second)
	if _, err := m.load(ctx, tenantID, "user-1", "Bearer t"); err != nil {
		t.Fatal(err)
	}
	if f.count() != before {
		t.Errorf("fetches after recovery = %d, want %d (fresh entry)", f.count(), before)
	}
}

// A 401 is an answer about the caller, not an outage: never served over stale.
func TestLoadDoesNotServeStaleOnRejectedToken(t *testing.T) {
	f := &flakyFetcher{raw: fixture(t)}
	now := time.Now().UTC()
	m := newStaleTestMiddleware(t, f, &now)
	ctx := context.Background()

	if _, err := m.load(ctx, tenantID, "user-1", "Bearer t"); err != nil {
		t.Fatal(err)
	}

	f.fail = ErrTokenRejected
	now = now.Add(2 * time.Minute)
	if _, err := m.load(ctx, tenantID, "user-1", "Bearer t"); !errors.Is(err, ErrTokenRejected) {
		t.Fatalf("want ErrTokenRejected surfaced, got %v", err)
	}
}

// etagFetcher answers the first call with a body and validator, and every
// revalidation that offers the validator with a bare 304.
type etagFetcher struct {
	raw   []byte
	calls int
}

func (f *etagFetcher) FetchPolicies(_ context.Context, _, _, _, etag string) (FetchResult, error) {
	f.calls++
	if etag == `"v1"` {
		return FetchResult{NotModified: true, ETag: etag}, nil
	}
	return FetchResult{Raw: f.raw, ETag: `"v1"`}, nil
}

// A 304 resets the entry's clock and reuses the compiled set: no body, no
// recompile, and the next requests inside the TTL fetch nothing at all.
func TestLoadRevalidatesWith304(t *testing.T) {
	f := &etagFetcher{raw: fixture(t)}
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
	ctx := context.Background()

	first, err := m.load(ctx, tenantID, "user-1", "Bearer t")
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(2 * time.Minute)
	revalidated, err := m.load(ctx, tenantID, "user-1", "Bearer t")
	if err != nil {
		t.Fatal(err)
	}
	if revalidated != first {
		t.Error("304 rebuilt the compiled set")
	}
	if f.calls != 2 {
		t.Fatalf("fetches = %d, want 2", f.calls)
	}

	// The 304 reset the clock: within the new TTL nothing is fetched.
	now = now.Add(30 * time.Second)
	if _, err := m.load(ctx, tenantID, "user-1", "Bearer t"); err != nil {
		t.Fatal(err)
	}
	if f.calls != 2 {
		t.Errorf("fetches within reset TTL = %d, want 2", f.calls)
	}
}

// A set naming another principal is refused rather than compiled.
func TestLoadRefusesMismatchedPrincipal(t *testing.T) {
	ctx, err := NewTestContext(context.Background(),
		Principal{ID: "user-1", TenantID: tenantID},
		[]byte(`{"principal_id":"someone-else","policies":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	d := Decide(ctx, Request{Action: "file:getFile", Resource: resource(t, "projectx/app.json")})
	if d.Allowed || !errors.Is(d.Err, ErrPolicySetMismatch) {
		t.Fatalf("got %+v, want denied with ErrPolicySetMismatch", d)
	}
}

// Evict drops the entry: the next load fetches even though the TTL had not
// expired, so a synchronous eviction after a write means zero revocation lag.
func TestEvict(t *testing.T) {
	f := &flakyFetcher{raw: fixture(t)}
	now := time.Now().UTC()
	m := newStaleTestMiddleware(t, f, &now)
	ctx := context.Background()

	if _, err := m.load(ctx, tenantID, "user-1", "Bearer t"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.load(ctx, tenantID, "user-1", "Bearer t"); err != nil {
		t.Fatal(err)
	}
	if f.count() != 1 {
		t.Fatalf("fetches before evict = %d, want 1 (second load is a cache hit)", f.count())
	}

	if err := m.Evict(tenantID, "user-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.load(ctx, tenantID, "user-1", "Bearer t"); err != nil {
		t.Fatal(err)
	}
	if f.count() != 2 {
		t.Errorf("fetches after evict = %d, want 2 (entry was dropped)", f.count())
	}
}

// filterByService keeps a statement's actions scoped to the service
// ("file:getFile", "file:*") or unscoped ("*"), strips other services' actions,
// and drops statements — then policies — left empty.
func TestFilterByService(t *testing.T) {
	in := []policy.Policy{
		{
			ID: "p1",
			Statements: []policy.Statement{
				{Sid: "mixed", Effect: policy.Allow, Actions: []string{"file:getFile", "file:*", "state:getJobs"}, Resources: []string{"r"}},
				{Sid: "other-only", Effect: policy.Allow, Actions: []string{"state:getJobs", "state:listJobs"}, Resources: []string{"r"}},
				{Sid: "wildcard-deny", Effect: policy.Deny, Actions: []string{"*"}, Resources: []string{"r"}},
			},
		},
		{
			ID:         "p2", // state-only: drops entirely
			Statements: []policy.Statement{{Sid: "state", Effect: policy.Allow, Actions: []string{"state:*"}, Resources: []string{"r"}}},
		},
	}

	out := filterByService(in, "file")

	if len(out) != 1 || out[0].ID != "p1" {
		t.Fatalf("policies = %+v, want only p1", out)
	}
	stmts := out[0].Statements
	if len(stmts) != 2 {
		t.Fatalf("statements = %d, want 2 (mixed, wildcard-deny): %+v", len(stmts), stmts)
	}
	if got, want := stmts[0].Actions, []string{"file:getFile", "file:*"}; !slices.Equal(got, want) {
		t.Errorf("mixed actions = %v, want %v (scoped literal + wildcard kept, other stripped)", got, want)
	}
	if got, want := stmts[1].Actions, []string{"*"}; !slices.Equal(got, want) {
		t.Errorf("wildcard deny actions = %v, want the unscoped * kept", got)
	}
}

// With Config.ServiceID set, the compiled set carries only this service's
// statements: a same-service allow decides, a surviving unscoped "*" deny still
// applies, and another service's policy is gone without disturbing either.
func TestLoadFiltersByService(t *testing.T) {
	body := []byte(fmt.Sprintf(`{
		"principal_id": "user-1",
		"policies": [
			{"id":"p1","version":"1.0.0","statements":[
				{"sid":"allow-file","effect":"allow","actions":["file:getFile","state:getJobs"],"resources":["crn:%[1]s:*:file::file:**"]},
				{"sid":"deny-secrets","effect":"deny","actions":["*"],"resources":["crn:%[1]s:*:file::file:projectx/secrets/**"]}
			]},
			{"id":"p2","version":"1.0.0","statements":[
				{"sid":"state-only","effect":"allow","actions":["state:listJobs"],"resources":["crn:%[1]s:*:state::state:**"]}
			]}
		]
	}`, tenantID))

	m, err := New(Config{
		Fetcher:         StaticFetcher(body),
		Cache:           NewMapCache(),
		CacheLifeWindow: DefaultCacheMaxStale,
		Principal:       func(context.Context) (Principal, error) { return Principal{ID: "user-1", TenantID: tenantID}, nil },
		ServiceID:       "file",
		Logger:          slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}

	set, err := m.load(context.Background(), tenantID, "user-1", "")
	if err != nil {
		t.Fatal(err)
	}

	if d := set.Decide(engine.Request{Action: "file:getFile", Resource: resource(t, "projectx/app.json")}); !d.Allowed {
		t.Errorf("file:getFile = denied (%s), want allowed: the scoped action survived filtering", d.Reason)
	}
	if d := set.Decide(engine.Request{Action: "file:getFile", Resource: resource(t, "projectx/secrets/db.json")}); d.Allowed {
		t.Error("file:getFile on secrets = allowed, want denied: the unscoped * deny must survive filtering")
	}
}

func TestNewValidatesConfig(t *testing.T) {
	base := func() Config {
		return Config{
			Fetcher:         StaticFetcher(nil),
			Cache:           NewMapCache(),
			CacheLifeWindow: time.Hour,
			Principal:       func(context.Context) (Principal, error) { return Principal{}, nil },
			TTL:             time.Minute,
			MaxStale:        10 * time.Minute,
		}
	}

	if _, err := New(base()); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}

	cfg := base()
	cfg.MaxStale = time.Second
	if _, err := New(cfg); err == nil {
		t.Error("want error for MaxStale < TTL")
	}

	cfg = base()
	cfg.CacheLifeWindow = 0
	if _, err := New(cfg); err == nil {
		t.Error("want error for missing CacheLifeWindow")
	}

	// The API's default cache life window (10m) is shorter than the default
	// MaxStale (30m): wiring must surface that conflict, not swallow it.
	cfg = base()
	cfg.MaxStale = 0 // defaults to 30m
	cfg.CacheLifeWindow = 10 * time.Minute
	if _, err := New(cfg); err == nil {
		t.Error("want error for CacheLifeWindow < MaxStale")
	}
}

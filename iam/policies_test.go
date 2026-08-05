package iam

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// flakyFetcher succeeds until fail is set, then returns it.
type flakyFetcher struct {
	mu    sync.Mutex
	raw   []byte
	fail  error
	calls int
}

func (f *flakyFetcher) FetchPolicies(context.Context, string, string, string) (FetchResult, error) {
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

func (f *etagFetcher) FetchPolicies(_ context.Context, _, _, etag string) (FetchResult, error) {
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

// Helpers for testing handlers that call Decide.
//
// These ship in the package rather than in a _test.go file because consumers
// need them: a service testing its own handlers has neither an Echo server nor
// a live IAM service to run the real path against.

package iam

import (
	"context"
	"errors"
	"log/slog"
	"sync"
)

// NewTestContext returns a context that behaves as though Handler had run, so
// handlers can be tested without an Echo server or a live IAM service. Pass a
// zero Principal to exercise the unauthenticated path.
//
// policySetJSON is the response body the IAM API would return for this
// principal — an EffectivePolicySet, so `{"principal_id": …, "policies": […]}`
// and not a bare array of documents. Its principal_id must equal p.ID: the
// middleware refuses a set belonging to someone else, and this helper does not
// paper over that.
func NewTestContext(ctx context.Context, p Principal, policySetJSON []byte) (context.Context, error) {
	m, err := New(Config{
		Fetcher: StaticFetcher(policySetJSON),
		Cache:   NewMapCache(),
		// The map cache never evicts, so any value at least MaxStale is true.
		CacheLifeWindow: DefaultCacheMaxStale,
		Principal:       func(context.Context) (Principal, error) { return p, nil },
		Logger:          slog.New(slog.DiscardHandler),
	})
	if err != nil {
		return nil, err
	}
	return m.newContext(ctx, ""), nil
}

// StaticFetcher answers every fetch with the same response body, ignoring the
// tenant, the principal, the authorization, and any ETag offered.
type StaticFetcher []byte

func (f StaticFetcher) FetchPolicies(context.Context, string, string, string, string) (FetchResult, error) {
	return FetchResult{Raw: f}, nil
}

// NewMapCache returns an unbounded in-memory Cache for tests.
func NewMapCache() Cache { return &mapCache{m: map[string][]byte{}} }

var errCacheMiss = errors.New("iam: cache miss")

type mapCache struct {
	mu sync.RWMutex
	m  map[string][]byte
}

func (c *mapCache) Get(key string) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.m[key]
	if !ok {
		return nil, errCacheMiss
	}
	return v, nil
}

func (c *mapCache) Set(key string, entry []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = entry
	return nil
}

func (c *mapCache) Delete(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
	return nil
}

// Package iam authorizes Echo requests against policies held by the IAM
// service.
//
// Policy semantics live in github.com/grasp-labs/ds-go-policy. This package
// resolves the principal, fetches and caches their policies, and exposes the
// decision to handlers through context.Context.
//
//	authz, err := iam.New(iam.Config{
//	    Fetcher:         &iam.HTTPFetcher{BaseURL: cfg.IAMURL},
//	    Cache:           app.Cache,
//	    CacheLifeWindow: cacheLifeWindow, // what app.Cache was built with
//	    Principal:       auth.IAMPrincipal,
//	})
//	e.Use(authz.Handler())
//
// The caller's Authorization header is forwarded verbatim when their policies
// are fetched, so the IAM API's own access control applies and this package
// holds no credentials.
package iam

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/sync/singleflight"
)

var DefaultCacheTTL = 60 * time.Second
var DefaultCacheMaxStale = 30 * time.Minute
var DefaultFetchTimeout = 3 * time.Second

// Principal is the authenticated caller, as established by the authentication
// middleware that ran earlier. This package never validates credentials.
type Principal struct {
	ID       string
	TenantID string
}

type Config struct {
	// Fetcher retrieves policy documents. Required.
	Fetcher PolicyFetcher

	// Cache holds raw policy documents. Required.
	Cache Cache

	// CacheLifeWindow declares how long Cache retains an entry — for bigcache,
	// the LifeWindow it was built with. Required, and it must be at least
	// MaxStale: stale serving reads entries up to MaxStale old, and a cache
	// that evicts sooner would silently shorten outage tolerance to its own
	// window. For a cache with no age-based eviction, pass MaxStale.
	CacheLifeWindow time.Duration

	// Principal reads the principal from the request context. Required.
	Principal func(context.Context) (Principal, error)

	// ServiceID, when set, limits policies to the service using this middleware.
	// Before compilation, each statement keeps only actions for this service
	// ("file:getFile", "file:*") or the wildcard action ("*"). Statements and
	// policies with no remaining actions are dropped.
	//
	// Constrain applies the same boundary to resources. It keeps allow and deny
	// patterns for this service or the wildcard service and removes patterns for
	// other services before they reach a query adapter. Empty (the default)
	// leaves the policy set unchanged.
	ServiceID string

	// TTL is how long policies are served from Cache before revalidation, and
	// therefore the revocation lag. Default 60s.
	TTL time.Duration

	// MaxStale is the hard bound for serving a cached set while the policy
	// source is unreachable: a failed revalidation serves the cached set until
	// it is MaxStale old, and past that the middleware answers unavailable
	// rather than stale. It trades revocation lag for availability during an
	// outage, and only for principals who already held a set. Default 30m.
	MaxStale time.Duration

	// Timeout bounds one call to the IAM service. Default 3s.
	Timeout time.Duration

	// Logger defaults to slog.Default().
	Logger *slog.Logger

	// Now is injectable for tests. Defaults to time.Now in UTC; a replacement
	// should also return UTC, since the timestamp it produces is serialized
	// into the cache entry.
	Now func() time.Time
}

// Middleware is built once in server.go and shared. Use it as a pointer.
type Middleware struct {
	cfg      Config
	compiled *compiledCache

	// group collapses concurrent cold lookups for the same principal into one
	// IAM request.
	group singleflight.Group
}

func New(cfg Config) (*Middleware, error) {
	switch {
	case cfg.Fetcher == nil:
		return nil, errors.New("iam: Config.Fetcher is required")
	case cfg.Cache == nil:
		return nil, errors.New("iam: Config.Cache is required")
	case cfg.Principal == nil:
		return nil, errors.New("iam: Config.Principal is required")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultCacheTTL
	}
	if cfg.MaxStale <= 0 {
		cfg.MaxStale = DefaultCacheMaxStale
	}
	if cfg.MaxStale < cfg.TTL {
		return nil, errors.New("iam: Config.MaxStale must be at least Config.TTL")
	}
	if cfg.CacheLifeWindow <= 0 {
		return nil, errors.New("iam: Config.CacheLifeWindow is required: declare how long Cache retains entries (for bigcache, its LifeWindow)")
	}
	if cfg.CacheLifeWindow < cfg.MaxStale {
		return nil, fmt.Errorf(
			"iam: Config.CacheLifeWindow (%s) must be at least Config.MaxStale (%s): the cache would evict entries stale serving still needs — raise the cache's life window or lower MaxStale",
			cfg.CacheLifeWindow, cfg.MaxStale)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultFetchTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Middleware{cfg: cfg, compiled: newCompiledCache()}, nil
}

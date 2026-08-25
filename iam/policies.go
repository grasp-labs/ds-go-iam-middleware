package iam

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/grasp-labs/ds-go-policy/engine"
	"github.com/grasp-labs/ds-go-policy/policy"
)

const cachePrefix = "iam:pol:v1:"
const compiledCacheMax = 256

func cacheKey(tenantID, principalID string) string {
	return cachePrefix + tenantID + ":" + principalID
}

// revalidateCooldown is how long a stale entry is served without retrying the
// policy source after a failed revalidation. During an outage, one principal
// costs one fetch round trip per cooldown instead of one per request.
const revalidateCooldown = 5 * time.Second

type cacheEntry struct {
	FetchedAt time.Time `json:"t"`
	ETag      string    `json:"e,omitempty"`

	// FailedAt is when a revalidation of this entry last failed; the zero
	// value means the last fetch succeeded. It starts the cooldown above.
	FailedAt time.Time `json:"f,omitzero"`

	// Hash keys the compiled set. It is taken once, when the bytes arrive,
	// because Raw does not survive the cache round trip byte for byte —
	// encoding/json compacts a RawMessage on the way out — so hashing it again
	// later would not agree with itself. Doing it here also keeps the hash off
	// the per-request path.
	Hash string          `json:"h,omitempty"`
	Raw  json.RawMessage `json:"p,omitempty"`
}

type PolicySet struct {
	PrincipalID string          `json:"principal_id"`
	Policies    []policy.Policy `json:"policies"`
}

func (m *Middleware) load(ctx context.Context, tenantID, principalID, authorization string) (*engine.Compiled, error) {
	key := cacheKey(tenantID, principalID)
	prev, cached := m.read(key)
	now := m.cfg.Now()
	if cached && now.Sub(prev.FetchedAt) < m.cfg.TTL {
		return m.compile(prev, principalID)
	}

	// A revalidation failed a moment ago; within the cooldown the entry is
	// served as it stands rather than paying another fetch round trip.
	if cached && now.Sub(prev.FetchedAt) < m.cfg.MaxStale && now.Sub(prev.FailedAt) < revalidateCooldown {
		return m.compile(prev, principalID)
	}

	// Concurrent misses for one principal share a single fetch, made with the
	// first caller's credential. Same principal, same scope, so any of the
	// waiting requests' tokens would have produced the same set.
	entry, err, _ := m.group.Do(key, func() (any, error) {
		return m.fetch(ctx, key, tenantID, principalID, authorization, prev)
	})
	if err == nil {
		return m.compile(entry.(cacheEntry), principalID)
	}

	// An unreachable policy source degrades availability before correctness:
	// a set fetched less than MaxStale ago still answers, and the request
	// that finds it older than that gets the outage, not a denial. Only
	// outages qualify — a 401 or 422 is an answer about this caller and must
	// surface no matter what is cached.
	if cached && errors.Is(err, ErrPolicySourceUnavailable) && now.Sub(prev.FetchedAt) < m.cfg.MaxStale {
		m.cfg.Logger.Warn("iam: serving stale policy set",
			"principal_id", principalID, "age", now.Sub(prev.FetchedAt).String(), "error", err)
		prev.FailedAt = now
		m.write(key, prev)
		return m.compile(prev, principalID)
	}
	return nil, err
}

// Evict drops the cached policy set for one principal, so the next request
// resolves it afresh. ds-iam calls this synchronously on its own writes for
// zero revocation lag; an event consumer would call the same method. The
// compiled memo needs no eviction — it is content-addressed, and a changed
// set simply hashes anew.
func (m *Middleware) Evict(tenantID, principalID string) error {
	return m.cfg.Cache.Delete(cacheKey(tenantID, principalID))
}

func (m *Middleware) fetch(ctx context.Context, key, tenantID, principalID, authorization string, prev cacheEntry) (cacheEntry, error) {
	// Detached from the request: other requests may be waiting on this fetch,
	// so one client disconnecting must not cancel it.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), m.cfg.Timeout)
	defer cancel() //nolint:errcheck

	res, err := m.cfg.Fetcher.FetchPolicies(ctx, tenantID, principalID, authorization, prev.ETag)
	if err != nil {
		return cacheEntry{}, fmt.Errorf("iam: fetching policies for %s: %w", principalID, err)
	}

	entry := cacheEntry{
		FetchedAt: m.cfg.Now(), ETag: res.ETag, Raw: res.Raw, Hash: contentKey(res.Raw),
	}
	if res.NotModified {
		entry.Raw, entry.Hash = prev.Raw, prev.Hash
	}
	m.write(key, entry)
	return entry, nil
}

// compile turns cached bytes into a compiled policy set.
//
// The compiled form is cached separately, keyed by content: Cache stores bytes,
// so without this every cache hit would re-run Unmarshal and engine.Compile,
// which is the expensive half.
//
// The key is a content hash rather than the ETag because this map is shared by
// every principal in the process: equal bytes are safe to share, but two
// principals presenting one ETag would not be.
func (m *Middleware) compile(e cacheEntry, principalID string) (*engine.Compiled, error) {
	if set, ok := m.compiled.get(e.Hash); ok {
		return set, nil
	}

	var policySet PolicySet
	if err := json.Unmarshal(e.Raw, &policySet); err != nil {
		return nil, fmt.Errorf("iam: decoding policy set: %w", err)
	}

	// The response echoes the principal it belongs to. A mismatch means the set
	// came from somewhere other than the request we made.
	if policySet.PrincipalID != principalID {
		m.cfg.Logger.Error("iam: policy set principal mismatch",
			"requested", principalID, "returned", policySet.PrincipalID)
		return nil, ErrPolicySetMismatch
	}

	policies := policySet.Policies
	if m.cfg.ServiceID != "" {
		policies = filterByService(policies, m.cfg.ServiceID)
	}
	set, err := engine.Compile(policies)
	if err != nil {
		return nil, fmt.Errorf("iam: compiling policies: %w", err)
	}
	m.compiled.put(e.Hash, &set)
	return &set, nil
}

// filterByService drops everything the named service cannot act on: each
// statement keeps only its actions scoped to serviceID ("file:getFile",
// "file:*") or unscoped ("*"), statements left with no action are removed, and
// policies left with no statement follow. A service only decides its own
// actions, so a dropped one could never have matched — this trims the compiled
// set, it does not change a verdict. The compiled cache is per-Middleware and
// ServiceID is fixed for its lifetime, so the content hash still keys it
// unambiguously.
func filterByService(in []policy.Policy, serviceID string) []policy.Policy {
	prefix := serviceID + ":"
	out := make([]policy.Policy, 0, len(in))
	for _, p := range in {
		statements := make([]policy.Statement, 0, len(p.Statements))
		for _, s := range p.Statements {
			actions := make([]string, 0, len(s.Actions))
			for _, a := range s.Actions {
				if a == "*" || strings.HasPrefix(a, prefix) {
					actions = append(actions, a)
				}
			}
			if len(actions) == 0 {
				continue
			}
			s.Actions = actions
			statements = append(statements, s)
		}
		if len(statements) == 0 {
			continue
		}
		p.Statements = statements
		out = append(out, p)
	}
	return out
}

func (m *Middleware) read(key string) (cacheEntry, bool) {
	b, err := m.cfg.Cache.Get(key)
	if err != nil {
		return cacheEntry{}, false
	}
	var e cacheEntry
	if err := json.Unmarshal(b, &e); err != nil {
		return cacheEntry{}, false
	}
	return e, true
}

func (m *Middleware) write(key string, e cacheEntry) {
	b, err := json.Marshal(e)
	if err != nil {
		m.cfg.Logger.Error("iam: encoding cache entry", "error", err)
		return
	}
	if err := m.cfg.Cache.Set(key, b); err != nil {
		m.cfg.Logger.Warn("iam: writing cache entry", "error", err)
	}
}

// compiledCache holds compiled policy sets keyed by content. Its working set is
// the distinct policy documents in play, which is small, so it resets wholesale
// instead of carrying eviction metadata.
type compiledCache struct {
	mu sync.RWMutex
	m  map[string]*engine.Compiled
}

func newCompiledCache() *compiledCache {
	return &compiledCache{m: make(map[string]*engine.Compiled)}
}

func (c *compiledCache) get(key string) (*engine.Compiled, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock() //nolint:errcheck
	set, ok := c.m[key]
	return set, ok
}

func (c *compiledCache) put(key string, set *engine.Compiled) {
	c.mu.Lock()
	defer c.mu.Unlock() //nolint:errcheck
	if len(c.m) >= compiledCacheMax {
		c.m = make(map[string]*engine.Compiled)
	}
	c.m[key] = set
}

// contentKey is collision-resistant because it gates which compiled set a
// principal receives from the shared map: two documents hashing alike would
// hand one principal the other's policies. It runs only when bytes arrive
// from a fetch, never on the per-request path.
func contentKey(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/grasp-labs/ds-go-policy/policy"
)

// PolicyFetcher is the data-plane seam: everything above it — cache, ages,
// compile, Decide, Constrain — is fetcher-agnostic. HTTPFetcher is the default
// for every service; ds-iam, which owns the tables, adapts its own resolution
// service instead of calling itself over HTTP.
type PolicyFetcher interface {
	// FetchPolicies retrieves the policy set in force for (tenantID,
	// principalID). authorization is the caller's Authorization header value,
	// forwarded so the policy source applies its own access control — an
	// in-process source that resolves from tenantID directly may ignore it, as
	// the HTTP source ignores tenantID (the bearer scopes the tenant). etag,
	// when non-empty, asks the source to answer NotModified if the set is
	// unchanged.
	FetchPolicies(ctx context.Context, tenantID, principalID, authorization, etag string) (FetchResult, error)
}

type FetchResult struct {
	Raw         []byte
	ETag        string
	NotModified bool
}

// maxResponseSize bounds one policy set response. Real sets are kilobytes;
// the cap only ensures a misbehaving endpoint cannot exhaust memory.
const maxResponseSize = 8 << 20 // 8 MiB

type HTTPFetcher struct {
	BaseURL string
	Client  *http.Client

	// ServiceID, when set, narrows each fetched set before it is cached and
	// compiled: a statement keeps only its actions scoped to this service
	// ("file:getFile", "file:*") or unscoped ("*"), and statements — then
	// policies — left empty are dropped. A service only decides its own
	// actions, so this trims the compiled set without changing a verdict.
	// Empty (the default) compiles the whole set.
	ServiceID string
}

func (f *HTTPFetcher) FetchPolicies(ctx context.Context, _, principalID, authorization, etag string) (FetchResult, error) {
	endpoint := strings.TrimRight(f.BaseURL, "/") + "/principal/" + url.PathEscape(principalID) + "/policies/"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return FetchResult{}, err
	}

	req.Header.Set("Accept", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	client := f.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%w: %w", ErrPolicySourceUnavailable, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// The statuses below are the ones the IAM OpenAPI spec documents for this
	// endpoint. Each maps to a different verdict for the caller, so they must
	// not collapse into one error.
	switch resp.StatusCode {
	case http.StatusOK:
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
		if err != nil {
			return FetchResult{}, fmt.Errorf("%w: reading policy set: %w", ErrPolicySourceUnavailable, err)
		}
		if len(raw) > maxResponseSize {
			return FetchResult{}, fmt.Errorf("%w: policy set response exceeds %d bytes", ErrPolicySourceUnavailable, maxResponseSize)
		}
		if f.ServiceID != "" {
			raw, err = filterPolicySetByService(raw, f.ServiceID)
			if err != nil {
				return FetchResult{}, fmt.Errorf("%w: filtering policy set: %w", ErrPolicySourceUnavailable, err)
			}
		}
		// ETag tags the full upstream set, so revalidation is unchanged: an
		// unchanged set is an unchanged subset, and a 304 keeps the filtered
		// bytes already cached.
		return FetchResult{Raw: raw, ETag: resp.Header.Get("ETag")}, nil

	case http.StatusNotModified:
		// A 304 confirms the validator we sent is still current; the response
		// carries no body and need not repeat the ETag.
		return FetchResult{NotModified: true, ETag: etag}, nil

	case http.StatusUnauthorized:
		return FetchResult{}, ErrTokenRejected

	case http.StatusUnprocessableEntity:
		return FetchResult{}, ErrPrincipalRejected

	default:
		// 429 is documented load shedding and 5xx is an outage; both are "try
		// again later", as is anything the spec does not list.
		return FetchResult{}, fmt.Errorf("%w: policy endpoint returned %s", ErrPolicySourceUnavailable, resp.Status)
	}
}

// filterPolicySetByService drops everything the named service cannot act on:
// each statement keeps only the actions scoped to serviceID or unscoped ("*"),
// statements left empty are removed, and policies left empty follow. The
// principal_id is preserved so the compile step's ownership check still holds.
func filterPolicySetByService(raw []byte, serviceID string) ([]byte, error) {
	var set PolicySet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("decoding policy set: %w", err)
	}

	prefix := serviceID + ":"
	policies := make([]policy.Policy, 0, len(set.Policies))
	for _, p := range set.Policies {
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
		policies = append(policies, p)
	}
	set.Policies = policies

	return json.Marshal(set)
}

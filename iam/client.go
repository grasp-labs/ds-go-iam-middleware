package iam

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type PolicyFetcher interface {
	// FetchPolicies retrieves the policy set for principalID. authorization is
	// the caller's Authorization header value, forwarded so the policy source
	// applies its own access control; etag, when non-empty, asks the source to
	// answer NotModified if the set is unchanged.
	FetchPolicies(ctx context.Context, principalID, authorization, etag string) (FetchResult, error)
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
}

func (f *HTTPFetcher) FetchPolicies(ctx context.Context, principalID, authorization, etag string) (FetchResult, error) {
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

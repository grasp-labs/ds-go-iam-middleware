package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// The fetcher must hit the contract's one endpoint with the caller's
// credential and validator, and map each documented status to its verdict.
func TestHTTPFetcherRequestShape(t *testing.T) {
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(context.Background())
		w.Header().Set("ETag", `"v7"`)
		_, _ = w.Write([]byte(`{"principal_id":"user@example.com","policies":[]}`))
	}))
	defer srv.Close()

	f := &HTTPFetcher{BaseURL: srv.URL + "/"} // trailing slash must not double up
	res, err := f.FetchPolicies(context.Background(), tenantID, "user@example.com", "Bearer tok", `"v6"`)
	if err != nil {
		t.Fatal(err)
	}

	if want := "/principal/user@example.com/policies/"; got.URL.Path != want {
		t.Errorf("path = %q, want %q", got.URL.Path, want)
	}
	if h := got.Header.Get("Authorization"); h != "Bearer tok" {
		t.Errorf("Authorization = %q, want the caller's header verbatim", h)
	}
	if h := got.Header.Get("If-None-Match"); h != `"v6"` {
		t.Errorf("If-None-Match = %q, want the stored validator", h)
	}
	if res.ETag != `"v7"` || res.NotModified || len(res.Raw) == 0 {
		t.Errorf("result = %+v, want fresh body with new ETag", res)
	}
}

func TestHTTPFetcherStatusMapping(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   error // nil means success
	}{
		{"not modified", http.StatusNotModified, nil},
		{"unauthorized", http.StatusUnauthorized, ErrTokenRejected},
		{"unprocessable", http.StatusUnprocessableEntity, ErrPrincipalRejected},
		{"server error", http.StatusInternalServerError, ErrPolicySourceUnavailable},
		{"load shed", http.StatusTooManyRequests, ErrPolicySourceUnavailable},
		{"undocumented", http.StatusTeapot, ErrPolicySourceUnavailable},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			f := &HTTPFetcher{BaseURL: srv.URL}
			res, err := f.FetchPolicies(context.Background(), tenantID, "user-1", "Bearer tok", `"v1"`)
			if tc.want == nil {
				if err != nil {
					t.Fatal(err)
				}
				if !res.NotModified || res.ETag != `"v1"` {
					t.Errorf("304 result = %+v, want NotModified with the offered validator", res)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// serveJSON answers every request with body.
func serveJSON(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// With ServiceID set, a statement keeps only its actions scoped to that service
// ("file:getFile", "file:*") or unscoped ("*"); another service's actions are
// stripped, and statements — then policies — left empty are dropped.
func TestHTTPFetcherServiceFilter(t *testing.T) {
	const body = `{
		"principal_id": "user-1",
		"policies": [
			{
				"id": "p1",
				"version": "1.0.0",
				"statements": [
					{
						"sid": "mixed",
						"effect": "allow",
						"actions": ["file:getFile", "file:*", "state:getJobs"],
						"resources": ["crn:t:*:file::file:**"]
					},
					{
						"sid": "other-only",
						"effect": "allow",
						"actions": ["state:getJobs", "state:listJobs"],
						"resources": ["crn:t:*:state::state:**"]
					},
					{
						"sid": "wildcard-deny",
						"effect": "deny",
						"actions": ["*"],
						"resources": ["crn:t:*:file::file:secrets/**"]
					}
				]
			},
			{
				"id": "p2",
				"version": "1.0.0",
				"statements": [
					{
						"sid": "state-scoped",
						"effect": "allow",
						"actions": ["state:*"],
						"resources": ["crn:t:*:state::state:**"]
					}
				]
			}
		]
	}`
	f := &HTTPFetcher{BaseURL: serveJSON(t, body).URL, ServiceID: "file"}
	res, err := f.FetchPolicies(context.Background(), tenantID, "user-1", "", "")
	if err != nil {
		t.Fatal(err)
	}

	var got PolicySet
	if err := json.Unmarshal(res.Raw, &got); err != nil {
		t.Fatalf("decoding filtered set: %v", err)
	}

	if got.PrincipalID != "user-1" {
		t.Errorf("principal_id = %q, want it preserved", got.PrincipalID)
	}
	// p2 is state-only and drops entirely; only p1 survives.
	if len(got.Policies) != 1 || got.Policies[0].ID != "p1" {
		t.Fatalf("policies = %+v, want only p1", got.Policies)
	}

	stmts := got.Policies[0].Statements
	// "other-only" drops (no file action); "mixed" and "wildcard-deny" stay.
	if len(stmts) != 2 {
		t.Fatalf("statements = %d, want 2 (mixed, wildcard-deny): %+v", len(stmts), stmts)
	}
	if got, want := stmts[0].Actions, []string{"file:getFile", "file:*"}; !slices.Equal(got, want) {
		t.Errorf("mixed actions = %v, want %v (scoped literal + wildcard kept, other service stripped)", got, want)
	}
	if got, want := stmts[1].Actions, []string{"*"}; !slices.Equal(got, want) {
		t.Errorf("wildcard deny actions = %v, want the unscoped * kept", got)
	}
}

// A filter that matches nothing yields a valid empty set — principal preserved,
// policies an empty array, not null — so it caches and compiles like any other.
func TestHTTPFetcherServiceFilterEmpty(t *testing.T) {
	body := `{"principal_id":"user-1","policies":[{"id":"p1","version":"1.0.0","statements":[{"sid":"s","effect":"allow","actions":["state:getJobs"],"resources":["crn:t:*:state::state:**"]}]}]}`
	f := &HTTPFetcher{BaseURL: serveJSON(t, body).URL, ServiceID: "file"}
	res, err := f.FetchPolicies(context.Background(), tenantID, "user-1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(res.Raw, []byte(`"principal_id":"user-1"`)) || !bytes.Contains(res.Raw, []byte(`"policies":[]`)) {
		t.Errorf("filtered set = %s, want principal preserved and an empty policies array", res.Raw)
	}
}

// Unset ServiceID is the default and must not touch the body: the bytes reach
// the cache exactly as the source sent them.
func TestHTTPFetcherServiceFilterUnset(t *testing.T) {
	body := `{"principal_id":"user-1","policies":[{"id":"p1","version":"1.0.0","statements":[{"sid":"s","effect":"allow","actions":["state:getJobs"],"resources":["crn:t:*:state::state:**"]}]}]}`
	f := &HTTPFetcher{BaseURL: serveJSON(t, body).URL}
	res, err := f.FetchPolicies(context.Background(), tenantID, "user-1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Raw) != body {
		t.Errorf("raw = %s, want the body passed through verbatim", res.Raw)
	}
}

// A body that will not parse is a source problem, mapped to the outage error
// like any other unusable response — not a silent pass-through.
func TestHTTPFetcherServiceFilterMalformed(t *testing.T) {
	f := &HTTPFetcher{BaseURL: serveJSON(t, `{not json`).URL, ServiceID: "file"}
	if _, err := f.FetchPolicies(context.Background(), tenantID, "user-1", "", ""); !errors.Is(err, ErrPolicySourceUnavailable) {
		t.Fatalf("err = %v, want ErrPolicySourceUnavailable", err)
	}
}

// A dead endpoint is an outage, not a denial.
func TestHTTPFetcherTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // nothing listens anymore

	f := &HTTPFetcher{BaseURL: srv.URL}
	if _, err := f.FetchPolicies(context.Background(), tenantID, "user-1", "", ""); !errors.Is(err, ErrPolicySourceUnavailable) {
		t.Fatalf("err = %v, want ErrPolicySourceUnavailable", err)
	}
}

// An oversized response is refused rather than read into memory.
func TestHTTPFetcherResponseTooLarge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxResponseSize+1)))
	}))
	defer srv.Close()

	f := &HTTPFetcher{BaseURL: srv.URL}
	if _, err := f.FetchPolicies(context.Background(), tenantID, "user-1", "", ""); !errors.Is(err, ErrPolicySourceUnavailable) {
		t.Fatalf("err = %v, want ErrPolicySourceUnavailable", err)
	}
}

package iam

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
	res, err := f.FetchPolicies(context.Background(), "user@example.com", "Bearer tok", `"v6"`)
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
			res, err := f.FetchPolicies(context.Background(), "user-1", "Bearer tok", `"v1"`)
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

// A dead endpoint is an outage, not a denial.
func TestHTTPFetcherTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // nothing listens anymore

	f := &HTTPFetcher{BaseURL: srv.URL}
	if _, err := f.FetchPolicies(context.Background(), "user-1", "", ""); !errors.Is(err, ErrPolicySourceUnavailable) {
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
	if _, err := f.FetchPolicies(context.Background(), "user-1", "", ""); !errors.Is(err, ErrPolicySourceUnavailable) {
		t.Fatalf("err = %v, want ErrPolicySourceUnavailable", err)
	}
}

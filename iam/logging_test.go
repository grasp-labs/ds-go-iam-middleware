package iam

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"
)

type logContextKey struct{}

type logContextHandler struct {
	slog.Handler
	messages []string
}

func newLogContextHandler() *logContextHandler {
	return &logContextHandler{Handler: slog.NewJSONHandler(io.Discard, nil)}
}

func (h *logContextHandler) Handle(ctx context.Context, record slog.Record) error {
	if ctx.Value(logContextKey{}) == "request-1" && ctx.Err() == nil {
		h.messages = append(h.messages, record.Message)
	}
	return nil
}

func (h *logContextHandler) requireCorrelated(t *testing.T, messages ...string) {
	t.Helper()
	for _, msg := range messages {
		if !slices.Contains(h.messages, msg) {
			t.Errorf("missing %q in logs with a live request context: %v", msg, h.messages)
		}
	}
}

func newLoggingTestMiddleware(t *testing.T, policy string) (*Middleware, *logContextHandler) {
	t.Helper()
	h := newLogContextHandler()
	m, err := New(Config{
		Fetcher:         StaticFetcher(policy),
		Cache:           NewMapCache(),
		CacheLifeWindow: DefaultCacheMaxStale,
		Principal: func(context.Context) (Principal, error) {
			return Principal{ID: "user-1", TenantID: tenantID}, nil
		},
		Logger: slog.New(h),
	})
	if err != nil {
		t.Fatal(err)
	}
	return m, h
}

func TestDecisionLogsRetainRequestContext(t *testing.T) {
	for _, tt := range []struct {
		name, policy string
		list         bool
		logs         []string
	}{
		{"denial", `{"principal_id":"user-1","policies":[]}`, false, []string{"iam: denied"}},
		{"policy mismatch", `{"principal_id":"someone-else","policies":[]}`, false, []string{"iam: policy set principal mismatch", "iam: cannot authorize"}},
		{"list failure", `{`, true, []string{"iam: encoding cache entry", "iam: cannot constrain"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m, h := newLoggingTestMiddleware(t, tt.policy)
			ctx := context.WithValue(t.Context(), logContextKey{}, "request-1")
			ctx = m.newContext(ctx, "Bearer test")
			if tt.list {
				_, _ = Constrain(ctx, "file:listFiles", nil)
			} else {
				Decide(ctx, Request{Action: "file:getFile", Resource: resource(t, "projectx/app.json")})
			}
			h.requireCorrelated(t, tt.logs...)
		})
	}
}

type writeErrorCache struct{ Cache }

func (writeErrorCache) Set(string, []byte) error { return errors.New("cache unavailable") }

func TestCacheLogRetainsDetachedRequestContext(t *testing.T) {
	m, h := newLoggingTestMiddleware(t, `{"principal_id":"user-1","policies":[]}`)
	m.cfg.Cache = writeErrorCache{NewMapCache()}
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), logContextKey{}, "request-1"))
	cancel()
	if _, err := m.load(ctx, tenantID, "user-1", "Bearer test"); err != nil {
		t.Fatal(err)
	}
	h.requireCorrelated(t, "iam: writing cache entry")
}

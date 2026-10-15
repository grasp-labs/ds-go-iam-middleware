package echoiam_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	sdkmodels "github.com/grasp-labs/ds-event-stream-go-sdk/models"
	"github.com/grasp-labs/ds-go-echo-middleware/v3/middleware/requestctx"
	"github.com/grasp-labs/ds-go-iam-middleware/adapter/echoiam"
	"github.com/grasp-labs/ds-go-iam-middleware/audit"
	"github.com/grasp-labs/ds-go-iam-middleware/iam"
	"github.com/grasp-labs/ds-go-policy/crn"
	"github.com/grasp-labs/ds-go-policy/engine"
	"github.com/labstack/echo/v4"
)

type auditProducer struct {
	events chan sdkmodels.EventJson
	gate   <-chan struct{}
}

func (p auditProducer) Send(ctx context.Context, _ string, value any) error {
	if p.gate != nil {
		select {
		case <-p.gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	p.events <- value.(sdkmodels.EventJson)
	return nil
}

type auditStatusError struct {
	status int
	cause  error
}

func (e *auditStatusError) Error() string { return "request failed" }
func (e *auditStatusError) Status() int   { return e.status }
func (e *auditStatusError) Unwrap() error { return e.cause }

func auditContext(t *testing.T, raw string) context.Context {
	t.Helper()
	const tenant = "11111111-1111-4111-8111-111111111111"
	ctx, err := iam.NewTestContext(t.Context(), iam.Principal{ID: "alice", TenantID: tenant}, []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	ctx = requestctx.SetPrincipal(ctx, requestctx.Principal{Kind: "user", ID: "alice", TenantID: uuid.MustParse(tenant)})
	ctx = requestctx.SetRequestID(ctx, "22222222-2222-4222-8222-222222222222")
	return requestctx.SetSessionID(ctx, "33333333-3333-4333-8333-333333333333")
}

func auditGuard(ctx context.Context, convertErr error) error {
	_, err := (iam.Guard[int]{Action: "file:getFile", Convert: func(engine.Constraints) (int, error) {
		return 42, convertErr
	}}).Constrain(ctx)
	return err
}

func TestAuditServeHTTPStatus(t *testing.T) {
	for _, test := range []struct {
		name      string
		err       error
		committed int
		want      int
		message   string
	}{
		{"direct Echo error", echo.ErrForbidden, 0, http.StatusForbidden, "opening the report"},
		{"wrapped Echo error", fmt.Errorf("request failed: %w", echo.ErrForbidden), 0, http.StatusInternalServerError, ""},
		{"custom status error", &auditStatusError{http.StatusServiceUnavailable, iam.ErrAccessDenied}, 0, http.StatusInternalServerError, ""},
		{"nested Echo error", echo.NewHTTPError(http.StatusInternalServerError).SetInternal(echo.ErrForbidden), 0, http.StatusForbidden, ""},
		{"committed status wins", echo.ErrInternalServerError, http.StatusForbidden, http.StatusForbidden, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			events := make(chan sdkmodels.EventJson, 1)
			publisher, err := audit.New(auditProducer{events: events}, "compliance", "ds.core.file.v2")
			if err != nil {
				t.Fatal(err)
			}
			e := echo.New()
			e.Use(echoiam.Audit(publisher))
			e.GET("/files/:id", func(c echo.Context) error {
				_ = auditGuard(c.Request().Context(), iam.ErrAccessDenied)
				if test.committed != 0 {
					if err := c.NoContent(test.committed); err != nil {
						return err
					}
				}
				return test.err
			})
			ctx := auditContext(t, `{"principal_id":"alice","policies":[]}`)
			recorder := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/files/original", nil)
			if test.message != "" {
				req.Header.Set("X-Message", test.message)
			}
			e.ServeHTTP(recorder, req)
			if recorder.Code != test.want {
				t.Fatalf("HTTP status = %d, want %d", recorder.Code, test.want)
			}
			select {
			case event := <-events:
				body, err := json.Marshal(event.Payload)
				if err != nil {
					t.Fatal(err)
				}
				var payload struct {
					StatusCode int `json:"status_code"`
				}
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatal(err)
				}
				if payload.StatusCode != recorder.Code {
					t.Fatalf("audit status = %d, HTTP status = %d", payload.StatusCode, recorder.Code)
				}
				if test.message == "" {
					if event.Message != nil {
						t.Fatalf("message = %q without X-Message header", *event.Message)
					}
				} else if event.Message == nil || *event.Message != test.message {
					t.Fatalf("message = %v, want %q", event.Message, test.message)
				}
			case <-time.After(time.Second):
				t.Fatal("authorization event was not published")
			}
		})
	}
}

func TestAuditFinalIAMOutcome(t *testing.T) {
	for _, test := range []struct {
		name       string
		policy     string
		handler    echo.HandlerFunc
		wantType   string
		wantStatus int
	}{
		{"written denial", "", func(c echo.Context) error {
			_ = auditGuard(c.Request().Context(), iam.ErrAccessDenied)
			return c.NoContent(http.StatusForbidden)
		}, "authz.denied", http.StatusForbidden},
		{"returned Echo error", "", func(c echo.Context) error {
			_ = auditGuard(c.Request().Context(), iam.ErrAccessDenied)
			return echo.ErrForbidden
		}, "authz.denied", http.StatusForbidden},
		{"nested Echo error", "", func(c echo.Context) error {
			_ = auditGuard(c.Request().Context(), iam.ErrAccessDenied)
			return echo.NewHTTPError(http.StatusInternalServerError).SetInternal(echo.ErrForbidden)
		}, "authz.denied", http.StatusForbidden},
		{"committed status wins", "", func(c echo.Context) error {
			_ = auditGuard(c.Request().Context(), iam.ErrAccessDenied)
			if err := c.NoContent(http.StatusForbidden); err != nil {
				return err
			}
			return echo.ErrInternalServerError
		}, "authz.denied", http.StatusForbidden},
		{"returned policy source error", "{", func(c echo.Context) error {
			err := auditGuard(c.Request().Context(), nil)
			return &auditStatusError{http.StatusServiceUnavailable, err}
		}, "authz.error", http.StatusInternalServerError},
		{"converter error", "", func(c echo.Context) error {
			_ = auditGuard(c.Request().Context(), errors.New("unsupported mapping"))
			return c.NoContent(http.StatusInternalServerError)
		}, "authz.error", http.StatusInternalServerError},
		{"point denial", "", func(c echo.Context) error {
			iam.Decide(c.Request().Context(), iam.Request{Action: "file:getFile", Resource: crn.CRN{
				Tenant: "11111111-1111-4111-8111-111111111111", Service: "file", Type: "file", Resource: "reports/a.txt",
			}})
			return c.NoContent(http.StatusForbidden)
		}, "authz.denied", http.StatusForbidden},
		{"allowed then validation error", "", func(c echo.Context) error {
			_ = auditGuard(c.Request().Context(), nil)
			return c.NoContent(http.StatusUnprocessableEntity)
		}, "", 0},
		{"success clears prior denial", "", func(c echo.Context) error {
			_ = auditGuard(c.Request().Context(), iam.ErrAccessDenied)
			_ = auditGuard(c.Request().Context(), nil)
			return c.NoContent(http.StatusUnprocessableEntity)
		}, "", 0},
		{"ignored refusal with successful response", "", func(c echo.Context) error {
			_ = auditGuard(c.Request().Context(), iam.ErrAccessDenied)
			return c.NoContent(http.StatusOK)
		}, "", 0},
		{"unrelated forbidden", "", func(c echo.Context) error { return c.NoContent(http.StatusForbidden) }, "", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			events := make(chan sdkmodels.EventJson, 2)
			publisher, err := audit.New(auditProducer{events: events}, "compliance", "ds.core.file.v2")
			if err != nil {
				t.Fatal(err)
			}
			raw := test.policy
			if raw == "" {
				raw = `{"principal_id":"alice","policies":[]}`
			}
			req := httptest.NewRequestWithContext(auditContext(t, raw), http.MethodGet, "/files/original", nil)
			req.Header.Set("User-Agent", "original-agent")
			req.RemoteAddr = "192.0.2.1:1234"
			c := echo.New().NewContext(req, httptest.NewRecorder())
			c.SetPath("/files/:id")
			var handlerErr error
			gotErr := echoiam.Audit(publisher)(func(c echo.Context) error {
				handlerErr = test.handler(c)
				return handlerErr
			})(c)
			if gotErr != handlerErr {
				t.Fatal("audit changed the returned error")
			}
			wait := time.Second
			if test.wantType == "" {
				wait = 20 * time.Millisecond
			}
			select {
			case event := <-events:
				if event.EventType != test.wantType {
					t.Fatalf("event type = %q, want %q", event.EventType, test.wantType)
				}
				data, err := json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				var decoded sdkmodels.EventJson
				if err := json.Unmarshal(data, &decoded); err != nil {
					t.Fatalf("invalid event: %v", err)
				}
				var payload map[string]any
				body, _ := json.Marshal(event.Payload)
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatal(err)
				}
				if payload["status_code"] != float64(test.wantStatus) || payload["action"] != "file:getFile" || payload["path"] != "/files/:id" {
					t.Fatalf("payload = %+v", payload)
				}
				if event.CreatedBy != "alice" || event.RequestId.String() != "22222222-2222-4222-8222-222222222222" || event.SessionId.String() != "33333333-3333-4333-8333-333333333333" {
					t.Fatalf("identity or request IDs changed: %+v", event)
				}
				select {
				case <-events:
					t.Fatal("duplicate authorization event")
				case <-time.After(20 * time.Millisecond):
				}
			case <-time.After(wait):
				if test.wantType != "" {
					t.Fatal("authorization event was not published")
				}
			}
		})
	}
}

func TestAuditWithoutPrincipal(t *testing.T) {
	events := make(chan sdkmodels.EventJson, 1)
	publisher, err := audit.New(auditProducer{events: events}, "compliance", "ds.core.file.v2")
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := iam.NewTestContext(t.Context(), iam.Principal{}, []byte(`{"principal_id":"alice","policies":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	c := echo.New().NewContext(httptest.NewRequestWithContext(ctx, http.MethodGet, "/files/", nil), httptest.NewRecorder())
	if err := echoiam.Audit(publisher)(func(c echo.Context) error {
		if err := auditGuard(c.Request().Context(), nil); !errors.Is(err, iam.ErrNoPrincipal) {
			t.Fatalf("guard error = %v, want missing principal", err)
		}
		return c.NoContent(http.StatusUnauthorized)
	})(c); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		if event.TenantId != uuid.Nil || event.CreatedBy == "" || event.EventType != "authz.denied" {
			t.Fatalf("missing principal event = %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("missing principal was not audited")
	}
}

func TestAuditSnapshotsEchoContext(t *testing.T) {
	events := make(chan sdkmodels.EventJson, 1)
	gate := make(chan struct{})
	publisher, err := audit.New(auditProducer{events: events, gate: gate}, "compliance", "ds.core.file.v2")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(auditContext(t, `{"principal_id":"alice","policies":[]}`))
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/files/original", nil)
	req.Header.Set("User-Agent", "original-agent")
	req.Header.Set("X-Message", "original-message")
	req.RemoteAddr = "192.0.2.1:1234"
	c := echo.New().NewContext(req, httptest.NewRecorder())
	c.SetPath("/files/:id")
	if err := echoiam.Audit(publisher)(func(c echo.Context) error {
		_ = auditGuard(c.Request().Context(), iam.ErrAccessDenied)
		return c.NoContent(http.StatusForbidden)
	})(c); err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Message", "changed-message")
	c.SetPath("/reused")
	c.SetRequest(httptest.NewRequest(http.MethodPost, "/reused", nil))
	cancel()
	close(gate)
	select {
	case event := <-events:
		body, _ := json.Marshal(event.Payload)
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatal(err)
		}
		if payload["path"] != "/files/:id" || payload["user_agent"] != "original-agent" || payload["remote_addr"] != "192.0.2.1:1234" || event.CreatedBy != "alice" {
			t.Fatalf("event used a reused Echo context: %+v", event)
		}
		if event.Message == nil || *event.Message != "original-message" {
			t.Fatalf("event did not snapshot X-Message: %v", event.Message)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled request prevented audit delivery")
	}
}

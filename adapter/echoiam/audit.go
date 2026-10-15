package echoiam

import (
	"errors"
	"log/slog"
	"net/http"
	"sync"

	"github.com/grasp-labs/ds-go-echo-middleware/v3/middleware/requestctx"
	"github.com/grasp-labs/ds-go-iam-middleware/audit"
	"github.com/grasp-labs/ds-go-iam-middleware/iam"
	"github.com/grasp-labs/ds-go-policy/crn"
	"github.com/labstack/echo/v4"
)

// Audit publishes the last unsuccessful IAM check when the request fails. Wire
// it after authentication and before the IAM handler. It does not write responses.
func Audit(publisher *audit.Publisher) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			var mu sync.Mutex
			var request iam.Request
			var decision iam.Decision
			var failed bool
			ctx := iam.WithDecisionObserver(c.Request().Context(), func(req iam.Request, result iam.Decision) {
				mu.Lock()
				defer mu.Unlock()
				request, decision = req, result
				failed = result.Err != nil || !result.Allowed
			})
			c.SetRequest(c.Request().WithContext(ctx))
			err := next(c)
			status := c.Response().Status
			if !c.Response().Committed && err != nil {
				status = http.StatusInternalServerError
				if statusErr, ok := errors.AsType[interface {
					error
					Status() int
				}](err); ok {
					status = statusErr.Status()
				} else if httpErr, ok := errors.AsType[*echo.HTTPError](err); ok {
					if internal, ok := httpErr.Internal.(*echo.HTTPError); ok {
						httpErr = internal
					}
					status = httpErr.Code
				}
			}

			mu.Lock()
			req, result, refused := request, decision, failed
			mu.Unlock()
			if !refused || status < http.StatusBadRequest {
				return err
			}

			principal, _ := requestctx.GetPrincipal(ctx)
			resource := ""
			if req.Resource != (crn.CRN{}) {
				resource = req.Resource.String()
			}
			event := audit.Event{
				TenantID: principal.TenantID, Subject: principal.ID,
				RequestID: requestctx.GetOrNewRequestUUID(ctx),
				SessionID: requestctx.GetOrNewSessionUUID(ctx),
				Path:      c.Path(), UserAgent: c.Request().UserAgent(), RemoteAddr: c.Request().RemoteAddr,
				Action: req.Action, Resource: resource, Reason: result.Reason,
				StatusCode: status, Err: result.Err,
			}
			// shortcut: sends are not drained at shutdown; add a service-owned flush if durable delivery is required.
			go func() {
				if publishErr := publisher.Publish(ctx, event); publishErr != nil {
					slog.ErrorContext(ctx, "iam: failed to publish authorization audit", "error", publishErr)
				}
			}()
			return err
		}
	}
}

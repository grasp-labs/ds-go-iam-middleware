// The only file that imports Echo.

package iam

import "github.com/labstack/echo/v4"

// Handler returns the Echo middleware. Wire it once:
//
//	e.Use(authz.Handler())
//
// It does no I/O and makes no decision: it resolves the principal, captures
// the caller's Authorization header for forwarding to the policy source, and
// attaches per-request state to the context. See Middleware.newContext for
// what that state is and why a missing principal is recorded rather than
// rejected.
func (m *Middleware) Handler() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			r := c.Request()
			ctx := m.newContext(r.Context(), r.Header.Get("Authorization"))
			c.SetRequest(r.WithContext(ctx))
			return next(c)
		}
	}
}

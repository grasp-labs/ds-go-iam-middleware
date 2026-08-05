package iam

import "errors"

var (
	// ErrNoPrincipal means the request was never identified. Map it to 401.
	ErrNoPrincipal = errors.New("iam: no principal in context")

	// ErrNoMiddleware means Decide ran on a route that skipped Handler. A
	// wiring bug: map it to 500, not 403.
	ErrNoMiddleware = errors.New("iam: middleware not installed")

	// ErrPolicySourceUnavailable means the policy set could not be reached and
	// the request cannot be decided. An outage, not a denial: map it to 503 so
	// callers can tell the two apart. Wraps transport failures, 429 and 5xx.
	ErrPolicySourceUnavailable = errors.New("iam: policy source unavailable")

	// ErrTokenRejected means the IAM API refused the caller's forwarded token.
	// It passed our own auth middleware, so the usual cause is expiry in the
	// window between the two. Map it to 401 so the client refreshes: retrying
	// with the same token cannot succeed.
	ErrTokenRejected = errors.New("iam: policy source rejected the caller's token")

	// ErrPrincipalRejected means the IAM API will not accept the principal id
	// we sent (422). Permanent for this principal, so it is worth surfacing as
	// 500 rather than 503 — no amount of retrying fixes a malformed id.
	ErrPrincipalRejected = errors.New("iam: policy source rejected the principal id")

	// ErrPolicySetMismatch means the IAM API answered with a set belonging to a
	// different principal. A response mix-up rather than a denial: map it to
	// 503. The two ids are logged, never returned.
	ErrPolicySetMismatch = errors.New("iam: policy set does not match the requested principal")
)

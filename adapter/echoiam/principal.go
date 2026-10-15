// Package echoiam adapts identities from ds-go-echo-middleware v3 for IAM.
package echoiam

import (
	"context"

	"github.com/google/uuid"
	"github.com/grasp-labs/ds-go-echo-middleware/v3/middleware/requestctx"
	"github.com/grasp-labs/ds-go-iam-middleware/iam"
)

// ResolvePrincipal reads the identity established by authentication for use as
// iam.Config.Principal. It requires a nonempty subject and a nonzero tenant UUID;
// missing or incomplete identities return iam.ErrNoPrincipal. It does not parse
// tokens, read legacy claims, or fetch policies.
func ResolvePrincipal(ctx context.Context) (iam.Principal, error) {
	principal, ok := requestctx.GetPrincipal(ctx)
	if !ok || principal.ID == "" || principal.TenantID == uuid.Nil {
		return iam.Principal{}, iam.ErrNoPrincipal
	}

	return iam.Principal{
		ID:       principal.ID,
		TenantID: principal.TenantID.String(),
	}, nil
}

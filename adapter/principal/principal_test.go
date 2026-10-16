package principal_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/grasp-labs/ds-go-echo-middleware/v3/middleware/claims"
	"github.com/grasp-labs/ds-go-echo-middleware/v3/middleware/requestctx"
	"github.com/grasp-labs/ds-go-iam-middleware/adapter/principal"
	"github.com/grasp-labs/ds-go-iam-middleware/iam"
)

func TestResolvePrincipal(t *testing.T) {
	tenantID := uuid.MustParse("ba62a53f-afa9-427d-9d91-c7987bc5662e")
	for _, test := range []struct {
		name    string
		ctx     context.Context
		want    iam.Principal
		wantErr error
	}{
		{
			name:    "nil context",
			wantErr: iam.ErrNoPrincipal,
		},
		{
			name:    "missing principal",
			ctx:     t.Context(),
			wantErr: iam.ErrNoPrincipal,
		},
		{
			name: "claims without a normalized principal",
			ctx: requestctx.SetUserContext(t.Context(), new(claims.Context{
				Sub: "alice@example.com",
				Rsc: tenantID.String() + ":Tenant",
			})),
			wantErr: iam.ErrNoPrincipal,
		},
		{
			name: "empty subject",
			ctx: requestctx.SetPrincipal(t.Context(), requestctx.Principal{
				TenantID: tenantID,
			}),
			wantErr: iam.ErrNoPrincipal,
		},
		{
			name: "zero tenant",
			ctx: requestctx.SetPrincipal(t.Context(), requestctx.Principal{
				ID: "alice@example.com",
			}),
			wantErr: iam.ErrNoPrincipal,
		},
		{
			name: "user subject is preserved",
			ctx: requestctx.SetPrincipal(t.Context(), requestctx.Principal{
				Kind:     requestctx.KindUser,
				ID:       "Alice+Finance@example.com",
				TenantID: tenantID,
			}),
			want: iam.Principal{ID: "Alice+Finance@example.com", TenantID: tenantID.String()},
		},
		{
			name: "application subject is preserved",
			ctx: requestctx.SetPrincipal(t.Context(), requestctx.Principal{
				Kind:     requestctx.KindApp,
				ID:       "client:etl-service",
				TenantID: tenantID,
			}),
			want: iam.Principal{ID: "client:etl-service", TenantID: tenantID.String()},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := principal.ResolvePrincipal(test.ctx)
			if got != test.want || !errors.Is(err, test.wantErr) {
				t.Fatalf("ResolvePrincipal() = (%+v, %v), want (%+v, %v)", got, err, test.want, test.wantErr)
			}
		})
	}
}

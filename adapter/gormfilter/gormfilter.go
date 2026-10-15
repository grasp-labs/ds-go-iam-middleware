// Package gormfilter converts IAM constraints or completed SQL predicates into
// GORM scopes. Resource mappings and additional query restrictions belong to
// the service.
package gormfilter

import (
	"errors"
	"strings"

	"github.com/grasp-labs/ds-go-iam-middleware/iam"
	"github.com/grasp-labs/ds-go-policy/adapter/sqlfilter"
	"github.com/grasp-labs/ds-go-policy/engine"
	"gorm.io/gorm"
)

// Scope is GORM's query scope function, shared without creating a new named type.
type Scope = func(*gorm.DB) *gorm.DB

// Bind applies a completed, trusted SQL predicate to the supplied query. Values
// must travel through args. The predicate is grouped before other filters are
// ANDed with it. A sqlfilter closed clause returns iam.ErrAccessDenied; an empty
// predicate is an invalid input, not a permission denial.
func Bind(where string, args ...any) (Scope, error) {
	if strings.TrimSpace(where) == "" {
		return nil, errors.New("gormfilter: empty SQL predicate")
	}
	if sqlfilter.IsClosed(where) {
		return nil, iam.ErrAccessDenied
	}
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("("+where+")", args...)
	}, nil
}

// Via converts constraints using a service-owned mapping, then binds the SQL.
// It can be used as iam.Guard[Scope].Convert. Translation errors are returned
// unchanged, so an unusable mapping cannot be mistaken for denied access.
func Via(mapping sqlfilter.Mapping) func(engine.Constraints) (Scope, error) {
	return func(constraints engine.Constraints) (Scope, error) {
		where, args, err := sqlfilter.Where(constraints, mapping)
		if err != nil {
			return nil, err
		}
		return Bind(where, args...)
	}
}

package gormfilter_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/grasp-labs/ds-go-iam-middleware/adapter/gormfilter"
	"github.com/grasp-labs/ds-go-iam-middleware/iam"
	"github.com/grasp-labs/ds-go-policy/adapter/sqlfilter"
	"github.com/grasp-labs/ds-go-policy/crn"
	"github.com/grasp-labs/ds-go-policy/engine"
	"github.com/grasp-labs/ds-go-policy/policy"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func dryRunDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN: "host=localhost dbname=iam_test sslmode=disable",
	}), &gorm.Config{
		DryRun:                 true,
		DisableAutomaticPing:   true,
		SkipDefaultTransaction: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pool.Close(); err != nil {
			t.Error(err)
		}
	})
	return db
}

func TestBindGroupsWithExistingQueryRestrictions(t *testing.T) {
	scope, err := gormfilter.Bind("owner_id = ? OR owner_id = ?", "alice", "bob")
	if err != nil {
		t.Fatal(err)
	}
	db := dryRunDB(t)
	for _, test := range []struct {
		name string
		run  func(*gorm.DB) *gorm.DB
	}{
		{"read", func(db *gorm.DB) *gorm.DB { return db.Find(&[]struct{}{}) }},
		{"count", func(db *gorm.DB) *gorm.DB { return db.Count(new(int64)) }},
		{"update", func(db *gorm.DB) *gorm.DB { return db.UpdateColumn("active", gorm.Expr("active")) }},
		{"delete", func(db *gorm.DB) *gorm.DB { return db.Delete(&struct{}{}) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			query := test.run(db.WithContext(ctx).Table("records").Where("active = ?", true).Scopes(scope))
			if query.Error != nil {
				t.Fatal(query.Error)
			}
			if sql := query.Statement.SQL.String(); !strings.Contains(sql, "WHERE active = $1 AND ((owner_id = $2 OR owner_id = $3))") {
				t.Fatalf("query lost predicate grouping: %s", sql)
			}
			if want := []any{true, "alice", "bob"}; !reflect.DeepEqual(query.Statement.Vars, want) {
				t.Fatalf("arguments = %#v, want %#v", query.Statement.Vars, want)
			}
			if query.Statement.Context != ctx {
				t.Fatal("scope replaced the query context")
			}
		})
	}
}

func TestBindPreservesTypedArguments(t *testing.T) {
	tenant := uuid.MustParse("ba62a53f-afa9-427d-9d91-c7987bc5662e")
	since := time.Date(2026, time.October, 15, 0, 0, 0, 0, time.UTC)
	scope, err := gormfilter.Bind(
		"tenant_id = ? AND created_at >= ? AND owner_id IN ? AND archived_at IS NOT DISTINCT FROM ?",
		tenant, since, []string{"alice' OR true --", "bob"}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	query := dryRunDB(t).Table("records").Scopes(scope).Find(&[]struct{}{})
	if query.Error != nil {
		t.Fatal(query.Error)
	}
	want := []any{tenant, since, "alice' OR true --", "bob", nil}
	if !reflect.DeepEqual(query.Statement.Vars, want) || strings.Contains(query.Statement.SQL.String(), "alice") {
		t.Fatalf("SQL = %q, arguments = %#v, want bound values %#v", query.Statement.SQL.String(), query.Statement.Vars, want)
	}
}

func TestBindRejectsClosedAndEmptyPredicates(t *testing.T) {
	for _, where := range []string{"1=0", "", " \n\t"} {
		t.Run(where, func(t *testing.T) {
			scope, err := gormfilter.Bind(where)
			if scope != nil || err == nil {
				t.Fatalf("Bind(%q) returned scope or no error", where)
			}
			if denied := errors.Is(err, iam.ErrAccessDenied); denied != (where == "1=0") {
				t.Fatalf("Bind(%q) error = %v, denial = %t", where, err, denied)
			}
		})
	}
}

func TestVia(t *testing.T) {
	const tenant = "ba62a53f-afa9-427d-9d91-c7987bc5662e"
	pattern, err := crn.ParsePattern("crn:" + tenant + "::config::dataset:*")
	if err != nil {
		t.Fatal(err)
	}
	mapping := sqlfilter.Mapping{
		Service: "config",
		Tenant:  "tenant_id",
		Fixed: map[sqlfilter.Segment]string{
			sqlfilter.SegmentScope:  "",
			sqlfilter.SegmentRegion: "",
			sqlfilter.SegmentType:   "dataset",
		},
		Resource: sqlfilter.ResourceColumn{ID: "id"},
	}
	allow := engine.Constraints{Allow: []engine.ResourceMatch{{Pattern: pattern}}}
	unsupported := engine.Constraints{Allow: []engine.ResourceMatch{{
		Pattern: pattern,
		Conditions: policy.Conditions{
			"StringEquals": {"unmapped": {"value"}},
		},
	}}}
	for _, test := range []struct {
		name        string
		mapping     sqlfilter.Mapping
		constraints engine.Constraints
		wantErr     error
	}{
		{"allow", mapping, allow, nil},
		{"no grant", mapping, engine.Constraints{}, iam.ErrAccessDenied},
		{"invalid mapping", sqlfilter.Mapping{}, allow, sqlfilter.ErrServiceRequired},
		{"unsupported condition", mapping, unsupported, sqlfilter.ErrUnsupportedCondition},
	} {
		t.Run(test.name, func(t *testing.T) {
			scope, err := gormfilter.Via(test.mapping)(test.constraints)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Via error = %v, want %v", err, test.wantErr)
			}
			if err != nil {
				if scope != nil || errors.Is(err, iam.ErrAccessDenied) != errors.Is(test.wantErr, iam.ErrAccessDenied) {
					t.Fatal("conversion failure returned a scope or changed denial classification")
				}
				return
			}
			query := dryRunDB(t).Table("datasets").Scopes(scope).Find(&[]struct{}{})
			if query.Error != nil || !strings.Contains(query.Statement.SQL.String(), "WHERE (tenant_id = $1)") || !reflect.DeepEqual(query.Statement.Vars, []any{tenant}) {
				t.Fatalf("query = %q, arguments = %#v, error = %v", query.Statement.SQL.String(), query.Statement.Vars, query.Error)
			}
		})
	}
}

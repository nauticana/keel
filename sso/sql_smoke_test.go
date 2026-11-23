package sso

import (
	"testing"

	"github.com/nauticana/keel/pgsql/sqlsmoke"
)

func TestNamedQueriesPrepare(t *testing.T) {
	sqlsmoke.Test(t, map[string]map[string]string{"sso": allQueries}, "../schema/basis_pgsql.sql")
}

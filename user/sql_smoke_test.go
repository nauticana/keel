package user

import (
	"testing"

	"github.com/nauticana/keel/pgsql/sqlsmoke"
)

func TestNamedQueriesPrepare(t *testing.T) {
	sqlsmoke.Test(t, map[string]map[string]string{"user": LocalUserQueries, "registration": registerQueries}, "../schema/basis_pgsql.sql")
}

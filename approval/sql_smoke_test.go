package approval

import (
	"testing"

	"github.com/nauticana/keel/pgsql/sqlsmoke"
)

func TestNamedQueriesPrepare(t *testing.T) {
	sqlsmoke.Test(t, map[string]map[string]string{"approval": queries}, "../schema/basis_pgsql.sql")
}

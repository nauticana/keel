package authserver

import (
	"testing"

	"github.com/nauticana/keel/pgsql/sqlsmoke"
)

func TestNamedQueriesPrepare(t *testing.T) {
	sqlsmoke.Test(t, map[string]map[string]string{"grants": oauthGrantQueries, "tokens": oauthTokenQueries, "clients": oauthClientQueries}, "../../schema/basis_pgsql.sql")
}

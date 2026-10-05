package authserver

import (
	"context"
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/nauticana/keel/pgsql/sqlsmoke"
)

var sqlSmoke = flag.Bool("sqlsmoke", false, "PREPARE the package's named queries on the PostgreSQL named by the libpq environment (PGHOST, PGDATABASE, ...)")

// TestNamedQueriesPrepare loads the generated DDL into a scratch schema, which
// it drops afterwards, and PREPAREs every named query against it.
func TestNamedQueriesPrepare(t *testing.T) {
	if !*sqlSmoke {
		t.Skip("run with -sqlsmoke against a disposable PostgreSQL")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	scratch := fmt.Sprintf("sqlsmoke_authserver_%d", os.Getpid())
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+scratch); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := conn.Exec(ctx, "DROP SCHEMA "+scratch+" CASCADE"); err != nil {
			t.Errorf("drop scratch schema %s: %v", scratch, err)
		}
	}()
	if _, err := conn.Exec(ctx, "SET search_path TO "+scratch); err != nil {
		t.Fatal(err)
	}
	if err := sqlsmoke.LoadSchema(ctx, conn, "../../schema/basis_pgsql.sql"); err != nil {
		t.Fatal(err)
	}
	sqlsmoke.Run(t, conn, map[string]map[string]string{"grants": oauthGrantQueries, "tokens": oauthTokenQueries, "clients": oauthClientQueries})
}

package pgsql

import (
	"context"
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/nauticana/keel/data"
)

var sqlSmoke = flag.Bool("sqlsmoke", false, "run the catalog queries on the PostgreSQL named by the libpq environment (PGHOST, PGDATABASE, ...)")

// TestForeignKeyCatalog loads the generated DDL into a scratch schema and checks
// that a foreign key to a unique key wider than the primary key pairs its columns.
func TestForeignKeyCatalog(t *testing.T) {
	if !*sqlSmoke {
		t.Skip("run with -sqlsmoke against a disposable PostgreSQL")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	scratch := fmt.Sprintf("sqlsmoke_pgsql_%d", os.Getpid())
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
	ddl, err := os.ReadFile("../schema/basis_pgsql.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, string(ddl)); err != nil {
		t.Fatal(err)
	}
	rows, err := conn.Query(ctx, rewriteQueries(pgsqlMetaQueries(scratch))[data.QGetForeignKeys], scratch)
	if err != nil {
		t.Fatal(err)
	}
	var pairs []string
	for rows.Next() {
		var constraint, child, column, parent, parentColumn string
		var position int64
		if err := rows.Scan(&constraint, &child, &position, &column, &parent, &parentColumn); err != nil {
			t.Fatal(err)
		}
		if constraint == "partner_identity_provider_oidc" {
			pairs = append(pairs, fmt.Sprintf("%d:%s.%s=%s.%s", position, child, column, parent, parentColumn))
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := "[1:partner_idp_oidc.partner_id=partner_identity_provider.partner_id 2:partner_idp_oidc.provider_id=partner_identity_provider.id]"
	if fmt.Sprint(pairs) != want {
		t.Errorf("pairs = %v, want %s", pairs, want)
	}
}

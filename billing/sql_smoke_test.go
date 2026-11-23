package billing

import (
	"testing"

	"github.com/nauticana/keel/pgsql/sqlsmoke"
)

func TestNamedQueriesPrepare(t *testing.T) {
	sqlsmoke.Test(t, map[string]map[string]string{
		"billing":      defaultBillingQueries,
		"lifecycle":    lifecycleQueries,
		"selfSchedule": selfSchedQueries,
		"provenance":   provenanceQueries,
		"reversal":     reversalQueries,
	}, "../schema/basis_pgsql.sql")
}

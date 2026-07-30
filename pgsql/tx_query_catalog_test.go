package pgsql

import "testing"

func TestCachedTransactionQueriesReuseCompiledCatalog(t *testing.T) {
	const catalogID = "test/pgsql/tx-query-catalog"
	queries := map[string]string{"find": "SELECT ?"}
	first := cachedTransactionQueries(catalogID, queries)
	queries["find"] = "SELECT ?, ?"
	second := cachedTransactionQueries(catalogID, queries)

	if first["find"] != "SELECT $1" || second["find"] != "SELECT $1" {
		t.Fatalf("cached queries = %q / %q, want one compiled catalog", first["find"], second["find"])
	}
}

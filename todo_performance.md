# Performance TODO

## Typed row scanning for hot queries

`[][]any` boxes most cells (strings, `time.Time`, most `int64`) and forces a `common.As*` type switch per read. `rows.Values()` decoding and minor-unit money columns do not remove this.

Proposed port addition, non-generic so it can live on the interface:

```go
type RowScanner interface{ Scan(dest ...any) error } // pgx.Rows and *sql.Rows both satisfy it

QueryEach(ctx context.Context, name string, scan func(RowScanner) error, args ...any) error
```

Plus a generic free helper (for example `data.Collect[T]`) that returns `[]T`. Callers scan into typed variables in the order of the SQL `SELECT` list; no boxing, no `As*`, and no column-name lookup. `QueryResult` stays for small and ad-hoc queries. Do this only when profiling shows a hot path.

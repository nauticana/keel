package model

// QueryResult is the column-name-aware return shape of every QueryService.
// Rows is a positional slice (one entry per Columns position).
type QueryResult struct {
	Columns []string
	Rows    [][]any
}

// AsMaps projects Rows into []map[string]any keyed by Columns. Useful when
// a handler needs to JSON-encode an ad-hoc query response without a typed
// model on the receiving side. Returns an empty slice (not nil) when the
// result is nil or has no rows. Each row is a fresh map; callers may
// mutate without affecting the underlying QueryResult.
func (qr *QueryResult) AsMaps() []map[string]any {
	if qr == nil || len(qr.Rows) == 0 {
		return []map[string]any{}
	}
	out := make([]map[string]any, 0, len(qr.Rows))
	for _, row := range qr.Rows {
		m := make(map[string]any, len(qr.Columns))
		for i, col := range qr.Columns {
			if i >= len(row) {
				break
			}
			m[col] = row[i]
		}
		out = append(out, m)
	}
	return out
}

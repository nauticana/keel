package config

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Print writes every command-line flag and catalog entry with its effective
// value and source. Secret-reference and credential-like values are masked.
func Print(w io.Writer, rows ConfigRows) error {
	var writeErr error
	write := func(format string, args ...any) {
		if writeErr != nil {
			return
		}
		_, writeErr = fmt.Fprintf(w, format, args...)
	}
	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })
	write("flags:\n")
	flag.VisitAll(func(f *flag.Flag) {
		source := "default"
		if set[f.Name] {
			source = "set"
		}
		write("  --%s=%s (%s)\n", f.Name, maskValue(f.Name, f.Value.String()), source)
	})

	ids := make([]string, 0, len(rows))
	for id := range rows {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	write("config:\n")
	for _, id := range ids {
		row := rows[id]
		source := row.Source
		if source == "" {
			source = "default"
		}
		if source != "default" && row.Default != "" {
			source += ", default " + maskValue(id, row.Default)
		}
		write("  %s=%s (%s)\n", id, maskValue(id, row.Value), source)
	}
	return writeErr
}

func maskValue(key, value string) string {
	if value == "" || !isSensitiveKey(key) {
		return value
	}
	return "***"
}

func isSensitiveKey(key string) bool {
	k := strings.ToLower(key)
	if strings.HasSuffix(k, "_mode") {
		return false
	}
	for _, marker := range []string{"password", "secret", "credential", "private"} {
		if strings.Contains(k, marker) {
			return true
		}
	}
	return false
}

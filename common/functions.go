package common

import (
	"fmt"
	"strings"
	"time"
	"unicode"
)

// AsFloat64 returns -1 sentinel on nil / unrecognized types. Use
// AsFloat64OK when the domain treats -1 as a meaningful value
// (e.g. "unlimited" sentinels in quota tables) and "did the column
// hold an actual -1 vs. was it NULL" needs to be distinguishable.
func AsFloat64(v any) float64 {
	if out, ok := AsFloat64OK(v); ok {
		return out
	}
	return -1
}

// AsFloat64OK is the explicit-result sibling. Returns ok=true only
// when v is a known numeric type. Callers should prefer this in
// hot paths that read quota / amount columns where -1 is a real
// value — the sentinel-based AsFloat64 conflates "NULL row" with
// "actual -1".
func AsFloat64OK(v any) (float64, bool) {
	if v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	case float32:
		return float64(n), true
	}
	return 0, false
}

func AsInt32(v any) int32 {
	if v, ok := AsInt32OK(v); ok {
		return v
	}
	return -1
}

// AsInt32OK is the explicit-result sibling of AsInt32. Same
// motivation as AsFloat64OK: distinguish "NULL" from "actual -1".
func AsInt32OK(v any) (int32, bool) {
	if v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return int32(n), true
	case int32:
		return n, true
	case int64:
		return int32(n), true
	case float64:
		return int32(n), true
	}
	return 0, false
}

func AsInt64(v any) int64 {
	if v, ok := AsInt64OK(v); ok {
		return v
	}
	return -1
}

// AsInt64OK is the explicit-result sibling of AsInt64. Returns
// ok=false on nil / unrecognized types so callers can distinguish
// NULL columns from actual -1 values (relevant in quota /
// "unlimited" sentinels).
func AsInt64OK(v any) (int64, bool) {
	if v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), true
	}
	return 0, false
}

func AsBool(v any) bool {
	if v == nil {
		return false
	}
	switch v := v.(type) {
	case bool:
		return v
	case string:
		return v == "1" || v == "true"
	case []byte:
		return string(v) == "1"
	}
	return false
}

func AsString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return fmt.Sprintf("%v", v)
}

// AsTime extracts a time.Time from a value of unknown type. Returns
// the zero Time when v is nil, isn't a time/string, or doesn't parse
// against the RFC3339 / "2006-01-02 15:04:05" formats.
//
// CAUTION (P2-06): the zero return is ambiguous — it conflates "no
// value" with "couldn't parse the value we got". Code that needs to
// distinguish the two should call AsTimeOK.
func AsTime(v any) time.Time {
	t, _ := AsTimeOK(v)
	return t
}

// AsTimeOK is the explicit-result sibling of AsTime: it returns
// ok=true only when v was non-nil AND parsed successfully. Use this
// when "no value" needs to be distinguishable from "we got a value
// but it didn't parse" — e.g. when the zero time would be a valid
// observation in the domain (a deleted-at column where the row IS
// supposed to be epoch-0 to mark a tombstone).
func AsTimeOK(v any) (time.Time, bool) {
	if v == nil {
		return time.Time{}, false
	}
	if t, ok := v.(time.Time); ok {
		return t, true
	}
	if s, ok := v.(string); ok {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t, true
		}
		if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func PascalCase(s string) string {
	words := strings.Split(s, "_")
	for i, word := range words {
		if len(word) > 0 {
			runes := []rune(word)
			runes[0] = unicode.ToUpper(runes[0])
			words[i] = string(runes)
		}
	}
	return strings.Join(words, "")
}

func TitleCase(s string) string {
	words := strings.Split(s, "_")
	for i, word := range words {
		if len(word) > 0 {
			runes := []rune(word)
			runes[0] = unicode.ToUpper(runes[0])
			words[i] = string(runes)
		}
	}
	return strings.Join(words, " ")
}

package handler

import "testing"

// Reserved pagination/order params are accepted under both the canonical name
// (limit/offset/order) and the underscore-prefixed alias (_limit/_offset/_order)
// some clients send, and are stripped from the filter map so they never reach
// the strict column filter (which rejects unknown keys with 400).
func TestExtractPagination_AcceptsBothConventions(t *testing.T) {
	cases := []struct {
		name       string
		in         map[string]string
		limit, off int
	}{
		{"underscore", map[string]string{"_limit": "25", "_offset": "50"}, 25, 50},
		{"canonical", map[string]string{"limit": "10", "offset": "5"}, 10, 5},
		{"none defaults", map[string]string{}, 100, 0},                    // default_list_page_size
		{"over cap clamps", map[string]string{"_limit": "5000"}, 1000, 0}, // max_list_page_size
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			limit, off := extractPagination(c.in)
			if limit != c.limit || off != c.off {
				t.Fatalf("limit/offset = %d/%d, want %d/%d", limit, off, c.limit, c.off)
			}
			if len(c.in) != 0 {
				t.Fatalf("reserved params not stripped from filter: %v", c.in)
			}
		})
	}
}

// The reserved params must be stripped (so a well-formed paginated request isn't
// 400'd), while a genuinely unknown key must survive for the column filter to
// reject it — that rejection is the v1.2.18 mass-delete guard.
func TestExtractPagination_StripsReservedButKeepsUnknown(t *testing.T) {
	f := map[string]string{"_limit": "25", "_offset": "0", "bogus": "1"}
	extractPagination(f)
	if _, ok := f["_limit"]; ok {
		t.Error("_limit not stripped")
	}
	if _, ok := f["_offset"]; ok {
		t.Error("_offset not stripped")
	}
	if f["bogus"] != "1" {
		t.Error("unknown filter key must survive so castFilterValues can reject it")
	}
}

func TestExtractOrder_AcceptsBothConventions(t *testing.T) {
	for _, key := range []string{"order", "_order"} {
		f := map[string]string{key: "name DESC"}
		if got := extractOrder(f); got != "name DESC" {
			t.Errorf("%s: order = %q, want %q", key, got, "name DESC")
		}
		if len(f) != 0 {
			t.Errorf("%s: order key not stripped: %v", key, f)
		}
	}
}

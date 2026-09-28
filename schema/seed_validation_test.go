package schema

import "testing"

func TestSeedsSatisfyForeignKeys(t *testing.T) {
	s, err := ParseDir(".")
	if err != nil {
		t.Fatal(err)
	}
	seeds, err := ParseSeedDir("seed")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSeeds(seeds, s); err != nil {
		t.Fatal(err)
	}
}

func TestValidateSeedsRejectsMissingParent(t *testing.T) {
	s, err := ParseDir("core")
	if err != nil {
		t.Fatal(err)
	}
	seeds := []*SeedFile{{Seeds: []*SeedTable{
		{Table: "rest_api_header", Columns: []string{"id", "master_table"}, Rows: [][]any{{"thing", "thing"}}},
		{Table: "rest_api_child", Columns: []string{"api_id", "seq", "parent_seq", "constraint_name"}, Rows: [][]any{{"thing", 1, 0, "thing_children"}}},
	}}}
	if err := ValidateSeeds(seeds, s); err == nil {
		t.Fatal("child without its foreign_key_lookup accepted")
	}
}

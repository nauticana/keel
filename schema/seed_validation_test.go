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

func TestValidateRejectsLongSequenceName(t *testing.T) {
	s, err := ParseDir("core")
	if err != nil {
		t.Fatal(err)
	}
	s.GetTable("consent_event").Sequence.Name = "consent_event_sequence_name_too_long"
	if err := s.Validate(); err == nil {
		t.Fatal("sequence name over 32 characters accepted")
	}
}

func TestParseSeedPathAcceptsFilesAndDirectories(t *testing.T) {
	file, err := ParseSeedPath("seed/core.yml")
	if err != nil || len(file) != 1 {
		t.Fatalf("seed file = %d files, %v", len(file), err)
	}
	dir, err := ParseSeedPath("seed")
	if err != nil || len(dir) < 2 {
		t.Fatalf("seed directory = %d files, %v", len(dir), err)
	}
	if _, err := ParseSeedPath("seed.go"); err == nil {
		t.Fatal("non-YAML seed file accepted")
	}
	if _, err := ParseSeedPath("seed/missing.yml"); err == nil {
		t.Fatal("missing seed file accepted")
	}
}

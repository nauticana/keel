package schema

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

type dependencyLayout struct {
	Version int                     `yaml:"version"`
	Groups  []dependencyLayoutGroup `yaml:"groups"`
}

type dependencyLayoutGroup struct {
	Name          string   `yaml:"name"`
	Path          string   `yaml:"path"`
	Seed          string   `yaml:"seed"`
	DependsOn     []string `yaml:"depends_on"`
	SeedDependsOn []string `yaml:"seed_depends_on"`
}

func TestComponentLayoutMatchesSchemaAndSeeds(t *testing.T) {
	data, err := os.ReadFile("dependency.yml")
	if err != nil {
		t.Fatal(err)
	}
	var layout dependencyLayout
	if err := yaml.Unmarshal(data, &layout); err != nil {
		t.Fatal(err)
	}
	if layout.Version != 1 {
		t.Fatalf("dependency.yml version = %d, want 1", layout.Version)
	}

	ownerByTable := make(map[string]string)
	groupsByName := make(map[string]dependencyLayoutGroup)
	seedFilesByGroup := make(map[string]*SeedFile)
	expandedSeedArray := regexp.MustCompile(`(?m)^\s+columns:\s*$|^\s+- - `)
	lastSeedOrder := 0
	for _, group := range layout.Groups {
		if _, duplicate := groupsByName[group.Name]; duplicate {
			t.Fatalf("duplicate group %q", group.Name)
		}
		for _, dependency := range group.DependsOn {
			if _, ordered := groupsByName[dependency]; !ordered {
				t.Fatalf("group %s dependency %s must appear earlier in dependency.yml", group.Name, dependency)
			}
		}
		for _, dependency := range group.SeedDependsOn {
			if _, ordered := groupsByName[dependency]; !ordered {
				t.Fatalf("group %s seed dependency %s must appear earlier in dependency.yml", group.Name, dependency)
			}
		}
		groupsByName[group.Name] = group

		groupSchema, err := ParseDir(group.Path)
		if err != nil {
			t.Fatalf("parse group %s: %v", group.Name, err)
		}
		if len(groupSchema.Tables) == 0 {
			t.Fatalf("group %s has no table definitions", group.Name)
		}
		for _, table := range groupSchema.Tables {
			if previous := ownerByTable[table.Name]; previous != "" {
				t.Fatalf("table %s belongs to both %s and %s", table.Name, previous, group.Name)
			}
			ownerByTable[table.Name] = group.Name
		}
		seedFile, err := ParseSeedFile(group.Seed)
		if err != nil {
			t.Fatalf("parse seed for group %s: %v", group.Name, err)
		}
		if seedFile.Order <= lastSeedOrder {
			t.Fatalf("group %s seed order %d must follow %d", group.Name, seedFile.Order, lastSeedOrder)
		}
		lastSeedOrder = seedFile.Order
		seedFilesByGroup[group.Name] = seedFile
		seedSource, err := os.ReadFile(group.Seed)
		if err != nil {
			t.Fatal(err)
		}
		if expandedSeedArray.Match(seedSource) {
			t.Errorf("group %s seed contains expanded columns or row arrays", group.Name)
		}
		if filepath.Base(group.Seed) != group.Name+".yml" {
			t.Fatalf("group %s seed path %q does not use the group name", group.Name, group.Seed)
		}
	}

	fullSchema, err := ParseDir(".")
	if err != nil {
		t.Fatal(err)
	}
	if err := fullSchema.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(fullSchema.Tables) != len(ownerByTable) {
		t.Fatalf("recursive schema has %d tables, component folders have %d", len(fullSchema.Tables), len(ownerByTable))
	}
	for group, seedFile := range seedFilesByGroup {
		for _, seedTable := range seedFile.Seeds {
			table := fullSchema.GetTable(seedTable.Table)
			if table == nil {
				t.Errorf("group %s seed references unknown table %s", group, seedTable.Table)
				continue
			}
			columns := make(map[string]bool)
			for _, column := range table.Columns {
				columns[column.Name] = true
			}
			for _, column := range seedTable.Columns {
				if !columns[column] {
					t.Errorf("group %s seed references unknown column %s.%s", group, seedTable.Table, column)
				}
			}
			for index, row := range seedTable.Rows {
				if len(row) != len(seedTable.Columns) {
					t.Errorf("group %s seed row %d for %s has %d values for %d columns", group, index, seedTable.Table, len(row), len(seedTable.Columns))
				}
			}
		}
	}

	actualDependencies := make(map[string]map[string]bool)
	for _, table := range fullSchema.Tables {
		childGroup := ownerByTable[table.Name]
		for _, fk := range table.ForeignKeys {
			parentGroup := ownerByTable[fk.References.Table]
			if parentGroup != childGroup {
				if actualDependencies[childGroup] == nil {
					actualDependencies[childGroup] = make(map[string]bool)
				}
				actualDependencies[childGroup][parentGroup] = true
			}
		}
	}

	for _, group := range layout.Groups {
		var actual []string
		for dependency := range actualDependencies[group.Name] {
			actual = append(actual, dependency)
		}
		slices.Sort(actual)
		expected := slices.Clone(group.DependsOn)
		slices.Sort(expected)
		if !slices.Equal(actual, expected) {
			t.Errorf("group %s dependencies = %v, want %v", group.Name, actual, expected)
		}
		for _, dependency := range group.DependsOn {
			if _, exists := groupsByName[dependency]; !exists {
				t.Errorf("group %s has unknown dependency %s", group.Name, dependency)
			}
		}
		for _, dependency := range group.SeedDependsOn {
			if _, exists := groupsByName[dependency]; !exists {
				t.Errorf("group %s has unknown seed dependency %s", group.Name, dependency)
			}
		}
	}

	for groupName, seedFile := range seedFilesByGroup {
		actualSet := make(map[string]bool)
		for _, seedTable := range seedFile.Seeds {
			owner := ownerByTable[seedTable.Table]
			if owner != "" && owner != groupName {
				actualSet[owner] = true
			}
		}
		var actual []string
		for dependency := range actualSet {
			actual = append(actual, dependency)
		}
		slices.Sort(actual)
		expected := slices.Clone(groupsByName[groupName].SeedDependsOn)
		slices.Sort(expected)
		if !slices.Equal(actual, expected) {
			t.Errorf("group %s seed dependencies = %v, want %v", groupName, actual, expected)
		}
	}

	seedFiles, err := ParseSeedDir("seed")
	if err != nil {
		t.Fatal(err)
	}
	if len(seedFiles) != len(layout.Groups) {
		t.Fatalf("seed directory has %d files, dependency.yml has %d groups", len(seedFiles), len(layout.Groups))
	}
}

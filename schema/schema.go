package schema

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// Schema represents the complete parsed schema from YAML files.
type Schema struct {
	Tables   []*Table
	tableMap map[string]*Table
}

// Table represents a single database table definition.
type Table struct {
	Name        string        `yaml:"table"`
	Comment     string        `yaml:"comment,omitempty"`
	Columns     []*Column     `yaml:"columns"`
	PrimaryKey  []string      `yaml:"primary_key"`
	ForeignKeys []*ForeignKey `yaml:"foreign_keys,omitempty"`
	Indexes     []*Index      `yaml:"indexes,omitempty"`
	Checks      []*Check      `yaml:"checks,omitempty"`
	Sequence    *Sequence     `yaml:"sequence,omitempty"`
	Extensions  []string      `yaml:"extensions,omitempty"`
	Order       int           `yaml:"order,omitempty"`
}

// Column represents a table column.
type Column struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`
	Nullable bool   `yaml:"nullable,omitempty"`
	Default  string `yaml:"default,omitempty"`
	Comment  string `yaml:"comment,omitempty"`
}

// ForeignKey represents a foreign key constraint.
//
// OnDelete / OnUpdate (P1-50) accept the standard SQL referential
// actions: NO ACTION (default), RESTRICT, CASCADE, SET NULL,
// SET DEFAULT. Empty string emits no clause; the dialect emitter
// passes the value through verbatim, so misspellings will surface
// as a SQL syntax error at apply time rather than silently being
// dropped.
type ForeignKey struct {
	Name       string    `yaml:"name"`
	Columns    []string  `yaml:"columns"`
	References RefTarget `yaml:"references"`
	OnDelete   string    `yaml:"on_delete,omitempty"`
	OnUpdate   string    `yaml:"on_update,omitempty"`
}

// RefTarget represents the target of a foreign key reference.
type RefTarget struct {
	Table   string   `yaml:"table"`
	Columns []string `yaml:"columns"`
}

// Index represents a database index.
type Index struct {
	Name    string   `yaml:"name"`
	Columns []string `yaml:"columns"`
	Unique  bool     `yaml:"unique,omitempty"`
	Using   string   `yaml:"using,omitempty"`
}

// Check represents a CHECK constraint.
type Check struct {
	Name       string `yaml:"name"`
	Expression string `yaml:"expression"`
}

// Sequence represents an auto-increment sequence for a column.
type Sequence struct {
	Name        string `yaml:"name"`
	Column      string `yaml:"column"`
	IncrementBy int    `yaml:"increment_by,omitempty"`
	StartWith   int    `yaml:"start_with,omitempty"`
}

// ParseFile parses a single YAML schema file.
func ParseFile(path string) (*Table, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	var table Table
	if err := yaml.Unmarshal(data, &table); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	if table.Name == "" {
		return nil, fmt.Errorf("table name is required in %s", path)
	}
	if len(table.Columns) == 0 {
		return nil, fmt.Errorf("at least one column is required in %s", path)
	}
	if len(table.PrimaryKey) == 0 {
		return nil, fmt.Errorf("primary_key is required in %s", path)
	}
	// Default sequence values
	if table.Sequence != nil {
		if table.Sequence.IncrementBy == 0 {
			table.Sequence.IncrementBy = 1
		}
		if table.Sequence.StartWith == 0 {
			table.Sequence.StartWith = 1
		}
	}
	return &table, nil
}

// ParseDir parses all YAML files in a directory (non-recursive).
func ParseDir(dir string) (*Schema, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", dir, err)
	}
	schema := &Schema{
		tableMap: make(map[string]*Table),
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yml" && ext != ".yaml" {
			continue
		}
		table, err := ParseFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		if _, exists := schema.tableMap[table.Name]; exists {
			return nil, fmt.Errorf("duplicate table name %q", table.Name)
		}
		schema.tableMap[table.Name] = table
		schema.Tables = append(schema.Tables, table)
	}
	// Sort by order field, then by name for stability
	sort.Slice(schema.Tables, func(i, j int) bool {
		if schema.Tables[i].Order != schema.Tables[j].Order {
			return schema.Tables[i].Order < schema.Tables[j].Order
		}
		return schema.Tables[i].Name < schema.Tables[j].Name
	})
	return schema, nil
}

// ParseDirs parses multiple directories in order, merging all tables.
func ParseDirs(dirs []string) (*Schema, error) {
	schema := &Schema{
		tableMap: make(map[string]*Table),
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("failed to read directory %s: %w", dir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			ext := filepath.Ext(entry.Name())
			if ext != ".yml" && ext != ".yaml" {
				continue
			}
			table, err := ParseFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				return nil, err
			}
			if _, exists := schema.tableMap[table.Name]; exists {
				return nil, fmt.Errorf("duplicate table name %q", table.Name)
			}
			schema.tableMap[table.Name] = table
			schema.Tables = append(schema.Tables, table)
		}
	}
	sort.Slice(schema.Tables, func(i, j int) bool {
		if schema.Tables[i].Order != schema.Tables[j].Order {
			return schema.Tables[i].Order < schema.Tables[j].Order
		}
		return schema.Tables[i].Name < schema.Tables[j].Name
	})
	return schema, nil
}

// GetTable returns a table by name.
func (s *Schema) GetTable(name string) *Table {
	return s.tableMap[name]
}

// Validate runs cross-table integrity checks against the parsed schema
// (P1-51). Errors here used to surface only at psql apply time —
// validation now fails fast at parse time with a clear message.
//
// Checks:
//   - every primary-key column exists in the table's column list
//   - every FK column exists in the table
//   - every FK target table exists in the schema
//   - FK source/target column counts match
//   - sequence column exists in the table
//   - index columns exist in the table
//   - constraint / index / FK / check names are unique within a table
func (s *Schema) Validate() error {
	for _, t := range s.Tables {
		colSet := map[string]struct{}{}
		for _, c := range t.Columns {
			if _, dup := colSet[c.Name]; dup {
				return fmt.Errorf("schema: duplicate column %q in table %q", c.Name, t.Name)
			}
			colSet[c.Name] = struct{}{}
		}
		for _, pk := range t.PrimaryKey {
			if _, ok := colSet[pk]; !ok {
				return fmt.Errorf("schema: primary key column %q on table %q is not in the column list", pk, t.Name)
			}
		}
		fkNames := map[string]struct{}{}
		for _, fk := range t.ForeignKeys {
			if _, dup := fkNames[fk.Name]; dup {
				return fmt.Errorf("schema: duplicate FK constraint name %q on table %q", fk.Name, t.Name)
			}
			fkNames[fk.Name] = struct{}{}
			if len(fk.Columns) != len(fk.References.Columns) {
				return fmt.Errorf("schema: FK %q on table %q has %d source columns but references %d target columns",
					fk.Name, t.Name, len(fk.Columns), len(fk.References.Columns))
			}
			for _, c := range fk.Columns {
				if _, ok := colSet[c]; !ok {
					return fmt.Errorf("schema: FK %q on table %q references unknown source column %q",
						fk.Name, t.Name, c)
				}
			}
			parent := s.tableMap[fk.References.Table]
			if parent == nil {
				return fmt.Errorf("schema: FK %q on table %q references unknown table %q",
					fk.Name, t.Name, fk.References.Table)
			}
			parentCols := map[string]struct{}{}
			for _, c := range parent.Columns {
				parentCols[c.Name] = struct{}{}
			}
			for _, c := range fk.References.Columns {
				if _, ok := parentCols[c]; !ok {
					return fmt.Errorf("schema: FK %q on table %q references unknown column %q on table %q",
						fk.Name, t.Name, c, parent.Name)
				}
			}
		}
		idxNames := map[string]struct{}{}
		for _, idx := range t.Indexes {
			if _, dup := idxNames[idx.Name]; dup {
				return fmt.Errorf("schema: duplicate index name %q on table %q", idx.Name, t.Name)
			}
			idxNames[idx.Name] = struct{}{}
			for _, c := range idx.Columns {
				if _, ok := colSet[c]; !ok {
					return fmt.Errorf("schema: index %q on table %q references unknown column %q",
						idx.Name, t.Name, c)
				}
			}
		}
		if t.Sequence != nil {
			if _, ok := colSet[t.Sequence.Column]; !ok {
				return fmt.Errorf("schema: sequence on table %q references unknown column %q",
					t.Name, t.Sequence.Column)
			}
		}
		checkNames := map[string]struct{}{}
		for _, chk := range t.Checks {
			if _, dup := checkNames[chk.Name]; dup {
				return fmt.Errorf("schema: duplicate check constraint %q on table %q", chk.Name, t.Name)
			}
			checkNames[chk.Name] = struct{}{}
		}
	}
	return nil
}

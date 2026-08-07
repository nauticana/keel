package schema

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

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

// Index represents a database index. Where makes it a partial index —
// PostgreSQL emits the predicate verbatim; MySQL cannot express filtered
// indexes, so the mysql dialect degrades a partial index to a plain
// non-unique index and the invariant must be service-enforced there.
type Index struct {
	Name    string   `yaml:"name"`
	Columns []string `yaml:"columns"`
	Unique  bool     `yaml:"unique,omitempty"`
	Using   string   `yaml:"using,omitempty"`
	Where   string   `yaml:"where,omitempty"`
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

type tableGroupMeta struct {
	Tables []string `yaml:"tables"`
}

type dependencyPaths struct {
	Groups []struct {
		Path string `yaml:"path"`
	} `yaml:"groups"`
}

type tableSource struct {
	Path        string
	OrderedMeta bool
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

// ParseDir parses all table YAML files below a directory recursively.
func ParseDir(dir string) (*Schema, error) {
	return ParseDirs([]string{dir})
}

// ParseDirs recursively parses multiple directories and merges all tables.
// A schema root may contain dependency.yml and a seed directory; neither is a
// table definition, so both are excluded from the recursive walk.
func ParseDirs(dirs []string) (*Schema, error) {
	schema := &Schema{
		tableMap: make(map[string]*Table),
	}
	var hasOrderedMetadata bool
	var hasLegacyOrder bool
	for _, dir := range dirs {
		sources, err := tableSources(dir)
		if err != nil {
			return nil, err
		}
		for _, source := range sources {
			table, err := ParseFile(source.Path)
			if err != nil {
				return nil, err
			}
			if source.OrderedMeta {
				hasOrderedMetadata = true
				if table.Order != 0 {
					return nil, fmt.Errorf("table %q declares order in %s; put creation order in %s instead",
						table.Name, source.Path, filepath.Join(filepath.Dir(source.Path), "ab_meta.yml"))
				}
				filename := strings.TrimSuffix(filepath.Base(source.Path), filepath.Ext(source.Path))
				if filename != table.Name {
					return nil, fmt.Errorf("table %q must be stored as %s.yml, got %s", table.Name, table.Name, source.Path)
				}
			} else {
				hasLegacyOrder = true
			}
			if _, exists := schema.tableMap[table.Name]; exists {
				return nil, fmt.Errorf("duplicate table name %q", table.Name)
			}
			if source.OrderedMeta {
				table.Order = len(schema.Tables) + 1
			}
			schema.tableMap[table.Name] = table
			schema.Tables = append(schema.Tables, table)
		}
	}
	if hasOrderedMetadata && hasLegacyOrder {
		return nil, fmt.Errorf("cannot mix ab_meta.yml ordered groups with legacy per-table order files")
	}
	if hasLegacyOrder {
		sort.Slice(schema.Tables, func(i, j int) bool {
			if schema.Tables[i].Order != schema.Tables[j].Order {
				return schema.Tables[i].Order < schema.Tables[j].Order
			}
			return schema.Tables[i].Name < schema.Tables[j].Name
		})
	}
	return schema, nil
}

func tableSources(dir string) ([]tableSource, error) {
	root := filepath.Clean(dir)
	dependencyPath := filepath.Join(root, "dependency.yml")
	if _, err := os.Stat(dependencyPath); err == nil {
		return dependencyTableSources(root, dependencyPath)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect dependency file %s: %w", dependencyPath, err)
	}
	metaPath := filepath.Join(root, "ab_meta.yml")
	if _, err := os.Stat(metaPath); err == nil {
		return groupTableSources(root, metaPath)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect table metadata %s: %w", metaPath, err)
	}
	return legacyTableSources(root)
}

func dependencyTableSources(root, dependencyPath string) ([]tableSource, error) {
	data, err := os.ReadFile(dependencyPath)
	if err != nil {
		return nil, fmt.Errorf("read dependency file %s: %w", dependencyPath, err)
	}
	var dependencies dependencyPaths
	if err := yaml.Unmarshal(data, &dependencies); err != nil {
		return nil, fmt.Errorf("parse dependency file %s: %w", dependencyPath, err)
	}
	if len(dependencies.Groups) == 0 {
		return nil, fmt.Errorf("dependency file %s has no groups", dependencyPath)
	}
	seen := make(map[string]bool)
	var sources []tableSource
	for _, group := range dependencies.Groups {
		if group.Path == "" {
			return nil, fmt.Errorf("dependency file %s contains a group without a path", dependencyPath)
		}
		if seen[group.Path] {
			return nil, fmt.Errorf("dependency file %s repeats group path %q", dependencyPath, group.Path)
		}
		seen[group.Path] = true
		groupDir := filepath.Join(root, group.Path)
		groupSources, err := groupTableSources(groupDir, filepath.Join(groupDir, "ab_meta.yml"))
		if err != nil {
			return nil, err
		}
		sources = append(sources, groupSources...)
	}
	return sources, nil
}

func groupTableSources(dir, metaPath string) ([]tableSource, error) {
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("read table metadata %s: %w", metaPath, err)
	}
	var meta tableGroupMeta
	if err := yaml.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parse table metadata %s: %w", metaPath, err)
	}
	if len(meta.Tables) == 0 {
		return nil, fmt.Errorf("table metadata %s has no tables", metaPath)
	}
	seen := make(map[string]bool)
	sources := make([]tableSource, 0, len(meta.Tables))
	for _, table := range meta.Tables {
		if table == "" {
			return nil, fmt.Errorf("table metadata %s contains an empty table name", metaPath)
		}
		if seen[table] {
			return nil, fmt.Errorf("table metadata %s repeats table %q", metaPath, table)
		}
		seen[table] = true
		path := filepath.Join(dir, table+".yml")
		if _, err := os.Stat(path); os.IsNotExist(err) {
			alternate := filepath.Join(dir, table+".yaml")
			if _, alternateErr := os.Stat(alternate); alternateErr != nil {
				return nil, fmt.Errorf("table metadata %s lists %q but neither %s nor %s exists", metaPath, table, path, alternate)
			}
			path = alternate
		} else if err != nil {
			return nil, fmt.Errorf("inspect table file %s: %w", path, err)
		}
		sources = append(sources, tableSource{Path: path, OrderedMeta: true})
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read table group directory %s: %w", dir, err)
	}
	var tableFileCount int
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "ab_meta.yml" || entry.Name() == "ab_meta.yaml" {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext == ".yml" || ext == ".yaml" {
			tableFileCount++
		}
	}
	if tableFileCount != len(sources) {
		return nil, fmt.Errorf("table metadata %s lists %d tables but directory contains %d table YAML files",
			metaPath, len(sources), tableFileCount)
	}
	return sources, nil
}

func legacyTableSources(root string) ([]tableSource, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && entry.Name() == "seed" {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() == "dependency.yml" || entry.Name() == "dependency.yaml" ||
			entry.Name() == "ab_meta.yml" || entry.Name() == "ab_meta.yaml" {
			return nil
		}
		ext := filepath.Ext(entry.Name())
		if ext == ".yml" || ext == ".yaml" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk directory %s: %w", root, err)
	}
	sort.Strings(files)
	sources := make([]tableSource, len(files))
	for index, file := range files {
		sources[index] = tableSource{Path: file}
	}
	return sources, nil
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
//   - every FK parent is ordered before its child (required by MySQL)
func (s *Schema) Validate() error {
	position := make(map[string]int, len(s.Tables))
	for index, table := range s.Tables {
		position[table.Name] = index
	}
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
			if parent.Name != t.Name && position[parent.Name] > position[t.Name] {
				return fmt.Errorf("schema: FK %q requires parent table %q before child table %q; fix the component ab_meta.yml or dependency.yml order",
					fk.Name, parent.Name, t.Name)
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

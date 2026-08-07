package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/nauticana/keel/schema"
	"github.com/nauticana/keel/schema/dialect"
)

func main() {
	dialectName := flag.String("dialect", "pgsql", "SQL dialect: pgsql or mysql")
	inputDirs := flag.String("input", "schema/", "Comma-separated list of schema directories")
	seedDirs := flag.String("seed", "", "Comma-separated list of directories containing seed YAML files")
	outputFile := flag.String("out", "", "Output file path (default: stdout)")
	singleTable := flag.String("table", "", "Generate DDL for a single table by table name")
	flag.Parse()

	dirs := strings.Split(*inputDirs, ",")
	for i := range dirs {
		dirs[i] = strings.TrimSpace(dirs[i])
	}

	var d dialect.Dialect
	switch *dialectName {
	case "pgsql", "postgresql", "postgres":
		d = &dialect.PgSQL{}
	case "mysql":
		d = &dialect.MySQL{}
	default:
		fmt.Fprintf(os.Stderr, "unknown dialect: %s (supported: pgsql, mysql)\n", *dialectName)
		os.Exit(1)
	}

	var output string

	if *singleTable != "" {
		path, err := findTableFile(dirs, *singleTable)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if path == "" {
			fmt.Fprintf(os.Stderr, "table %q not found in directories: %s\n", *singleTable, *inputDirs)
			os.Exit(1)
		}
		table, err := schema.ParseFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		output = d.GenerateTable(table)
	} else {
		// Generate full schema
		s, err := schema.ParseDirs(dirs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if len(s.Tables) == 0 {
			fmt.Fprintf(os.Stderr, "no tables found in: %s\n", *inputDirs)
			os.Exit(1)
		}
		// Cross-table integrity check (P1-51): catches FK targets that
		// don't resolve, PK columns missing from the column list,
		// duplicate constraint names, etc. — at parse time rather
		// than at psql-apply time. Without this call schema.Validate
		// is dead code and the v0.4.1 CHANGELOG promise of
		// parse-time validation goes unmet.
		if err := s.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "schema validation failed: %v\n", err)
			os.Exit(1)
		}
		output = d.GenerateSchema(s)

		// Append seed data if requested
		if *seedDirs != "" {
			sDirs := strings.Split(*seedDirs, ",")
			for i := range sDirs {
				sDirs[i] = strings.TrimSpace(sDirs[i])
			}
			var allSeeds []*schema.SeedFile
			for _, sd := range sDirs {
				seeds, err := schema.ParseSeedDir(sd)
				if err != nil {
					fmt.Fprintf(os.Stderr, "seed error: %v\n", err)
					os.Exit(1)
				}
				allSeeds = append(allSeeds, seeds...)
			}
			if len(allSeeds) > 0 {
				output += "\n" + schema.GenerateSeedSQL(allSeeds, s)
			}
		}
	}

	if *outputFile != "" {
		dir := filepath.Dir(*outputFile)
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "failed to create output directory: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*outputFile, []byte(output), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write output: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "wrote %s (%d tables)\n", *outputFile, strings.Count(output, "CREATE TABLE"))
	} else {
		fmt.Print(output)
	}
}

func findTableFile(dirs []string, table string) (string, error) {
	for _, dir := range dirs {
		var found string
		err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				if path != filepath.Clean(dir) && entry.Name() == "seed" {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.Name() == "ab_meta.yml" || entry.Name() == "ab_meta.yaml" {
				return nil
			}
			ext := filepath.Ext(entry.Name())
			if (ext == ".yml" || ext == ".yaml") && strings.TrimSuffix(entry.Name(), ext) == table {
				found = path
				return filepath.SkipAll
			}
			return nil
		})
		if err != nil {
			return "", fmt.Errorf("failed to search directory %s: %w", dir, err)
		}
		if found != "" {
			return found, nil
		}
	}
	return "", nil
}

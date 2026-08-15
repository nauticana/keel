package schema

import (
	_ "embed"
	"fmt"

	"github.com/nauticana/keel/config"
	"gopkg.in/yaml.v3"
)

//go:embed seed/core.yml
var coreSeedYML []byte

// ConfigDefaults returns the framework flag catalog from the embedded core
// seed as flag_id -> ConfigRow (defaults only, no assigned values) — the same
// shape config.KeelConfig.Apply consumes.
func ConfigDefaults() (config.ConfigRows, error) {
	var sf SeedFile
	if err := yaml.Unmarshal(coreSeedYML, &sf); err != nil {
		return nil, fmt.Errorf("parse embedded core seed: %w", err)
	}
	m := make(config.ConfigRows)
	for _, t := range sf.Seeds {
		if t.Table != "application_config_flag" {
			continue
		}
		idIdx, defIdx := -1, -1
		for i, c := range t.Columns {
			switch c {
			case "id":
				idIdx = i
			case "default_value":
				defIdx = i
			}
		}
		if idIdx < 0 || defIdx < 0 {
			return nil, fmt.Errorf("application_config_flag seed block lacks id/default_value columns")
		}
		for _, row := range t.Rows {
			m[fmt.Sprint(row[idIdx])] = config.ConfigRow{Default: fmt.Sprint(row[defIdx])}
		}
	}
	return m, nil
}

// LoadTestConfig publishes the embedded seed defaults so
// test binaries run against the catalog without a database. Production always
// loads from the application_config_* tables.
func LoadTestConfig() {
	m, err := ConfigDefaults()
	if err != nil {
		panic(err)
	}
	c := &config.KeelConfig{}
	if err := c.Apply(m); err != nil {
		panic(err)
	}
	config.SetConfig(c)
}

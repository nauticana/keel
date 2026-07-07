package schema

import (
	_ "embed"
	"fmt"

	"github.com/nauticana/keel/common"
	"gopkg.in/yaml.v3"
)

//go:embed basis_seed.yml
var basisSeedYML []byte

// ConfigDefaults returns the framework flag catalog from the embedded basis
// seed as flag_id -> ConfigRow (defaults only, no assigned values) — the same
// shape BaseConfig.ApplyBase consumes.
func ConfigDefaults() (map[string]common.ConfigRow, error) {
	var sf SeedFile
	if err := yaml.Unmarshal(basisSeedYML, &sf); err != nil {
		return nil, fmt.Errorf("parse embedded basis seed: %w", err)
	}
	m := make(map[string]common.ConfigRow)
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
			m[fmt.Sprint(row[idIdx])] = common.ConfigRow{Default: fmt.Sprint(row[defIdx])}
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
	cfg := &common.BaseConfig{}
	if err := cfg.ApplyBase(m); err != nil {
		panic(err)
	}
	common.SetConfig(cfg)
}

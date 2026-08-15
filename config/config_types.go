package config

// ConfigRow is one flag's resolved (assigned value, catalog default) pair.
type ConfigRow struct {
	Value   string
	Default string
}

// ConfigRows is the resolved flag catalog keyed by flag ID.
type ConfigRows map[string]ConfigRow

// ApplicationConfig is one repository's parsable section of an application config.
type ApplicationConfig interface {
	Apply(m ConfigRows) error
}

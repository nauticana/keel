package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const qNodeConfigs = "node_configs"

var acQueries = map[string]string{
	qNodeConfigs: `
SELECT a.id, COALESCE(n.assigned_value, s.assigned_value), a.default_value
  FROM application_config_flag a
  LEFT JOIN application_config_value n
    ON a.id = n.flag_id AND n.node_id = ?
  LEFT JOIN application_config_value s
    ON a.id = s.flag_id AND s.node_id = -1
`,
}

// AbstractConfig is the shared flag parser of one application config; embed it once, first.
type AbstractConfig struct {
	parseErrs []error
	missing   []string
}

// The typed readers resolve assigned value, else catalog default; missing rows
// and malformed values accumulate into ParseErr under the flag id.
func (c *AbstractConfig) String(rows ConfigRows, id string) string {
	return c.text(rows, id)
}

func (c *AbstractConfig) Int(rows ConfigRows, id string) int {
	return int(c.parseInt(rows, id, "int"))
}

func (c *AbstractConfig) Int64(rows ConfigRows, id string) int64 {
	return c.parseInt(rows, id, "int64")
}

func (c *AbstractConfig) Float(rows ConfigRows, id string) float64 {
	s := c.text(rows, id)
	if s == "" {
		return 0
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		c.parseErrs = append(c.parseErrs, fmt.Errorf("%s: malformed value %q (want float)", id, s))
	}
	return f
}

func (c *AbstractConfig) Bool(rows ConfigRows, id string) bool {
	s := strings.ToLower(c.text(rows, id))
	switch s {
	case "true", "1", "yes", "y", "on":
		return true
	case "", "false", "0", "no", "n", "off":
		return false
	}
	c.parseErrs = append(c.parseErrs, fmt.Errorf("%s: malformed value %q (want bool)", id, s))
	return false
}

// Duration reads a duration stored as whole seconds.
func (c *AbstractConfig) Duration(rows ConfigRows, id string) time.Duration {
	return time.Duration(c.parseInt(rows, id, "duration seconds")) * time.Second
}

func (c *AbstractConfig) text(rows ConfigRows, id string) string {
	r, ok := rows[id]
	if !ok {
		c.missing = append(c.missing, id)
		return ""
	}
	if v := strings.TrimSpace(r.Value); v != "" {
		return v
	}
	return strings.TrimSpace(r.Default)
}

func (c *AbstractConfig) parseInt(rows ConfigRows, id, kind string) int64 {
	s := c.text(rows, id)
	if s == "" {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		c.parseErrs = append(c.parseErrs, fmt.Errorf("%s: malformed value %q (want %s)", id, s, kind))
	}
	return n
}

// ParseErr returns and clears the accumulated missing-flag and parse failures.
func (c *AbstractConfig) ParseErr() error {
	errs := c.parseErrs
	c.parseErrs = nil
	if len(c.missing) > 0 {
		errs = append([]error{fmt.Errorf("application_config_flag catalog is missing flags: %s — re-seed", strings.Join(c.missing, ", "))}, errs...)
		c.missing = nil
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("application config: %w", errors.Join(errs...))
}

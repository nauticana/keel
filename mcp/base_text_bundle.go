package mcp

// BaseTextBundle is a map-backed TextBundle, usable as-is.
type BaseTextBundle struct {
	Instr  string
	Tools  map[string]string            // tool -> description
	Params map[string]map[string]string // tool -> param -> description
}

func (b BaseTextBundle) Instructions() string           { return b.Instr }
func (b BaseTextBundle) Tool(name string) string        { return b.Tools[name] }
func (b BaseTextBundle) Param(tool, name string) string { return b.Params[tool][name] }

var _ TextBundle = BaseTextBundle{}

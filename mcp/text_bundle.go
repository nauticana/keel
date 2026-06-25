package mcp

// TextBundle supplies the human-facing MCP copy — server instructions plus tool
// and parameter descriptions — separated from tool wiring so it can be localized
// or swapped per request. Tool/param NAMES stay in the ToolProvider; only copy
// lives here.
type TextBundle interface {
	Instructions() string
	Tool(name string) string
	Param(tool, name string) string
}

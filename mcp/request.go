package mcp

import (
	"fmt"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
)

// RequireInt reads a required integer argument. The returned result is non-nil
// (a ready-to-return tool error) when the argument is missing or zero, letting a
// handler write: id, bad := RequireInt(req, "id"); if bad != nil { return bad, nil }.
func RequireInt(req mcpgo.CallToolRequest, name string) (int64, *mcpgo.CallToolResult) {
	v := int64(req.GetInt(name, 0))
	if v == 0 {
		return 0, WrapErrorf("%s is required", name)
	}
	return v, nil
}

// RequireString reads a required, non-empty string argument; same contract as RequireInt.
func RequireString(req mcpgo.CallToolRequest, name string) (string, *mcpgo.CallToolResult) {
	v := req.GetString(name, "")
	if v == "" {
		return "", WrapErrorf("%s is required", name)
	}
	return v, nil
}

// WrapErrorf renders a formatted message as a tool-execution error (isError),
// so the model sees the failure and can self-correct.
func WrapErrorf(format string, args ...any) *mcpgo.CallToolResult {
	return mcpgo.NewToolResultError(fmt.Sprintf(format, args...))
}

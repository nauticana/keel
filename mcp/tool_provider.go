package mcp

import (
	"context"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
)

// ToolProvider is one MCP tool as an object. BaseServer.Register binds by Name(),
// so registration order needn't track a parallel handler list.
type ToolProvider interface {
	Name() string
	Definition() mcpgo.Tool
	Handle(ctx context.Context, req mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error)
}

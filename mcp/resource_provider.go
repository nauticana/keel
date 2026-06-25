package mcp

import (
	"context"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
)

// ResourceProvider is one browsable MCP resource; Read returns the payload that
// ResourceFunc JSON-marshals at URI().
type ResourceProvider interface {
	URI() string
	Definition() mcpgo.Resource
	Read(ctx context.Context) (any, error)
}

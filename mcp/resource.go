package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// ResourceFunc adapts a zero-arg domain method into an mcp-go resource handler,
// JSON-marshalling the result as application/json contents at the requested URI.
func ResourceFunc(fn func(ctx context.Context) (any, error)) server.ResourceHandlerFunc {
	return func(ctx context.Context, req mcpgo.ReadResourceRequest) ([]mcpgo.ResourceContents, error) {
		data, err := fn(ctx)
		if err != nil {
			return nil, fmt.Errorf("resource handler: %w", err)
		}
		b, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("resource marshal: %w", err)
		}
		return []mcpgo.ResourceContents{
			mcpgo.TextResourceContents{URI: req.Params.URI, MIMEType: "application/json", Text: string(b)},
		}, nil
	}
}

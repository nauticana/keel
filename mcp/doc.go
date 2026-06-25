// Package mcp is keel's MCP server layer over github.com/mark3labs/mcp-go: a
// transport wrapper (stdio / SSE / Streamable HTTP), a name-keyed tool &
// resource registry, the {data, _meta} envelope, a localizable text bundle, and
// a resource-handler adapter. Apps supply only ToolProvider/ResourceProvider
// implementations, their SQL, and their text.
//
// This package depends on mcp-go; the DTOs it projects (model.Envelope) and the
// trust-guard chain (guard.GuardChain) do not, so non-MCP surfaces can reuse them.
package mcp

package mcp

import (
	"context"
	"net/http"

	"github.com/mark3labs/mcp-go/server"

	"github.com/nauticana/keel/handler"
)

// ServerConfig carries the per-server values that must not be hardcoded in the
// library. ClientIPHook defaults to handler.WithClientIPContext when nil.
type ServerConfig struct {
	Name         string
	Version      string
	Instructions string
	Source       string
	ClientIPHook func(context.Context, *http.Request) context.Context
}

// BaseServer wraps an mcp-go server with name-keyed tool/resource registration.
type BaseServer struct {
	mcp    *server.MCPServer
	ipHook func(context.Context, *http.Request) context.Context
	source string
}

func NewServer(cfg ServerConfig) *BaseServer {
	ipHook := cfg.ClientIPHook
	if ipHook == nil {
		ipHook = handler.WithClientIPContext
	}
	return &BaseServer{
		mcp: server.NewMCPServer(
			cfg.Name,
			cfg.Version,
			server.WithToolCapabilities(true),
			server.WithResourceCapabilities(true, true),
			server.WithInstructions(cfg.Instructions),
		),
		ipHook: ipHook,
		source: cfg.Source,
	}
}

// Envelopes returns a response builder stamped with this server's Source.
func (s *BaseServer) Envelopes() Envelopes { return NewEnvelopes(s.source) }

// Register binds each tool by its Name(); registration order is irrelevant.
func (s *BaseServer) Register(tools ...ToolProvider) {
	for _, t := range tools {
		s.mcp.AddTool(t.Definition(), t.Handle)
	}
}

func (s *BaseServer) RegisterResource(resources ...ResourceProvider) {
	for _, r := range resources {
		s.mcp.AddResource(r.Definition(), ResourceFunc(r.Read))
	}
}

// MCPServer exposes the underlying mcp-go server for transport setups not
// covered by the Serve* helpers.
func (s *BaseServer) MCPServer() *server.MCPServer { return s.mcp }

func (s *BaseServer) ServeStdio() error { return server.ServeStdio(s.mcp) }

// ServeSSE builds the SSE server with the client-IP hook; pass opts (e.g.
// server.WithSSEEndpoint, server.WithMessageEndpoint) to set the transport paths.
func (s *BaseServer) ServeSSE(opts ...server.SSEOption) *server.SSEServer {
	return server.NewSSEServer(s.mcp, append([]server.SSEOption{server.WithSSEContextFunc(s.ipHook)}, opts...)...)
}

func (s *BaseServer) ServeStreamableHTTP() *server.StreamableHTTPServer {
	return server.NewStreamableHTTPServer(s.mcp, server.WithHTTPContextFunc(s.ipHook))
}

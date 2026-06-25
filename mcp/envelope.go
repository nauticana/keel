package mcp

import (
	"encoding/json"
	"time"

	mcpgo "github.com/mark3labs/mcp-go/mcp"

	"github.com/nauticana/keel/model"
)

// Envelopes builds {data, _meta} tool results with an injected Source (one per
// server, from ServerConfig) so the label isn't hardcoded in the library.
type Envelopes struct {
	Source string
	now    func() time.Time // injectable clock for tests; nil = time.Now().UTC()
}

// NewEnvelopes returns an Envelopes that stamps responses with source.
func NewEnvelopes(source string) Envelopes {
	return Envelopes{Source: source}
}

func (e Envelopes) timestamp() string {
	if e.now != nil {
		return e.now().Format(time.RFC3339)
	}
	return time.Now().UTC().Format(time.RFC3339)
}

// Wrap renders data + meta as the JSON-text tool result, defaulting GeneratedAt
// and Source when unset.
func (e Envelopes) Wrap(data any, meta *model.EnvelopeMeta) *mcpgo.CallToolResult {
	if meta == nil {
		meta = &model.EnvelopeMeta{}
	}
	if meta.GeneratedAt == "" {
		meta.GeneratedAt = e.timestamp()
	}
	if meta.Source == "" {
		meta.Source = e.Source
	}
	b, err := json.MarshalIndent(model.Envelope{Data: data, Meta: meta}, "", "  ")
	if err != nil {
		return mcpgo.NewToolResultError("failed to marshal envelope: " + err.Error())
	}
	return mcpgo.NewToolResultText(string(b))
}

// WrapWithProvenance is a single-record convenience; a nil prov renders without it.
func (e Envelopes) WrapWithProvenance(data any, prov *model.ProvenanceMeta) *mcpgo.CallToolResult {
	meta := &model.EnvelopeMeta{}
	if prov != nil {
		meta.Provenance = prov
	}
	return e.Wrap(data, meta)
}

// WrapWithPagination is the list-tool helper. total is rows on this page; the
// service supplies hasMore (the limit+1 trick).
func (e Envelopes) WrapWithPagination(data any, limit, offset, total int, hasMore bool) *mcpgo.CallToolResult {
	pag := &model.PaginationMeta{Limit: limit, Offset: offset, Total: total, HasMore: hasMore}
	if hasMore {
		pag.NextOffset = offset + limit
	}
	return e.Wrap(data, &model.EnvelopeMeta{Pagination: pag})
}

// WrapError renders a failed call as an MCP tool-execution error (so the model
// can self-correct) rather than a transport error. Source-independent.
func WrapError(err error) *mcpgo.CallToolResult {
	return mcpgo.NewToolResultErrorFromErr("tool execution failed", err)
}

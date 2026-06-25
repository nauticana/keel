package port

import (
	"context"

	"github.com/nauticana/keel/model"
)

// FieldCatalog is the schema-introspection contract behind list_fields /
// describe_field style MCP tools, letting agents discover the queryable surface
// without reading source. mcp.BaseFieldCatalog is a ready implementation (merges
// a static core set with catalog-backed rows); apps supply the descriptors.
// Transport-neutral: the MCP adapter is one consumer, an HTTP "/schema" another.
type FieldCatalog interface {
	ListFields(ctx context.Context) ([]model.FieldDescriptor, error)
	DescribeField(ctx context.Context, name string) (*model.FieldDescriptor, error)
}

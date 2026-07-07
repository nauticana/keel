package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// DescriptorProvider contributes one family of fields to a BaseFieldCatalog.
// A static family (core fields) sets Static; a catalog-backed family sets
// ListQuery + Map (and GetQuery for point lookups) and a Prefix that namespaces
// its names, e.g. "attr." / "question.". The app owns the SQL, the Prefix, and
// the row→descriptor Map; keel owns the merge and the prefix dispatch.
type DescriptorProvider struct {
	Prefix    string
	Static    []model.FieldDescriptor
	ListQuery string
	GetQuery  string                                // point lookup by stripped id; empty = scan
	Map       func(row []any) model.FieldDescriptor // required when ListQuery/GetQuery set
}

// BaseFieldCatalog is a complete port.FieldCatalog: ListFields concatenates
// every provider, DescribeField routes a prefixed name to its provider's point
// query and falls back to an exact-name scan for core/static fields.
type BaseFieldCatalog struct {
	qs        port.QueryService
	providers []DescriptorProvider
}

func NewFieldCatalog(qs port.QueryService, providers ...DescriptorProvider) *BaseFieldCatalog {
	return &BaseFieldCatalog{qs: qs, providers: providers}
}

func (c *BaseFieldCatalog) ListFields(ctx context.Context) ([]model.FieldDescriptor, error) {
	var out []model.FieldDescriptor
	for _, p := range c.providers {
		out = append(out, p.Static...)
		if p.ListQuery == "" {
			continue
		}
		res, err := c.qs.Query(ctx, p.ListQuery)
		if err != nil {
			return nil, fmt.Errorf("field catalog list %q: %w", p.ListQuery, err)
		}
		for _, row := range res.Rows {
			out = append(out, p.Map(row))
		}
	}
	return out, nil
}

func (c *BaseFieldCatalog) DescribeField(ctx context.Context, name string) (*model.FieldDescriptor, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("field name is required")
	}
	for _, p := range c.providers {
		if p.Prefix == "" || !strings.HasPrefix(name, p.Prefix) {
			continue
		}
		if p.GetQuery == "" {
			break // matched a family but no point query — fall through to scan
		}
		res, err := c.qs.Query(ctx, p.GetQuery, strings.TrimPrefix(name, p.Prefix))
		if err != nil {
			return nil, fmt.Errorf("field catalog describe %q: %w", p.GetQuery, err)
		}
		if len(res.Rows) == 0 {
			return nil, nil
		}
		fd := p.Map(res.Rows[0])
		return &fd, nil
	}
	fields, err := c.ListFields(ctx)
	if err != nil {
		return nil, err
	}
	for i := range fields {
		if fields[i].Name == name {
			return &fields[i], nil
		}
	}
	return nil, nil
}

var _ port.FieldCatalog = (*BaseFieldCatalog)(nil)

package content

import (
	"context"
	"encoding/json"
	"fmt"
)

var (
	_ ResourceCreator = (*ShopifyWriter)(nil)
	_ ResourceDeleter = (*ShopifyWriter)(nil)
)

// Create makes a new object of ref.Kind from the same logical fields
// UpdateField writes — including the ones the provider requires at creation
// (a page's title, an article's blogId and author), which the field map
// supplies as ordinary inputs typed by their ValueType. ref.ID is ignored; the returned ref carries Shopify's id.
func (w *ShopifyWriter) Create(ctx context.Context, ref ResourceRef, fields map[string]string) (ResourceRef, WriteResult, error) {
	kind, ok := shopifyKinds[ref.Kind]
	if !ok {
		return ResourceRef{}, WriteResult{}, fmt.Errorf("%w: %q", ErrUnsupportedKind, ref.Kind)
	}
	if len(fields) == 0 {
		return ResourceRef{}, WriteResult{}, fmt.Errorf("%w: creating a %s needs at least one field", ErrRejected, ref.Kind)
	}
	input, err := w.createInput(ref.Kind, fields)
	if err != nil {
		return ResourceRef{}, WriteResult{}, err
	}
	query := fmt.Sprintf(`mutation($in:%s!){%s(%s:$in){%s{id} userErrors{field message}}}`,
		kind.createInputType, kind.createMutation, kind.createInputArg, kind.root)
	payload, result, err := shopifyMutate(ctx, ref, kind.createMutation, query, map[string]any{"in": input})
	if err != nil {
		return ResourceRef{}, WriteResult{}, err
	}
	var created struct {
		ID string `json:"id"`
	}
	if raw, ok := payload[kind.root]; ok {
		if err := json.Unmarshal(raw, &created); err != nil {
			return ResourceRef{}, result, fmt.Errorf("decode created shopify %s: %w", ref.Kind, err)
		}
	}
	if created.ID == "" {
		return ResourceRef{}, result, fmt.Errorf("%w: shopify %s returned no id", ErrRejected, kind.createMutation)
	}
	ref.ID = created.ID
	return ref, result, nil
}

// createInput maps logical fields onto the provider's create input. A metafield
// rides the input's metafields list — the owner id it would otherwise need does
// not exist yet.
func (w *ShopifyWriter) createInput(kind string, fields map[string]string) (map[string]any, error) {
	input := map[string]any{}
	seo := map[string]any{}
	var metafields []map[string]any
	for field, value := range fields {
		target, ok := w.fields[kind][field]
		if !ok {
			return nil, fmt.Errorf("%w: %q on %s", ErrUnsupportedField, field, kind)
		}
		switch {
		case target.Metafield != nil:
			metafields = append(metafields, map[string]any{
				"namespace": target.Metafield.Namespace, "key": target.Metafield.Key,
				"type": target.Metafield.Type, "value": value,
			})
		case target.SEO != "":
			seo[target.SEO] = value
		default:
			v, err := target.inputValue(field, value)
			if err != nil {
				return nil, err
			}
			input[target.Input] = v
		}
	}
	if len(seo) > 0 {
		input["seo"] = seo
	}
	if len(metafields) > 0 {
		input["metafields"] = metafields
	}
	return input, nil
}

// Delete removes the object. Shopify takes the id as its own argument on some
// kinds and inside a delete input on others.
func (w *ShopifyWriter) Delete(ctx context.Context, ref ResourceRef) (WriteResult, error) {
	kind, ok := shopifyKinds[ref.Kind]
	if !ok {
		return WriteResult{}, fmt.Errorf("%w: %q", ErrUnsupportedKind, ref.Kind)
	}
	if ref.ID == "" {
		return WriteResult{}, fmt.Errorf("%w: deleting a %s needs an id", ErrRejected, ref.Kind)
	}
	var (
		query string
		vars  map[string]any
	)
	if kind.deleteInputType == "" {
		query = fmt.Sprintf(`mutation($id:ID!){%s(id:$id){userErrors{field message}}}`, kind.deleteMutation)
		vars = map[string]any{"id": ref.ID}
	} else {
		query = fmt.Sprintf(`mutation($in:%s!){%s(%s:$in){userErrors{field message}}}`,
			kind.deleteInputType, kind.deleteMutation, kind.deleteInputArg)
		vars = map[string]any{"in": map[string]any{"id": ref.ID}}
	}
	_, result, err := shopifyMutate(ctx, ref, kind.deleteMutation, query, vars)
	return result, err
}

package content

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/nauticana/keel/common"
)

// Shopify resource kinds the writer can address.
const (
	ShopifyPage       = "page"
	ShopifyArticle    = "article"
	ShopifyProduct    = "product"
	ShopifyCollection = "collection"
)

// ShopifyMetafield addresses one metafield; Type is the Shopify metafield type
// sent on write (e.g. "single_line_text_field").
type ShopifyMetafield struct {
	Namespace string
	Key       string
	Type      string
}

// ShopifyTarget says where a logical field lives on a Shopify object. Exactly
// one member is set.
type ShopifyTarget struct {
	Input     string // field on the object and its update input, e.g. "descriptionHtml"
	SEO       string // "title" or "description" of the object's seo member
	Metafield *ShopifyMetafield
}

// ShopifyFieldMap is kind → logical field → target.
type ShopifyFieldMap map[string]map[string]ShopifyTarget

type shopifyKind struct {
	root      string
	mutation  string
	inputType string
	inputArg  string
	idInInput bool
}

var shopifyKinds = map[string]shopifyKind{
	ShopifyPage:       {"page", "pageUpdate", "PageUpdateInput", "page", false},
	ShopifyArticle:    {"article", "articleUpdate", "ArticleUpdateInput", "article", false},
	ShopifyProduct:    {"product", "productUpdate", "ProductUpdateInput", "product", true},
	ShopifyCollection: {"collection", "collectionUpdate", "CollectionInput", "input", true},
}

var graphQLName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ShopifyWriter edits Shopify objects over the Admin GraphQL API. The API
// version is part of ResourceRef.Endpoint.
type ShopifyWriter struct {
	fields ShopifyFieldMap
}

var _ ResourceWriter = (*ShopifyWriter)(nil)

func NewShopifyWriter(fields ShopifyFieldMap) (*ShopifyWriter, error) {
	fieldCopy := make(ShopifyFieldMap, len(fields))
	for kind, byField := range fields {
		if _, ok := shopifyKinds[kind]; !ok {
			return nil, fmt.Errorf("shopify field map: %w %q", ErrUnsupportedKind, kind)
		}
		fieldCopy[kind] = make(map[string]ShopifyTarget, len(byField))
		for field, target := range byField {
			if field == "" {
				return nil, fmt.Errorf("shopify field map %s: empty logical field", kind)
			}
			if err := target.validate(); err != nil {
				return nil, fmt.Errorf("shopify field map %s.%s: %w", kind, field, err)
			}
			if target.Metafield != nil {
				metafield := *target.Metafield
				target.Metafield = &metafield
			}
			fieldCopy[kind][field] = target
		}
	}
	return &ShopifyWriter{fields: fieldCopy}, nil
}

func (t ShopifyTarget) validate() error {
	set := 0
	if t.Input != "" {
		set++
		if !graphQLName.MatchString(t.Input) {
			return fmt.Errorf("input %q is not a GraphQL name", t.Input)
		}
	}
	if t.SEO != "" {
		set++
		if t.SEO != "title" && t.SEO != "description" {
			return fmt.Errorf("seo member %q must be title or description", t.SEO)
		}
	}
	if t.Metafield != nil {
		set++
		if t.Metafield.Namespace == "" || t.Metafield.Key == "" || t.Metafield.Type == "" {
			return errors.New("metafield needs namespace, key and type")
		}
	}
	if set != 1 {
		return errors.New("exactly one of Input, SEO, Metafield must be set")
	}
	return nil
}

func (w *ShopifyWriter) target(ref ResourceRef, field string) (shopifyKind, ShopifyTarget, error) {
	kind, ok := shopifyKinds[ref.Kind]
	if !ok {
		return shopifyKind{}, ShopifyTarget{}, fmt.Errorf("%w: %q", ErrUnsupportedKind, ref.Kind)
	}
	target, ok := w.fields[ref.Kind][field]
	if !ok {
		return shopifyKind{}, ShopifyTarget{}, fmt.Errorf("%w: %q on %s", ErrUnsupportedField, field, ref.Kind)
	}
	return kind, target, nil
}

type shopifySEO struct {
	Title       *string `json:"title"`
	Description *string `json:"description"`
}

type shopifyFieldValue struct {
	Value     *string    `json:"value"`
	SEO       shopifySEO `json:"seo"`
	Metafield *struct {
		Value string `json:"value"`
	} `json:"metafield"`
}

func (w *ShopifyWriter) ReadField(ctx context.Context, ref ResourceRef, field string) (string, error) {
	kind, target, err := w.target(ref, field)
	if err != nil {
		return "", err
	}
	got, err := w.read(ctx, ref, kind, target)
	if err != nil {
		return "", err
	}
	switch {
	case target.Metafield != nil:
		if got.Metafield == nil {
			return "", nil
		}
		return got.Metafield.Value, nil
	case target.SEO == "title":
		return deref(got.SEO.Title), nil
	case target.SEO == "description":
		return deref(got.SEO.Description), nil
	}
	return deref(got.Value), nil
}

func (w *ShopifyWriter) read(ctx context.Context, ref ResourceRef, kind shopifyKind, target ShopifyTarget) (*shopifyFieldValue, error) {
	vars := map[string]any{"id": ref.ID}
	params, selection := "$id:ID!", "value: "+target.Input
	switch {
	case target.Metafield != nil:
		params += ",$ns:String!,$key:String!"
		selection = "metafield(namespace:$ns,key:$key){value}"
		vars["ns"], vars["key"] = target.Metafield.Namespace, target.Metafield.Key
	case target.SEO != "":
		selection = "seo{title description}"
	}
	query := fmt.Sprintf("query(%s){%s(id:$id){%s}}", params, kind.root, selection)
	var data map[string]*shopifyFieldValue
	if _, err := w.graphql(ctx, ref, query, vars, &data); err != nil {
		return nil, err
	}
	if data[kind.root] == nil {
		return nil, fmt.Errorf("%w: %s %s", ErrResourceNotFound, ref.Kind, ref.ID)
	}
	return data[kind.root], nil
}

func (w *ShopifyWriter) UpdateField(ctx context.Context, ref ResourceRef, field, value string) (WriteResult, error) {
	kind, target, err := w.target(ref, field)
	if err != nil {
		return WriteResult{}, err
	}
	if mf := target.Metafield; mf != nil {
		return w.mutate(ctx, ref, "metafieldsSet",
			`mutation($metafields:[MetafieldsSetInput!]!){metafieldsSet(metafields:$metafields){userErrors{field message}}}`,
			map[string]any{"metafields": []map[string]any{{
				"ownerId": ref.ID, "namespace": mf.Namespace, "key": mf.Key, "type": mf.Type, "value": value,
			}}})
	}
	input := map[string]any{}
	if target.SEO != "" {
		// SEOInput replaces the whole seo object, so the sibling is read and resent.
		current, err := w.read(ctx, ref, kind, target)
		if err != nil {
			return WriteResult{}, err
		}
		seo := map[string]any{"title": deref(current.SEO.Title), "description": deref(current.SEO.Description)}
		seo[target.SEO] = value
		input["seo"] = seo
	} else {
		input[target.Input] = value
	}
	vars := map[string]any{"in": input}
	var query string
	if kind.idInInput {
		input["id"] = ref.ID
		query = fmt.Sprintf(`mutation($in:%s!){%s(%s:$in){userErrors{field message}}}`, kind.inputType, kind.mutation, kind.inputArg)
	} else {
		vars["id"] = ref.ID
		query = fmt.Sprintf(`mutation($id:ID!,$in:%s!){%s(id:$id,%s:$in){userErrors{field message}}}`, kind.inputType, kind.mutation, kind.inputArg)
	}
	return w.mutate(ctx, ref, kind.mutation, query, vars)
}

func (w *ShopifyWriter) mutate(ctx context.Context, ref ResourceRef, root, query string, vars map[string]any) (WriteResult, error) {
	var data map[string]*struct {
		UserErrors []struct {
			Field   []string `json:"field"`
			Message string   `json:"message"`
		} `json:"userErrors"`
	}
	raw, err := w.graphql(ctx, ref, query, vars, &data)
	if err != nil {
		return WriteResult{}, err
	}
	result := data[root]
	if result == nil {
		return WriteResult{}, fmt.Errorf("%w: shopify %s returned no result", ErrRejected, root)
	}
	if errs := result.UserErrors; len(errs) > 0 {
		msgs := make([]string, 0, len(errs))
		for _, e := range errs {
			msgs = append(msgs, strings.TrimSpace(strings.Join(e.Field, ".")+": "+e.Message))
		}
		return WriteResult{}, fmt.Errorf("%w: shopify %s: %s", ErrRejected, root, strings.Join(msgs, "; "))
	}
	return WriteResult{Response: string(raw)}, nil
}

// graphql checks the errors array explicitly: GraphQL answers 200 on query errors.
func (w *ShopifyWriter) graphql(ctx context.Context, ref ResourceRef, query string, vars map[string]any, out any) ([]byte, error) {
	raw, _, err := common.RequestJSON(ctx, http.MethodPost, strings.TrimRight(ref.Endpoint, "/")+"/graphql.json",
		map[string]string{"X-Shopify-Access-Token": ref.Token},
		map[string]any{"query": query, "variables": vars})
	if err != nil {
		var status *common.HTTPStatusError
		if errors.As(err, &status) {
			switch {
			case status.Unauthorized():
				return nil, fmt.Errorf("%w: %w", ErrAccessDenied, err)
			case status.RateLimited():
				return nil, fmt.Errorf("%w: %w", ErrThrottled, err)
			}
		}
		return nil, err
	}
	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message    string `json:"message"`
			Extensions struct {
				Code string `json:"code"`
			} `json:"extensions"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("decode shopify response: %w", err)
	}
	if len(env.Errors) > 0 {
		kind := ErrRejected
		for _, e := range env.Errors {
			switch e.Extensions.Code {
			case "ACCESS_DENIED":
				kind = ErrAccessDenied
			case "THROTTLED":
				if kind == ErrRejected {
					kind = ErrThrottled
				}
			}
		}
		return nil, fmt.Errorf("%w: shopify graphql: %s", kind, env.Errors[0].Message)
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return nil, fmt.Errorf("decode shopify data: %w", err)
	}
	return raw, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

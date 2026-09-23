package content

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
)

var (
	_ MediaLister    = (*ShopifyWriter)(nil)
	_ MediaAnnotator = (*ShopifyWriter)(nil)
)

// Shopify caps a product at 250 media, so one page normally holds them all.
const shopifyMediaPage = 250

// ListImages lists a product's gallery images; video and 3D media are skipped.
// Other kinds carry at most a featured image, which is a field — map it as
// ValueJSON with a Selection instead.
func (w *ShopifyWriter) ListImages(ctx context.Context, ref ResourceRef) ([]ResourceImage, error) {
	if ref.Kind != ShopifyProduct {
		return nil, fmt.Errorf("%w: %q has no image gallery", ErrUnsupportedKind, ref.Kind)
	}
	const query = `query($id:ID!,$first:Int!,$after:String){product(id:$id){media(first:$first,after:$after){` +
		`pageInfo{hasNextPage endCursor} nodes{... on MediaImage{id alt image{url}}}}}}`
	var images []ResourceImage
	vars := map[string]any{"id": ref.ID, "first": shopifyMediaPage}
	for {
		var data struct {
			Product *struct {
				Media struct {
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
					Nodes []struct {
						ID    string `json:"id"`
						Alt   string `json:"alt"`
						Image *struct {
							URL string `json:"url"`
						} `json:"image"`
					} `json:"nodes"`
				} `json:"media"`
			} `json:"product"`
		}
		if _, err := shopifyGraphQL(ctx, ref, query, vars, &data); err != nil {
			return nil, err
		}
		if data.Product == nil {
			return nil, fmt.Errorf("%w: %s %s", ErrResourceNotFound, ref.Kind, ref.ID)
		}
		for _, node := range data.Product.Media.Nodes {
			if node.ID == "" {
				continue
			}
			image := ResourceImage{ID: node.ID, Alt: node.Alt}
			if node.Image != nil {
				image.URL = node.Image.URL
			}
			images = append(images, image)
		}
		page := data.Product.Media.PageInfo
		if !page.HasNextPage || page.EndCursor == "" {
			return images, nil
		}
		vars["after"] = page.EndCursor
	}
}

// SetImageAlt confirms the image is one of the product's own before writing,
// since fileUpdate would otherwise accept any file in the shop.
func (w *ShopifyWriter) SetImageAlt(ctx context.Context, ref ResourceRef, imageID, alt string) (WriteResult, error) {
	if imageID == "" {
		return WriteResult{}, fmt.Errorf("%w: setting alt text needs an image id", ErrRejected)
	}
	images, err := w.ListImages(ctx, ref)
	if err != nil {
		return WriteResult{}, err
	}
	if !slices.ContainsFunc(images, func(image ResourceImage) bool { return image.ID == imageID }) {
		return WriteResult{}, fmt.Errorf("%w: image %s on %s %s", ErrResourceNotFound, imageID, ref.Kind, ref.ID)
	}
	const mutation = `mutation($files:[FileUpdateInput!]!){fileUpdate(files:$files){files{id} userErrors{field message}}}`
	payload, result, err := shopifyMutate(ctx, ref, "fileUpdate", mutation, map[string]any{
		"files": []map[string]any{{"id": imageID, "alt": alt}},
	})
	if err != nil {
		return WriteResult{}, err
	}
	var files []struct {
		ID string `json:"id"`
	}
	if raw, ok := payload["files"]; ok {
		if err := json.Unmarshal(raw, &files); err != nil {
			return result, fmt.Errorf("decode shopify fileUpdate: %w", err)
		}
	}
	if len(files) == 0 {
		return result, fmt.Errorf("%w: shopify fileUpdate updated no file", ErrRejected)
	}
	return result, nil
}

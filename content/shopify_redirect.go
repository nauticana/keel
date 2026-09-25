package content

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

var _ RedirectLister = (*ShopifyWriter)(nil)

// Products and collections are live through the Online Store publication;
// pages and articles carry their own isPublished.
const shopifyPublicationSelection = `resourcePublications(first:250,onlyPublished:false){nodes{isPublished publication{id name catalog{title}}}}`

var shopifyLiveSelection = map[string]string{
	ShopifyPage:       "isPublished",
	ShopifyArticle:    "isPublished blog{handle}",
	ShopifyProduct:    "status " + shopifyPublicationSelection,
	ShopifyCollection: shopifyPublicationSelection,
}

// Shopify caps a page of a connection at 250 nodes.
const shopifyRedirectPage = 250

type shopifyLiveState struct {
	path          string
	live          bool
	restorable    bool
	publicationID string
	redirect      *Redirect
}

type shopifyPublicationState struct {
	IsPublished bool `json:"isPublished"`
	Publication struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Catalog *struct {
			Title string `json:"title"`
		} `json:"catalog"`
	} `json:"publication"`
}

func (w *ShopifyWriter) liveState(ctx context.Context, ref ResourceRef, kind shopifyKind) (shopifyLiveState, error) {
	query := fmt.Sprintf("query($id:ID!){%s(id:$id){handle %s}}", kind.root, shopifyLiveSelection[ref.Kind])
	var data map[string]*struct {
		Handle      string `json:"handle"`
		IsPublished bool   `json:"isPublished"`
		Status      string `json:"status"`
		Blog        *struct {
			Handle string `json:"handle"`
		} `json:"blog"`
		ResourcePublications struct {
			Nodes []shopifyPublicationState `json:"nodes"`
		} `json:"resourcePublications"`
	}
	if _, err := shopifyGraphQL(ctx, ref, query, map[string]any{"id": ref.ID}, &data); err != nil {
		return shopifyLiveState{}, err
	}
	object := data[kind.root]
	if object == nil {
		return shopifyLiveState{}, fmt.Errorf("%w: %s %s", ErrResourceNotFound, ref.Kind, ref.ID)
	}
	state := shopifyLiveState{restorable: true}
	switch ref.Kind {
	case ShopifyPage:
		state.path, state.live = "/pages/"+object.Handle, object.IsPublished
	case ShopifyArticle:
		if object.Blog == nil {
			return shopifyLiveState{}, fmt.Errorf("%w: article %s has no blog", ErrResourceNotFound, ref.ID)
		}
		state.path, state.live = "/blogs/"+object.Blog.Handle+"/"+object.Handle, object.IsPublished
	case ShopifyProduct:
		state.path = "/products/" + object.Handle
		state.live, state.publicationID = onlineStorePublication(object.ResourcePublications.Nodes)
		state.restorable = object.Status == "ACTIVE"
		state.live = state.live && state.restorable
	case ShopifyCollection:
		state.path = "/collections/" + object.Handle
		state.live, state.publicationID = onlineStorePublication(object.ResourcePublications.Nodes)
	}
	redirect, err := w.findRedirect(ctx, ref, state.path)
	if err != nil {
		return shopifyLiveState{}, err
	}
	state.redirect = redirect
	return state, nil
}

func onlineStorePublication(nodes []shopifyPublicationState) (bool, string) {
	for _, node := range nodes {
		catalogTitle := ""
		if node.Publication.Catalog != nil {
			catalogTitle = node.Publication.Catalog.Title
		}
		if isOnlineStoreName(node.Publication.Name) || isOnlineStoreName(catalogTitle) {
			return node.IsPublished, node.Publication.ID
		}
	}
	return false, ""
}

func isOnlineStoreName(value string) bool {
	normalized := strings.TrimSpace(strings.NewReplacer("-", " ", "_", " ").Replace(strings.ToLower(value)))
	return normalized == "online store" || strings.HasSuffix(normalized, " for online store")
}

func (w *ShopifyWriter) readRedirect(ctx context.Context, ref ResourceRef, kind shopifyKind) (string, error) {
	state, err := w.liveState(ctx, ref, kind)
	if err != nil || state.live || state.redirect == nil {
		return "", err
	}
	return state.redirect.Target, nil
}

// updateRedirect points the object's path at target and takes the object off
// the storefront; target "" reverses both. An object that is already off the
// storefront with no redirect is refused, since clearing the redirect again
// would publish something that was never live.
func (w *ShopifyWriter) updateRedirect(ctx context.Context, ref ResourceRef, kind shopifyKind, target string) (WriteResult, error) {
	state, err := w.liveState(ctx, ref, kind)
	if err != nil {
		return WriteResult{}, err
	}
	var responses []string
	record := func(res WriteResult, err error) error {
		responses = append(responses, res.Response)
		return err
	}
	if target == "" {
		if state.redirect == nil {
			return WriteResult{}, nil
		}
		if !state.live {
			if !state.restorable {
				return WriteResult{}, fmt.Errorf("%w: %s %s was not active before restore", ErrRejected, ref.Kind, ref.ID)
			}
			if err := record(w.setLive(ctx, ref, kind, state, true)); err != nil {
				return WriteResult{}, err
			}
		}
		const mutation = `mutation($id:ID!){urlRedirectDelete(id:$id){deletedUrlRedirectId userErrors{field message}}}`
		err := record(w.mutate(ctx, ref, "urlRedirectDelete", mutation, map[string]any{"id": state.redirect.ID}))
		return WriteResult{Response: strings.Join(responses, "\n")}, err
	}
	if !state.live && state.redirect == nil {
		return WriteResult{}, fmt.Errorf("%w: %s %s is not live, so there is nothing to retire", ErrRejected, ref.Kind, ref.ID)
	}
	redirect := map[string]any{"path": state.path, "target": target}
	if state.redirect == nil {
		const mutation = `mutation($r:UrlRedirectInput!){urlRedirectCreate(urlRedirect:$r){urlRedirect{id} userErrors{field message}}}`
		err = record(w.mutate(ctx, ref, "urlRedirectCreate", mutation, map[string]any{"r": redirect}))
	} else {
		const mutation = `mutation($id:ID!,$r:UrlRedirectInput!){urlRedirectUpdate(id:$id,urlRedirect:$r){urlRedirect{id} userErrors{field message}}}`
		err = record(w.mutate(ctx, ref, "urlRedirectUpdate", mutation, map[string]any{"id": state.redirect.ID, "r": redirect}))
	}
	if err == nil && state.live {
		err = record(w.setLive(ctx, ref, kind, state, false))
	}
	if err != nil {
		return WriteResult{}, err
	}
	return WriteResult{Response: strings.Join(responses, "\n")}, nil
}

func (w *ShopifyWriter) setLive(ctx context.Context, ref ResourceRef, kind shopifyKind, state shopifyLiveState, live bool) (WriteResult, error) {
	if ref.Kind == ShopifyPage || ref.Kind == ShopifyArticle {
		return w.update(ctx, ref, kind, map[string]any{"isPublished": live})
	}
	if state.publicationID == "" {
		return WriteResult{}, fmt.Errorf("%w: online store publication not found for %s %s", ErrRejected, ref.Kind, ref.ID)
	}
	root := "publishableUnpublish"
	if live {
		root = "publishablePublish"
	}
	query := fmt.Sprintf(`mutation($id:ID!,$input:[PublicationInput!]!){%s(id:$id,input:$input){userErrors{field message}}}`, root)
	return w.mutate(ctx, ref, root, query, map[string]any{
		"id": ref.ID, "input": []map[string]any{{"publicationId": state.publicationID}},
	})
}

// findRedirect matches path exactly; the search filter only narrows the list.
func (w *ShopifyWriter) findRedirect(ctx context.Context, ref ResourceRef, path string) (*Redirect, error) {
	redirects, err := listShopifyRedirects(ctx, ref, "path:"+strconv.Quote(path))
	if err != nil {
		return nil, err
	}
	for _, redirect := range redirects {
		if redirect.Path == path {
			return &redirect, nil
		}
	}
	return nil, nil
}

func (w *ShopifyWriter) ListRedirects(ctx context.Context, ref ResourceRef) ([]Redirect, error) {
	return listShopifyRedirects(ctx, ref, "")
}

func listShopifyRedirects(ctx context.Context, ref ResourceRef, search string) ([]Redirect, error) {
	const query = `query($first:Int!,$after:String,$q:String){urlRedirects(first:$first,after:$after,query:$q){` +
		`pageInfo{hasNextPage endCursor} nodes{id path target}}}`
	vars := map[string]any{"first": shopifyRedirectPage}
	if search != "" {
		vars["q"] = search
	}
	var redirects []Redirect
	for {
		var data struct {
			URLRedirects struct {
				PageInfo struct {
					HasNextPage bool   `json:"hasNextPage"`
					EndCursor   string `json:"endCursor"`
				} `json:"pageInfo"`
				Nodes []Redirect `json:"nodes"`
			} `json:"urlRedirects"`
		}
		if _, err := shopifyGraphQL(ctx, ref, query, vars, &data); err != nil {
			return nil, err
		}
		redirects = append(redirects, data.URLRedirects.Nodes...)
		page := data.URLRedirects.PageInfo
		if !page.HasNextPage || page.EndCursor == "" {
			return redirects, nil
		}
		vars["after"] = page.EndCursor
	}
}

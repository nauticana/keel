package meta

import (
	"context"
	"net/url"
)

// Page is a Page the grant manages, with the Page's own access token, which
// reads its leads. String omits the token so a logged Page does not leak it.
type Page struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	AccessToken string `json:"access_token"`
}

func (p Page) String() string { return "meta.Page{ID:" + p.ID + " Name:" + p.Name + "}" }

// Pages lists the Pages the user token manages.
func (c *Client) Pages(ctx context.Context, token string) ([]Page, error) {
	return list[Page](ctx, c, "pages", token, "/me/accounts", url.Values{"fields": {"id,name,access_token"}})
}

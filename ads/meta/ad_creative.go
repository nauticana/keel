package meta

import (
	"context"
	"net/url"
)

// AdCreative is the copy an ad runs now: Body is the primary text.
type AdCreative struct {
	ID    string `json:"id"`
	Body  string `json:"body"`
	Title string `json:"title"`
}

// AdCreative reads the creative of one ad.
func (c *Client) AdCreative(ctx context.Context, token, adID string) (AdCreative, error) {
	id, err := graphID("ad", adID)
	if err != nil {
		return AdCreative{}, err
	}
	var resp struct {
		Creative AdCreative `json:"creative"`
	}
	if err := c.object(ctx, "ad creative", token, "/"+id, url.Values{"fields": {"creative{id,body,title}"}}, &resp); err != nil {
		return AdCreative{}, err
	}
	return resp.Creative, nil
}

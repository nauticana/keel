package meta

import (
	"context"
	"net/url"
)

// LeadForm is one Instant Form of a Page; Status is "ACTIVE", "ARCHIVED", ….
type LeadForm struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// LeadForms lists a Page's Instant Forms with the Page's token.
func (c *Client) LeadForms(ctx context.Context, pageToken, pageID string) ([]LeadForm, error) {
	id, err := graphID("page", pageID)
	if err != nil {
		return nil, err
	}
	return list[LeadForm](ctx, c, "lead forms", pageToken, "/"+id+"/leadgen_forms", url.Values{"fields": {"id,name,status"}})
}

package meta

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const leadTimeLayout = "2006-01-02T15:04:05-0700"

// Lead is one Instant Form submission. CreatedAt is parsed from CreatedTime.
type Lead struct {
	ID           string      `json:"id"`
	FormID       string      `json:"form_id"`
	CreatedTime  string      `json:"created_time"`
	CreatedAt    time.Time   `json:"-"`
	CampaignID   string      `json:"campaign_id"`
	CampaignName string      `json:"campaign_name"`
	AdsetID      string      `json:"adset_id"`
	AdID         string      `json:"ad_id"`
	IsOrganic    bool        `json:"is_organic"`
	FieldData    []LeadField `json:"field_data"`
}

// LeadField is one answered question; Name is the form's key, such as
// "email", "full_name" or "phone_number".
type LeadField struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// Field returns the trimmed first answer to the named question, matched
// without regard to case, or "".
func (l Lead) Field(name string) string {
	for _, f := range l.FieldData {
		if strings.EqualFold(f.Name, name) && len(f.Values) > 0 {
			return strings.TrimSpace(f.Values[0])
		}
	}
	return ""
}

// Leads reads a form's leads with the Page's token, only those created after
// since unless since is zero.
func (c *Client) Leads(ctx context.Context, pageToken, formID string, since time.Time) ([]Lead, error) {
	id, err := graphID("lead form", formID)
	if err != nil {
		return nil, err
	}
	params := url.Values{"fields": {"id,form_id,created_time,campaign_id,campaign_name,adset_id,ad_id,is_organic,field_data"}}
	if !since.IsZero() {
		filter, err := json.Marshal([]map[string]any{{"field": "time_created", "operator": "GREATER_THAN", "value": since.Unix()}})
		if err != nil {
			return nil, err
		}
		params.Set("filtering", string(filter))
	}
	leads, err := list[Lead](ctx, c, "leads", pageToken, "/"+id+"/leads", params)
	if err != nil {
		return nil, err
	}
	for i := range leads {
		l := &leads[i]
		if l.CreatedAt, err = time.Parse(leadTimeLayout, l.CreatedTime); err != nil {
			return nil, fmt.Errorf("meta: lead %s created_time %q: %w", l.ID, l.CreatedTime, err)
		}
		if l.FormID == "" {
			l.FormID = id
		}
	}
	return leads, nil
}

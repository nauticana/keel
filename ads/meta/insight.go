package meta

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const insightFields = "campaign_id,campaign_name,adset_id,adset_name,ad_id,ad_name,date_start,date_stop," +
	"spend,impressions,clicks,reach,frequency,actions,action_values"

// Insight is one insights row. Spend and ActionValue.Value are decimal
// strings in the account currency, as Graph sends them; convert with
// common.ParseMinorUnits, never through a float. Frequency is a ratio string.
type Insight struct {
	CampaignID   string        `json:"campaign_id"`
	CampaignName string        `json:"campaign_name"`
	AdsetID      string        `json:"adset_id"`
	AdsetName    string        `json:"adset_name"`
	AdID         string        `json:"ad_id"`
	AdName       string        `json:"ad_name"`
	DateStart    string        `json:"date_start"` // YYYY-MM-DD
	DateStop     string        `json:"date_stop"`
	Spend        string        `json:"spend"`
	Impressions  int64         `json:"impressions,string"`
	Clicks       int64         `json:"clicks,string"`
	Reach        int64         `json:"reach,string"`
	Frequency    string        `json:"frequency"`
	Actions      []ActionValue `json:"actions"`
	ActionValues []ActionValue `json:"action_values"`
}

// ActionValue is one action_type entry of actions (a count) or action_values
// (a decimal amount).
type ActionValue struct {
	ActionType string `json:"action_type"`
	Value      string `json:"value"`
}

// InsightsQuery selects the window: DatePreset (such as "last_7d"), or Since
// and Until as whole days in UTC. Level is "account", "campaign", "adset" or
// "ad"; Daily splits rows per day.
type InsightsQuery struct {
	Level      string
	DatePreset string
	Since      time.Time
	Until      time.Time
	Daily      bool
}

// Insights reads an ad account's insights. accountID may carry "act_".
func (c *Client) Insights(ctx context.Context, token, accountID string, q InsightsQuery) ([]Insight, error) {
	id, err := graphID("ad account", strings.TrimPrefix(strings.TrimSpace(accountID), "act_"))
	if err != nil {
		return nil, err
	}
	params := url.Values{"fields": {insightFields}}
	switch q.Level {
	case "account", "campaign", "adset", "ad":
		params.Set("level", q.Level)
	default:
		return nil, fmt.Errorf("%w: level %q", ErrInvalidQuery, q.Level)
	}
	hasRange := !q.Since.IsZero() || !q.Until.IsZero()
	switch {
	case q.DatePreset != "" && hasRange:
		return nil, fmt.Errorf("%w: both a date preset and a time range", ErrInvalidQuery)
	case q.DatePreset != "":
		params.Set("date_preset", q.DatePreset)
	case q.Since.IsZero() || q.Until.IsZero() || q.Until.Before(q.Since):
		return nil, fmt.Errorf("%w: need a date preset or since <= until", ErrInvalidQuery)
	default:
		timeRange, err := json.Marshal(map[string]string{
			"since": q.Since.UTC().Format(time.DateOnly), "until": q.Until.UTC().Format(time.DateOnly)})
		if err != nil {
			return nil, err
		}
		params.Set("time_range", string(timeRange))
	}
	if q.Daily {
		params.Set("time_increment", "1")
	}
	return list[Insight](ctx, c, "insights", token, "/act_"+id+"/insights", params)
}

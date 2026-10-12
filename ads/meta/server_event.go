package meta

import "encoding/json"

// Event is one Conversions API server event. EventTime is Unix seconds.
// EventID lets Meta deduplicate a resent event.
type Event struct {
	EventName      string      `json:"event_name"`
	EventTime      int64       `json:"event_time"`
	EventID        string      `json:"event_id,omitempty"`
	ActionSource   string      `json:"action_source"`
	EventSourceURL string      `json:"event_source_url,omitempty"`
	UserData       UserData    `json:"user_data"`
	CustomData     *CustomData `json:"custom_data,omitempty"`
}

// UserData carries the match keys. Email and Phone hold HashEmail and
// HashPhone digests; ClickID is the fbc value (see ClickID).
type UserData struct {
	Email           []string `json:"em,omitempty"`
	Phone           []string `json:"ph,omitempty"`
	ExternalID      []string `json:"external_id,omitempty"`
	LeadID          int64    `json:"lead_id,omitempty"`
	ClickID         string   `json:"fbc,omitempty"`
	BrowserID       string   `json:"fbp,omitempty"`
	ClientIPAddress string   `json:"client_ip_address,omitempty"`
	ClientUserAgent string   `json:"client_user_agent,omitempty"`
}

func (u UserData) empty() bool {
	return len(u.Email) == 0 && len(u.Phone) == 0 && len(u.ExternalID) == 0 && u.LeadID == 0 &&
		u.ClickID == "" && u.BrowserID == "" && u.ClientIPAddress == ""
}

// CustomData carries the value as a decimal string written as a JSON number
// (common.FormatMinorUnits renders one from minor units); never a float.
type CustomData struct {
	Value    json.Number `json:"value,omitempty"`
	Currency string      `json:"currency,omitempty"`
	OrderID  string      `json:"order_id,omitempty"`
}

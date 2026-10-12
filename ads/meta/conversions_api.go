package meta

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// MaxEventsPerRequest is the Conversions API's limit on events in one request.
const MaxEventsPerRequest = 1000

// EventsResult is the Conversions API acknowledgement.
type EventsResult struct {
	EventsReceived int      `json:"events_received"`
	Messages       []string `json:"messages"`
	TraceID        string   `json:"fbtrace_id"`
}

// SendEvents posts events to a dataset (pixel) through the Conversions API.
// A response that acknowledges fewer events than were sent returns the result
// with ErrEventsNotReceived.
func (c *Client) SendEvents(ctx context.Context, token, datasetID string, events []Event) (EventsResult, error) {
	id, err := graphID("dataset", datasetID)
	if err != nil {
		return EventsResult{}, err
	}
	switch {
	case len(events) == 0:
		return EventsResult{}, ErrNoEvents
	case len(events) > MaxEventsPerRequest:
		return EventsResult{}, ErrTooManyEvents
	}
	for i, e := range events {
		if e.EventName == "" || e.EventTime <= 0 || e.ActionSource == "" || e.UserData.empty() {
			return EventsResult{}, fmt.Errorf("%w: event %d needs a name, time, action source and a match key", ErrInvalidEvent, i)
		}
	}
	target, err := c.endpoint(token, "/"+id+"/events", nil)
	if err != nil {
		return EventsResult{}, err
	}
	body, err := c.do(ctx, "send events", http.MethodPost, token, target, map[string]any{"data": events})
	if err != nil {
		return EventsResult{}, err
	}
	var res EventsResult
	if err := json.Unmarshal(body, &res); err != nil {
		return EventsResult{}, fmt.Errorf("meta: decode send events: %w", err)
	}
	if res.EventsReceived != len(events) {
		return res, fmt.Errorf("%w: %d of %d (trace %s)", ErrEventsNotReceived, res.EventsReceived, len(events), res.TraceID)
	}
	return res, nil
}

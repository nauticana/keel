package telephony

import "time"

// Event is one call or message a phone system reported. Numbers are as the
// provider sent them. ExternalID is the provider's own id, stable across
// redeliveries and status updates of the same call or message.
type Event struct {
	Kind          Kind
	Direction     Direction
	ExternalID    string
	From, To      string
	At            time.Time
	Answered      bool
	Duration      time.Duration // talk time of an answered call
	RecordingURL  string        // call recording, or voicemail of an unanswered call
	MessageStatus MessageStatus // empty for a call
}

// Counterpart is the other party's number, seen from the account's side.
func (e Event) Counterpart() string {
	if e.Direction == DirectionOutbound {
		return e.To
	}
	return e.From
}

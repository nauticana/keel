package notify

// Message is the channel-independent content of one notification. PartnerID
// scopes the recipient suppression check; 0 consults only fleet-wide entries.
type Message struct {
	PartnerID int64
	Title     string
	Body      string
	Data      map[string]string
}

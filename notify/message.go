package notify

// Message is the channel-independent content of one notification. PartnerID
// scopes the recipient suppression check; 0 consults only fleet-wide entries.
// Channel, when set, is the only channel delivered on: preferences and the
// type's channels are skipped, Addressable still applies.
type Message struct {
	PartnerID int64
	Channel   string
	Title     string
	Body      string
	Data      map[string]string
}

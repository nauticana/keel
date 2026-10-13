package connect

// ConnectionChangedEvent is the outbox event type CredentialStoreDB enqueues
// when AnnounceChanges is set; its payload is a ConnectionChange.
const ConnectionChangedEvent = "partner_credential.changed"

// ConnectionChange reports whether the partner's connection is now usable.
type ConnectionChange struct {
	PartnerID int64  `json:"partnerId"`
	EntityID  int64  `json:"entityId"`
	Provider  string `json:"provider"`
	Connected bool   `json:"connected"`
}

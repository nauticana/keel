package erasure

// Item is one row of a user's data and what the erasure does to it.
type Item struct {
	Table  string `json:"table"`
	Key    string `json:"key"` // the row's key as text, unique within Table
	Action Action `json:"action"`
	Reason string `json:"reason,omitempty"`
}

const (
	maxKeyLength    = 200
	maxReasonLength = 500
)

func (it Item) valid() bool {
	if it.Key == "" || len(it.Key) > maxKeyLength || !it.Action.valid() || len(it.Reason) > maxReasonLength {
		return false
	}
	return it.Action != ActionHold || it.Reason != ""
}

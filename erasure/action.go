package erasure

// Action is what an erasure does to one row.
type Action string

const (
	ActionDelete    Action = "D"
	ActionAnonymize Action = "A"
	ActionHold      Action = "H" // kept as is; Item.Reason says why
)

func (a Action) valid() bool {
	return a == ActionDelete || a == ActionAnonymize || a == ActionHold
}

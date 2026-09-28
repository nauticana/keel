package erasure

// Plan is a request with the rows its execution will delete, anonymize or hold.
// The worker re-enumerates at execution, so rows created later are covered too.
type Plan struct {
	Request Request `json:"request"`
	Items   []Item  `json:"items"`
}

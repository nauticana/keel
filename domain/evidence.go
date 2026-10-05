package domain

// Evidence is a passed check that is not yet recorded: Check produces it
// before a partner exists, and RecordTx records it inside the transaction
// that creates the partner, its domain and the membership. Only the service
// can create it, so unchecked evidence cannot be recorded.
type Evidence struct {
	method, domainName, tokenHash, ref string
}

func (e *Evidence) Method() string     { return e.method }
func (e *Evidence) DomainName() string { return e.domainName }
func (e *Evidence) Ref() string        { return e.ref }

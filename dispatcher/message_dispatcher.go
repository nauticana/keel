package dispatcher

import "github.com/nauticana/keel/port"

// MessageDispatcher is the channel-keyed delivery contract used by the
// dispatcher package. As of v0.5 it is a type alias for the canonical
// port.MessageDispatcher so the contract lives in port/ alongside the
// other pluggable interfaces; the alias keeps legacy code that types
// against dispatcher.MessageDispatcher compiling without change.
//
// New code should depend on port.MessageDispatcher directly so the
// dispatcher package only hosts implementations, not the contract.
type MessageDispatcher = port.MessageDispatcher

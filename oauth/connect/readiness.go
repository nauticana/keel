package connect

import (
	"context"
	"fmt"
)

// Source readiness states. NOT_CONNECTED is fixed by the tenant connecting an
// account; NOT_COLLECTED only by shipping a collector.
const (
	SourceReady        = "READY"
	SourceNotConnected = "NOT_CONNECTED"
	SourceNotCollected = "NOT_COLLECTED"
)

// Source is one external-data source of the app's catalog.
type Source struct {
	ID        string
	Provider  string // connection provider required; "" when none
	Collected bool   // a collector for this source ships
}

// ConnectionLister is the connection lookup the resolver needs;
// CredentialStoreDB implements it.
type ConnectionLister interface {
	ConnectedProviders(ctx context.Context, partnerID int64) ([]string, error)
}

var _ ConnectionLister = (*CredentialStoreDB)(nil)

// SourceReadiness maps source id → state for one tenant.
type SourceReadiness map[string]string

// State returns the source's state; known is false for an id outside the catalog.
func (r SourceReadiness) State(id string) (state string, known bool) {
	state, known = r[id]
	return state, known
}

// Ready is false only for a catalogued source that is not READY.
func (r SourceReadiness) Ready(id string) bool {
	state, known := r[id]
	return !known || state == SourceReady
}

// ReadinessResolver evaluates an injected source catalog against a tenant's
// active connections.
type ReadinessResolver struct {
	connections ConnectionLister
	sources     []Source
}

func NewReadinessResolver(connections ConnectionLister, sources []Source) (*ReadinessResolver, error) {
	if connections == nil {
		return nil, fmt.Errorf("readiness resolver: nil connection lister")
	}
	seen := make(map[string]bool, len(sources))
	for _, src := range sources {
		if src.ID == "" {
			return nil, fmt.Errorf("readiness resolver: source with empty id")
		}
		if seen[src.ID] {
			return nil, fmt.Errorf("readiness resolver: duplicate source %q", src.ID)
		}
		seen[src.ID] = true
	}
	return &ReadinessResolver{connections: connections, sources: append([]Source(nil), sources...)}, nil
}

func (r *ReadinessResolver) Resolve(ctx context.Context, partnerID int64) (SourceReadiness, error) {
	providers, err := r.connections.ConnectedProviders(ctx, partnerID)
	if err != nil {
		return nil, fmt.Errorf("resolve source readiness for partner %d: %w", partnerID, err)
	}
	connected := make(map[string]bool, len(providers))
	for _, p := range providers {
		connected[p] = true
	}
	out := make(SourceReadiness, len(r.sources))
	for _, src := range r.sources {
		switch {
		case !src.Collected:
			out[src.ID] = SourceNotCollected
		case src.Provider != "" && !connected[src.Provider]:
			out[src.ID] = SourceNotConnected
		default:
			out[src.ID] = SourceReady
		}
	}
	return out, nil
}

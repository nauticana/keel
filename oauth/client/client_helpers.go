package client

import (
	"context"
	"strconv"
)

// StateEntityKey is the OAuth-state extra key carrying the entity scope across
// the consent redirect (see WithEntity).
const StateEntityKey = "entity_id"

// entityCtxKey scopes a credential to a specific business/entity within a
// partner (0 = tenant-wide). It rides the OAuth state across the consent
// redirect and the request context into the CredentialStore, so no interface
// method carries it explicitly — existing callers and providers stay at 0.
type entityCtxKey struct{}

// WithEntity tags ctx with the entity scope a CredentialStore should read.
func WithEntity(ctx context.Context, entityID int64) context.Context {
	return context.WithValue(ctx, entityCtxKey{}, entityID)
}

// EntityFromContext returns the entity scope tagged on ctx, or 0 (tenant-wide).
func EntityFromContext(ctx context.Context) int64 {
	if v, ok := ctx.Value(entityCtxKey{}).(int64); ok {
		return v
	}
	return 0
}

// entityFromExtra reads the entity scope an AuthURL stashed in the OAuth-state
// extra, defaulting to 0 when absent or unparsable.
func entityFromExtra(extra map[string]string) int64 {
	if extra == nil {
		return 0
	}
	id, _ := strconv.ParseInt(extra[StateEntityKey], 10, 64)
	return id
}

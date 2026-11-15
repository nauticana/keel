package document

import "context"

// SeparationPolicy refuses a reviewer deciding a document they uploaded unless
// the type's policy allows one person; approval.Service is one.
type SeparationPolicy interface {
	RequireSeparation(ctx context.Context, partnerID int64, objectType string, authorID, actorID int64) error
}

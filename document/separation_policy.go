package document

import "context"

// SeparationPolicy decides whether the uploader of a document of the type may
// review it for the partner; approval.Service is one.
type SeparationPolicy interface {
	AllowsSinglePerson(ctx context.Context, partnerID int64, objectType string) (bool, error)
}

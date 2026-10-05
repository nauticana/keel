package user

import (
	"context"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// IdentityAccountCreator creates an identity's account in the registration
// transaction and records its signup consent after commit, because consent
// rows need the committed account. RegisterWithIdentity requires it of Users.
type IdentityAccountCreator interface {
	CreateIdentityAccountTx(ctx context.Context, tx port.TxQueryService, identity ExternalIdentity) (*model.UserSession, error)
	RecordSignupConsent(userID int, email string, consent *SignupConsent) error
}

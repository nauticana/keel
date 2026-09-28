package erasure

import (
	"context"

	"github.com/nauticana/keel/port"
)

// Classifier is implemented by the application once per table that holds a
// user's data. It decides per row whether the row is deleted, anonymized or
// held (with a reason), and applies deletes and anonymizations.
type Classifier interface {
	// Table names the audited table; user_account is reserved for the account itself.
	Table() string
	// Queries is the classifier's named-SQL catalog; both methods get a
	// QueryService bound to it.
	Queries() map[string]string
	Classify(ctx context.Context, qs port.QueryService, userID int) ([]Item, error)
	// Erase deletes or anonymizes one item inside the transaction that audits
	// it. pseudonym is set for ActionAnonymize: the stable stand-in for the user.
	Erase(ctx context.Context, tx port.QueryService, userID int, item Item, pseudonym string) error
}

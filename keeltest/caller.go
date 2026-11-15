package keeltest

import (
	"context"

	"github.com/nauticana/keel/common"
)

// AsUser returns a context whose caller is userID signed in to partnerID.
func AsUser(partnerID, userID int64) context.Context {
	return common.WithCallerSession(context.Background(), common.CallerSession{PartnerID: partnerID, UserID: userID})
}

package user

import (
	"context"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

const qRecipientAddresses = "keel_recipient_addresses"

var recipientQueries = map[string]string{
	qRecipientAddresses: `SELECT user_email, phone FROM user_account WHERE id = ?`,
}

// SQLRecipients is an address-only port.RecipientResolver for binaries that
// deliver or enqueue notifications without a full LocalUserService. A missing
// user resolves to no address.
type SQLRecipients struct {
	ctx context.Context
	qs  port.QueryService
}

var _ port.RecipientResolver = (*SQLRecipients)(nil)

func NewSQLRecipients(ctx context.Context, db port.DatabaseRepository) *SQLRecipients {
	return &SQLRecipients{ctx: ctx, qs: db.GetQueryService(ctx, recipientQueries)}
}

func (r *SQLRecipients) EmailFor(userID int) (string, error) {
	return r.address(userID, 0)
}

func (r *SQLRecipients) PhoneFor(userID int) (string, error) {
	return r.address(userID, 1)
}

func (r *SQLRecipients) address(userID, column int) (string, error) {
	res, err := r.qs.Query(r.ctx, qRecipientAddresses, userID)
	if err != nil {
		return "", err
	}
	if len(res.Rows) == 0 {
		return "", nil
	}
	return common.AsString(res.Rows[0][column]), nil
}

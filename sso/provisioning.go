package sso

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/domain"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

const (
	scimTokenPrefix    = "scim_"
	deactivationReason = "deactivated by directory provisioning"
)

// Provisioning is the SCIM 2.0 service provider of a partner's directory. A
// bearer token selects the partner; every read and write is scoped to it.
// Users must implement user.TenantAccountCreator.
type Provisioning struct {
	DB      port.DatabaseRepository
	Users   user.UserService
	Domains *domain.Service

	once sync.Once
	qs   port.QueryService
}

// IssueToken creates a provisioning token for the partner and returns it in
// clear exactly once. expiresDays 0 never expires; scim_token_max_days and
// scim_max_active_tokens bound the lifetime and the partner's active tokens.
func (p *Provisioning) IssueToken(ctx context.Context, partnerID int64, userID int, caption string, expiresDays int) (int64, string, error) {
	caption = strings.TrimSpace(caption)
	maxDays := config.Config().SCIMTokenMaxDays
	if partnerID <= 0 || userID <= 0 || caption == "" || len(caption) > 80 || expiresDays < 0 || expiresDays > maxDays {
		return 0, "", fmt.Errorf("%w: caption is required and expiry is 0 to %d days", ErrSCIMInvalidValue, maxDays)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return 0, "", err
	}
	token := scimTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	var id int64
	err := p.inTx(ctx, func(tx port.TxQueryService) error {
		locked, err := tx.Query(ctx, qLockSCIMTokens, partnerID)
		if err != nil {
			return err
		}
		if len(locked.Rows) != 1 {
			return ErrSCIMInvalidValue
		}
		res, err := tx.Query(ctx, qActiveTokens, partnerID)
		if err != nil {
			return err
		}
		if len(res.Rows) == 1 && common.AsInt64(res.Rows[0][0]) >= int64(config.Config().SCIMMaxActiveTokens) {
			return ErrSCIMTooMany
		}
		res, err = tx.Query(ctx, qInsertToken, partnerID, caption, common.Sha256Hex(token), userID, expiresDays, expiresDays)
		if err != nil {
			return fmt.Errorf("sso: insert provisioning token: %w", err)
		}
		if len(res.Rows) != 1 {
			return errors.New("sso: insert provisioning token returned no id")
		}
		id = common.AsInt64(res.Rows[0][0])
		return nil
	})
	if err != nil {
		return 0, "", err
	}
	return id, token, nil
}

// RevokeToken revokes one of the partner's tokens at once.
func (p *Provisioning) RevokeToken(ctx context.Context, partnerID, tokenID int64) error {
	res, err := p.query(ctx).Query(ctx, qRevokeToken, partnerID, tokenID)
	if err != nil {
		return err
	}
	if len(res.Rows) == 0 {
		return ErrSCIMNotFound
	}
	return nil
}

// Authenticate returns the partner of an active token.
func (p *Provisioning) Authenticate(ctx context.Context, token string) (int64, error) {
	if !strings.HasPrefix(token, scimTokenPrefix) || len(token) > 100 {
		return 0, ErrSCIMUnauthorized
	}
	res, err := p.query(ctx).Query(ctx, qTokenByHash, common.Sha256Hex(token))
	if err != nil {
		return 0, err
	}
	if len(res.Rows) != 1 {
		return 0, ErrSCIMUnauthorized
	}
	if _, err := p.query(ctx).Query(ctx, qTouchToken, res.Rows[0][0]); err != nil {
		return 0, fmt.Errorf("sso: record token use: %w", err)
	}
	return common.AsInt64(res.Rows[0][1]), nil
}

// inTx runs fn in one transaction over every package query.
func (p *Provisioning) inTx(ctx context.Context, fn func(tx port.TxQueryService) error) error {
	tx, err := p.DB.BeginTx(ctx, allQueries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("sso: commit provisioning: %w", err)
	}
	committed = true
	return nil
}

// syncGroupRoles maps an active provisioned user's groups, by display name
// and external id, through the role mapping of the partner's active
// connection. Without one the directory assigns no roles; an inactive user,
// whose membership has ended, gets none.
func syncGroupRoles(ctx context.Context, tx port.QueryService, partnerID int64, userID int) error {
	managed, err := tx.Query(ctx, qSCIMManaged, partnerID, userID)
	if err != nil || len(managed.Rows) == 0 {
		return err
	}
	conn, err := activeConnectionOn(ctx, tx, partnerID)
	if err != nil || conn == nil {
		return err
	}
	res, err := tx.Query(ctx, qSCIMUserGroups, partnerID, userID)
	if err != nil {
		return fmt.Errorf("sso: user groups: %w", err)
	}
	keys := make([]string, 0, 2*len(res.Rows))
	for _, row := range res.Rows {
		keys = append(keys, common.AsString(row[1]))
		if ext := common.AsString(row[2]); ext != "" {
			keys = append(keys, ext)
		}
	}
	return syncRoles(ctx, tx, conn, userID, func(string) []string { return keys })
}

func (p *Provisioning) accounts() (user.TenantAccountCreator, error) {
	a, ok := p.Users.(user.TenantAccountCreator)
	if !ok {
		return nil, errors.New("sso: the user service cannot provision tenant accounts")
	}
	return a, nil
}

// checkEmail admits only an address inside a domain the partner holds.
func (p *Provisioning) checkEmail(ctx context.Context, partnerID int64, email string) error {
	holder, err := holderOf(ctx, p.Domains, domain.DomainFromEmail(email))
	if errors.Is(err, domain.ErrNotHeld) || (err == nil && holder != partnerID) {
		return fmt.Errorf("%w: %s is outside the organization's verified domains", ErrSCIMInvalidValue, email)
	}
	return err
}

func (p *Provisioning) query(ctx context.Context) port.QueryService {
	p.once.Do(func() { p.qs = p.DB.GetQueryService(ctx, allQueries) })
	return p.qs
}

// page bounds startIndex (1-based) and count by the list page-size flags.
func page(startIndex, count int) (int, int) {
	if startIndex < 1 {
		startIndex = 1
	}
	if count <= 0 {
		count = config.Config().DefaultListPageSize
	}
	return startIndex, min(count, config.Config().MaxListPageSize)
}

func resourceID(id string) (int64, error) {
	v, err := strconv.ParseInt(id, 10, 64)
	if err != nil || v <= 0 {
		return 0, ErrSCIMNotFound
	}
	return v, nil
}

package sso

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

// scimUserInput is a validated user resource.
type scimUserInput struct {
	userName, externalID string
	member               user.TenantMember
	active               bool
}

func (p *Provisioning) userInput(ctx context.Context, partnerID int64, in *SCIMUser) (*scimUserInput, error) {
	v := &scimUserInput{userName: strings.ToLower(strings.TrimSpace(in.UserName)), externalID: strings.TrimSpace(in.ExternalID), active: in.active()}
	if v.userName == "" || len(v.userName) > 255 || len(v.externalID) > 255 {
		return nil, fmt.Errorf("%w: userName is required; userName and externalId are at most 255 characters", ErrSCIMInvalidValue)
	}
	given, family := in.names()
	if len(given) > 80 || len(family) > 80 {
		return nil, fmt.Errorf("%w: givenName and familyName are at most 80 characters", ErrSCIMInvalidValue)
	}
	v.member = user.TenantMember{FirstName: given, LastName: family, Email: normalizeEmail(in.email())}
	if v.member.Email == "" || len(v.member.Email) > 254 {
		return nil, fmt.Errorf("%w: an email is required", ErrSCIMInvalidValue)
	}
	if err := p.checkEmail(ctx, partnerID, v.member.Email); err != nil {
		return nil, err
	}
	return v, nil
}

// CreateUser provisions a user. An account that already has the email is
// adopted when it belongs to this partner or to none; an account of another
// partner is a conflict.
func (p *Provisioning) CreateUser(ctx context.Context, partnerID int64, in *SCIMUser) (*SCIMUser, error) {
	v, err := p.userInput(ctx, partnerID, in)
	if err != nil {
		return nil, err
	}
	accounts, err := p.accounts()
	if err != nil {
		return nil, err
	}
	existing, err := p.Users.GetUserByEmail(v.member.Email)
	switch {
	case errors.Is(err, user.ErrNoAccount):
		existing = nil
	case err != nil:
		return nil, err
	case existing.PartnerId != 0 && existing.PartnerId != partnerID:
		return nil, fmt.Errorf("%w: the account belongs to another organization", ErrSCIMConflict)
	}
	var userID int
	err = p.inTx(ctx, func(tx port.TxQueryService) error {
		if err := userConflict(ctx, tx, partnerID, 0, v); err != nil {
			return err
		}
		if existing != nil {
			if res, err := tx.Query(ctx, qSCIMUser, partnerID, existing.Id); err != nil || len(res.Rows) > 0 {
				if err != nil {
					return err
				}
				return fmt.Errorf("%w: the account is already provisioned", ErrSCIMConflict)
			}
			if err := accounts.UpdateTenantMemberTx(ctx, tx, existing.Id, v.member); err != nil {
				return accountError(err)
			}
			if existing.PartnerId == 0 && v.active {
				if err := accounts.JoinPartnerTx(ctx, tx, partnerID, existing.Id); err != nil {
					return accountError(err)
				}
			}
			userID = existing.Id
		} else {
			id, err := accounts.CreateTenantMemberTx(ctx, tx, partnerID, v.member, v.active)
			if err != nil {
				return accountError(err)
			}
			userID = id
		}
		_, err := tx.Query(ctx, qInsertSCIMUser, partnerID, userID, v.userName, nullable(v.externalID), v.active)
		return err
	})
	if err != nil {
		return nil, err
	}
	if existing != nil && existing.PartnerId == partnerID && !v.active {
		if err := p.endMembership(partnerID, userID); err != nil {
			cleanupErr := p.inTx(ctx, func(tx port.TxQueryService) error {
				_, cleanupErr := tx.Query(ctx, qDeleteSCIMUser, partnerID, userID)
				return cleanupErr
			})
			return nil, errors.Join(err, cleanupErr)
		}
	}
	return p.GetUser(ctx, partnerID, strconv.Itoa(userID))
}

// ReplaceUser sets every kept attribute. Deactivation ends the membership,
// its roles and its sessions at once; reactivation makes the account a
// member again.
func (p *Provisioning) ReplaceUser(ctx context.Context, partnerID int64, id string, in *SCIMUser) (*SCIMUser, error) {
	current, err := p.GetUser(ctx, partnerID, id)
	if err != nil {
		return nil, err
	}
	userID, _ := strconv.Atoi(current.ID)
	wasActive := current.active()
	v, err := p.userInput(ctx, partnerID, in)
	if err != nil {
		return nil, err
	}
	accounts, err := p.accounts()
	if err != nil {
		return nil, err
	}
	err = p.inTx(ctx, func(tx port.TxQueryService) error {
		if err := userConflict(ctx, tx, partnerID, userID, v); err != nil {
			return err
		}
		if err := accounts.UpdateTenantMemberTx(ctx, tx, userID, v.member); err != nil {
			return accountError(err)
		}
		if !wasActive && v.active {
			if err := accounts.JoinPartnerTx(ctx, tx, partnerID, userID); err != nil {
				return accountError(err)
			}
		}
		if _, err := tx.Query(ctx, qUpdateSCIMUser, v.userName, nullable(v.externalID), v.active, partnerID, userID); err != nil {
			return err
		}
		if v.active {
			return syncGroupRoles(ctx, tx, partnerID, userID)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !v.active {
		if err := p.endMembership(partnerID, userID); err != nil {
			return nil, err
		}
	}
	return p.GetUser(ctx, partnerID, current.ID)
}

// PatchUser applies PATCH operations, then replaces the user.
func (p *Provisioning) PatchUser(ctx context.Context, partnerID int64, id string, ops []SCIMPatchOp) (*SCIMUser, error) {
	current, err := p.GetUser(ctx, partnerID, id)
	if err != nil {
		return nil, err
	}
	if err := applyUserPatch(current, ops); err != nil {
		return nil, err
	}
	return p.ReplaceUser(ctx, partnerID, id, current)
}

// DeleteUser stops provisioning the user and ends its membership. The
// account itself remains, as for any former member.
func (p *Provisioning) DeleteUser(ctx context.Context, partnerID int64, id string) error {
	current, err := p.GetUser(ctx, partnerID, id)
	if err != nil {
		return err
	}
	userID, _ := strconv.Atoi(current.ID)
	if current.active() {
		if err := p.endMembership(partnerID, userID); err != nil {
			return err
		}
	}
	if err := p.inTx(ctx, func(tx port.TxQueryService) error {
		_, err := tx.Query(ctx, qDeleteSCIMUser, partnerID, userID)
		return err
	}); err != nil {
		return err
	}
	return nil
}

// GetUser returns a provisioned user with its groups.
func (p *Provisioning) GetUser(ctx context.Context, partnerID int64, id string) (*SCIMUser, error) {
	userID, err := resourceID(id)
	if err != nil {
		return nil, err
	}
	res, err := p.query(ctx).Query(ctx, qSCIMUser, partnerID, userID)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) != 1 {
		return nil, ErrSCIMNotFound
	}
	u := scimUserFromRow(res.Rows[0])
	groups, err := p.query(ctx).Query(ctx, qSCIMUserGroups, partnerID, userID)
	if err != nil {
		return nil, err
	}
	for _, row := range groups.Rows {
		u.Groups = append(u.Groups, SCIMRef{Value: strconv.FormatInt(common.AsInt64(row[0]), 10), Display: common.AsString(row[1])})
	}
	return u, nil
}

// ListUsers pages through provisioned users, optionally filtered by
// userName or externalId.
func (p *Provisioning) ListUsers(ctx context.Context, partnerID int64, filter string, startIndex, count int) (*SCIMList[*SCIMUser], error) {
	f, err := ParseSCIMFilter(filter, "userName", "externalId")
	if err != nil {
		return nil, err
	}
	name, ext := "", ""
	switch f.Attribute {
	case "userName":
		name = strings.ToLower(f.Value)
	case "externalId":
		ext = f.Value
	}
	startIndex, count = page(startIndex, count)
	total, err := p.query(ctx).Query(ctx, qSCIMUserCount, partnerID, name, name, ext, ext)
	if err != nil {
		return nil, err
	}
	res, err := p.query(ctx).Query(ctx, qSCIMUsers, partnerID, name, name, ext, ext, count, startIndex-1)
	if err != nil {
		return nil, err
	}
	out := &SCIMList[*SCIMUser]{Schemas: []string{SchemaListResponse}, StartIndex: startIndex, Resources: []*SCIMUser{}}
	if len(total.Rows) == 1 {
		out.TotalResults = int(common.AsInt64(total.Rows[0][0]))
	}
	for _, row := range res.Rows {
		out.Resources = append(out.Resources, scimUserFromRow(row))
	}
	out.ItemsPerPage = len(out.Resources)
	return out, nil
}

func (p *Provisioning) endMembership(partnerID int64, userID int) error {
	if err := p.Users.EndMembership(partnerID, userID, deactivationReason); err != nil && !errors.Is(err, user.ErrNoMembership) {
		return err
	}
	return nil
}

func userConflict(ctx context.Context, tx port.QueryService, partnerID int64, userID int, v *scimUserInput) error {
	res, err := tx.Query(ctx, qSCIMUserConflict, partnerID, userID, v.userName, v.externalID, v.externalID)
	if err != nil {
		return err
	}
	if len(res.Rows) > 0 {
		return fmt.Errorf("%w: userName or externalId is taken", ErrSCIMConflict)
	}
	return nil
}

// accountError maps account-layer refusals to SCIM conflicts.
func accountError(err error) error {
	if errors.Is(err, user.ErrAccountExists) || errors.Is(err, user.ErrAlreadyMember) {
		return fmt.Errorf("%w: %v", ErrSCIMConflict, err)
	}
	return err
}

func scimUserFromRow(row []any) *SCIMUser {
	active := SCIMBool(common.AsBool(row[3]))
	given, family, email := common.AsString(row[6]), common.AsString(row[7]), common.AsString(row[8])
	u := &SCIMUser{
		Schemas: []string{SchemaUser}, ID: strconv.FormatInt(common.AsInt64(row[0]), 10), ExternalID: common.AsString(row[1]),
		UserName: common.AsString(row[2]), Active: &active,
		Name:        &SCIMName{GivenName: given, FamilyName: family},
		DisplayName: strings.TrimSpace(given + " " + family),
		Meta:        &SCIMMeta{ResourceType: "User", Created: timestamp(row[4]), LastModified: timestamp(row[5])},
	}
	if email != "" {
		u.Emails = []SCIMEmail{{Value: email, Type: "work", Primary: true}}
	}
	return u
}

func timestamp(v any) string {
	if t, ok := v.(time.Time); ok {
		return t.UTC().Format(time.RFC3339)
	}
	return ""
}

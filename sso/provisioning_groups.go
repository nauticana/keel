package sso

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/port"
)

// CreateGroup provisions a group with its members and maps their roles.
func (p *Provisioning) CreateGroup(ctx context.Context, partnerID int64, in *SCIMGroup) (*SCIMGroup, error) {
	name, ext, err := groupInput(in.DisplayName, in.ExternalID)
	if err != nil {
		return nil, err
	}
	members, err := memberIDs(in.Members)
	if err != nil {
		return nil, err
	}
	var groupID int64
	err = p.inTx(ctx, func(tx port.TxQueryService) error {
		if err := groupConflict(ctx, tx, partnerID, 0, name, ext); err != nil {
			return err
		}
		res, err := tx.Query(ctx, qInsertSCIMGroup, partnerID, name, nullable(ext))
		if err != nil {
			return err
		}
		if len(res.Rows) != 1 {
			return fmt.Errorf("sso: insert group returned no id")
		}
		groupID = common.AsInt64(res.Rows[0][0])
		return changeMembers(ctx, tx, partnerID, groupID, members, nil)
	})
	if err != nil {
		return nil, err
	}
	return p.GetGroup(ctx, partnerID, strconv.FormatInt(groupID, 10), true)
}

// ReplaceGroup sets the name, external id and the whole member list.
func (p *Provisioning) ReplaceGroup(ctx context.Context, partnerID int64, id string, in *SCIMGroup) (*SCIMGroup, error) {
	groupID, err := p.groupID(ctx, partnerID, id)
	if err != nil {
		return nil, err
	}
	name, ext, err := groupInput(in.DisplayName, in.ExternalID)
	if err != nil {
		return nil, err
	}
	members, err := memberIDs(in.Members)
	if err != nil {
		return nil, err
	}
	err = p.inTx(ctx, func(tx port.TxQueryService) error {
		if err := groupConflict(ctx, tx, partnerID, groupID, name, ext); err != nil {
			return err
		}
		if _, err := tx.Query(ctx, qUpdateSCIMGroup, name, nullable(ext), partnerID, groupID); err != nil {
			return err
		}
		removed, err := removeAllMembers(ctx, tx, partnerID, groupID)
		if err != nil {
			return err
		}
		return changeMembers(ctx, tx, partnerID, groupID, members, removed)
	})
	if err != nil {
		return nil, err
	}
	return p.GetGroup(ctx, partnerID, id, true)
}

// PatchGroup renames the group or changes members without resending the list.
func (p *Provisioning) PatchGroup(ctx context.Context, partnerID int64, id string, ops []SCIMPatchOp) (*SCIMGroup, error) {
	current, err := p.GetGroup(ctx, partnerID, id, false)
	if err != nil {
		return nil, err
	}
	groupID, _ := strconv.ParseInt(current.ID, 10, 64)
	patch, err := parseGroupPatch(ops)
	if err != nil {
		return nil, err
	}
	name, ext := current.DisplayName, current.ExternalID
	if patch.displayName != nil {
		name = *patch.displayName
	}
	if patch.externalID != nil {
		ext = *patch.externalID
	}
	if name, ext, err = groupInput(name, ext); err != nil {
		return nil, err
	}
	add, err := parseIDs(patch.add)
	if err != nil {
		return nil, err
	}
	remove, err := parseIDs(patch.remove)
	if err != nil {
		return nil, err
	}
	err = p.inTx(ctx, func(tx port.TxQueryService) error {
		if name != current.DisplayName || ext != current.ExternalID {
			if err := groupConflict(ctx, tx, partnerID, groupID, name, ext); err != nil {
				return err
			}
			if _, err := tx.Query(ctx, qUpdateSCIMGroup, name, nullable(ext), partnerID, groupID); err != nil {
				return err
			}
		}
		var removed []int
		if patch.removeAll || patch.replaceMembers != nil {
			if removed, err = removeAllMembers(ctx, tx, partnerID, groupID); err != nil {
				return err
			}
		}
		if patch.replaceMembers != nil {
			if add, err = parseIDs(*patch.replaceMembers); err != nil {
				return err
			}
		}
		for _, userID := range remove {
			if _, err := tx.Query(ctx, qRemoveGroupMember, partnerID, groupID, userID); err != nil {
				return err
			}
			removed = append(removed, userID)
		}
		return changeMembers(ctx, tx, partnerID, groupID, add, removed)
	})
	if err != nil {
		return nil, err
	}
	return p.GetGroup(ctx, partnerID, id, true)
}

// DeleteGroup removes the group and the roles it mapped.
func (p *Provisioning) DeleteGroup(ctx context.Context, partnerID int64, id string) error {
	groupID, err := p.groupID(ctx, partnerID, id)
	if err != nil {
		return err
	}
	return p.inTx(ctx, func(tx port.TxQueryService) error {
		removed, err := removeAllMembers(ctx, tx, partnerID, groupID)
		if err != nil {
			return err
		}
		if _, err := tx.Query(ctx, qDeleteSCIMGroup, partnerID, groupID); err != nil {
			return err
		}
		return changeMembers(ctx, tx, partnerID, groupID, nil, removed)
	})
}

// GetGroup returns a group, with up to scim_max_group_members members when asked.
func (p *Provisioning) GetGroup(ctx context.Context, partnerID int64, id string, withMembers bool) (*SCIMGroup, error) {
	groupID, err := p.groupID(ctx, partnerID, id)
	if err != nil {
		return nil, err
	}
	res, err := p.query(ctx).Query(ctx, qSCIMGroup, partnerID, groupID)
	if err != nil {
		return nil, err
	}
	g := scimGroupFromRow(res.Rows[0])
	if withMembers {
		if err := p.loadMembers(ctx, partnerID, groupID, g); err != nil {
			return nil, err
		}
	}
	return g, nil
}

func (p *Provisioning) loadMembers(ctx context.Context, partnerID, groupID int64, g *SCIMGroup) error {
	members, err := p.query(ctx).Query(ctx, qSCIMGroupMembers, partnerID, groupID, config.Config().SCIMMaxGroupMembers)
	if err != nil {
		return err
	}
	for _, row := range members.Rows {
		g.Members = append(g.Members, SCIMRef{Value: strconv.FormatInt(common.AsInt64(row[0]), 10), Display: common.AsString(row[1])})
	}
	return nil
}

// ListGroups pages through groups, optionally filtered on id, displayName or
// externalId, with their members when q.Members is set.
func (p *Provisioning) ListGroups(ctx context.Context, partnerID int64, q SCIMListQuery) (*SCIMList[*SCIMGroup], error) {
	f, err := parseSCIMFilter(q.Filter, scimGroupFilterSchema)
	if err != nil {
		return nil, err
	}
	args := f.args(partnerID, scimGroupFilterSchema)
	startIndex, count := page(q)
	total, err := p.query(ctx).Query(ctx, qSCIMGroupCount, args...)
	if err != nil {
		return nil, err
	}
	out := &SCIMList[*SCIMGroup]{Schemas: []string{SchemaListResponse}, StartIndex: startIndex, Resources: []*SCIMGroup{}}
	if len(total.Rows) == 1 {
		out.TotalResults = int(common.AsInt64(total.Rows[0][0]))
	}
	if count > 0 {
		res, err := p.query(ctx).Query(ctx, qSCIMGroups, append(args, count, startIndex-1)...)
		if err != nil {
			return nil, err
		}
		for _, row := range res.Rows {
			g := scimGroupFromRow(row)
			if q.Members {
				if err := p.loadMembers(ctx, partnerID, common.AsInt64(row[0]), g); err != nil {
					return nil, err
				}
			}
			out.Resources = append(out.Resources, g)
		}
	}
	out.ItemsPerPage = len(out.Resources)
	return out, nil
}

func (p *Provisioning) groupID(ctx context.Context, partnerID int64, id string) (int64, error) {
	groupID, err := resourceID(id)
	if err != nil {
		return 0, err
	}
	res, err := p.query(ctx).Query(ctx, qSCIMGroup, partnerID, groupID)
	if err != nil {
		return 0, err
	}
	if len(res.Rows) != 1 {
		return 0, ErrSCIMNotFound
	}
	return groupID, nil
}

// changeMembers adds provisioned users to the group and re-maps the roles of
// every user added or removed.
func changeMembers(ctx context.Context, tx port.QueryService, partnerID, groupID int64, add, removed []int) error {
	touched := map[int]bool{}
	for _, userID := range add {
		res, err := tx.Query(ctx, qSCIMUser, partnerID, userID)
		if err != nil {
			return err
		}
		if len(res.Rows) == 0 {
			return fmt.Errorf("%w: member %d is not a provisioned user", ErrSCIMInvalidValue, userID)
		}
		if _, err := tx.Query(ctx, qAddGroupMember, partnerID, groupID, userID); err != nil {
			return err
		}
		touched[userID] = true
	}
	count, err := tx.Query(ctx, qSCIMGroupMemberCount, partnerID, groupID)
	if err != nil {
		return err
	}
	if len(count.Rows) != 1 || common.AsInt64(count.Rows[0][0]) > int64(config.Config().SCIMMaxGroupMembers) {
		return ErrSCIMTooMany
	}
	for _, userID := range removed {
		touched[userID] = true
	}
	for userID := range touched {
		if err := syncGroupRoles(ctx, tx, partnerID, userID); err != nil {
			return err
		}
	}
	return nil
}

func removeAllMembers(ctx context.Context, tx port.QueryService, partnerID, groupID int64) ([]int, error) {
	res, err := tx.Query(ctx, qRemoveAllMembers, partnerID, groupID)
	if err != nil {
		return nil, err
	}
	out := make([]int, 0, len(res.Rows))
	for _, row := range res.Rows {
		out = append(out, int(common.AsInt64(row[0])))
	}
	return out, nil
}

// groupConflict locks the partner's provisioning, since the unique index on
// display_name cannot compare without case, then looks for a taken key.
func groupConflict(ctx context.Context, tx port.QueryService, partnerID, groupID int64, name, ext string) error {
	locked, err := tx.Query(ctx, qLockSCIMPartner, partnerID)
	if err != nil {
		return err
	}
	if len(locked.Rows) != 1 {
		return ErrSCIMNotFound
	}
	res, err := tx.Query(ctx, qSCIMGroupConflict, partnerID, groupID, name, ext, ext)
	if err != nil {
		return err
	}
	if len(res.Rows) > 0 {
		return fmt.Errorf("%w: displayName or externalId is taken", ErrSCIMConflict)
	}
	return nil
}

func groupInput(displayName, externalID string) (string, string, error) {
	name, ext := strings.TrimSpace(displayName), strings.TrimSpace(externalID)
	if name == "" || len(name) > 255 || len(ext) > 255 {
		return "", "", fmt.Errorf("%w: displayName is required; displayName and externalId are at most 255 characters", ErrSCIMInvalidValue)
	}
	return name, ext, nil
}

func memberIDs(refs []SCIMRef) ([]int, error) {
	if len(refs) > config.Config().SCIMMaxGroupMembers {
		return nil, ErrSCIMTooMany
	}
	ids := make([]string, 0, len(refs))
	for _, r := range refs {
		ids = append(ids, r.Value)
	}
	return parseIDs(ids)
}

func parseIDs(ids []string) ([]int, error) {
	out := make([]int, 0, len(ids))
	for _, id := range ids {
		v, err := strconv.Atoi(id)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("%w: member %q", ErrSCIMInvalidValue, id)
		}
		out = append(out, v)
	}
	return out, nil
}

func scimGroupFromRow(row []any) *SCIMGroup {
	return &SCIMGroup{
		Schemas: []string{SchemaGroup}, ID: strconv.FormatInt(common.AsInt64(row[0]), 10), ExternalID: common.AsString(row[1]),
		DisplayName: common.AsString(row[2]),
		Meta:        &SCIMMeta{ResourceType: "Group", Created: timestamp(row[3]), LastModified: timestamp(row[4])},
	}
}

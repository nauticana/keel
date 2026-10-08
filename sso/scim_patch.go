package sso

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nauticana/keel/config"
)

// applyUserPatch applies PATCH operations to a user resource. Attributes keel
// does not keep (enterprise extension, phone numbers, addresses, title) are
// ignored, since directories send them routinely.
func applyUserPatch(u *SCIMUser, ops []SCIMPatchOp) error {
	if len(ops) > config.Config().SCIMMaxPatchOperations {
		return ErrSCIMTooMany
	}
	for _, op := range ops {
		kind := strings.ToLower(op.Op)
		if kind != "add" && kind != "replace" && kind != "remove" {
			return fmt.Errorf("%w: op %q", ErrSCIMInvalidValue, op.Op)
		}
		if op.Path == "" {
			if kind == "remove" {
				return fmt.Errorf("%w: remove needs a path", ErrSCIMInvalidPath)
			}
			var values map[string]json.RawMessage
			if err := json.Unmarshal(op.Value, &values); err != nil {
				return fmt.Errorf("%w: value: %v", ErrSCIMInvalidValue, err)
			}
			for path, value := range values {
				if err := setUserAttribute(u, path, value, false); err != nil {
					return err
				}
			}
			continue
		}
		if err := setUserAttribute(u, op.Path, op.Value, kind == "remove"); err != nil {
			return err
		}
	}
	return nil
}

func setUserAttribute(u *SCIMUser, path string, raw json.RawMessage, remove bool) error {
	str := func(target *string) error {
		if remove {
			*target = ""
			return nil
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrSCIMInvalidValue, path, err)
		}
		return nil
	}
	name := func() *SCIMName {
		if u.Name == nil {
			u.Name = &SCIMName{}
		}
		return u.Name
	}
	switch strings.ToLower(path) {
	case "active":
		if remove {
			return fmt.Errorf("%w: active cannot be removed", ErrSCIMInvalidPath)
		}
		var b SCIMBool
		if err := json.Unmarshal(raw, &b); err != nil {
			return err
		}
		u.Active = &b
	case "username":
		if remove {
			return fmt.Errorf("%w: userName cannot be removed", ErrSCIMInvalidPath)
		}
		return str(&u.UserName)
	case "externalid":
		return str(&u.ExternalID)
	case "displayname":
		return str(&u.DisplayName)
	case "name.givenname":
		return str(&name().GivenName)
	case "name.familyname":
		return str(&name().FamilyName)
	case "name.formatted":
		return str(&name().Formatted)
	case "name":
		if remove {
			u.Name = nil
			return nil
		}
		var n SCIMName
		if err := json.Unmarshal(raw, &n); err != nil {
			return fmt.Errorf("%w: name: %v", ErrSCIMInvalidValue, err)
		}
		u.Name = &n
	case "emails":
		if remove {
			u.Emails = nil
			return nil
		}
		var emails []SCIMEmail
		if err := json.Unmarshal(raw, &emails); err != nil {
			return fmt.Errorf("%w: emails: %v", ErrSCIMInvalidValue, err)
		}
		u.Emails = emails
	default:
		if value, ok := emailValuePath(path); ok {
			if remove {
				u.Emails = nil
				return nil
			}
			var v string
			if err := json.Unmarshal(raw, &v); err != nil {
				return fmt.Errorf("%w: %s: %v", ErrSCIMInvalidValue, path, err)
			}
			u.Emails = []SCIMEmail{{Value: v, Type: value, Primary: true}}
		}
	}
	return nil
}

// emailValuePath matches `emails[type eq "work"].value`, returning the type.
func emailValuePath(path string) (string, bool) {
	lower := strings.ToLower(strings.ReplaceAll(path, " ", ""))
	if !strings.HasPrefix(lower, `emails[typeeq"`) || !strings.HasSuffix(lower, `"].value`) {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(lower, `emails[typeeq"`), `"].value`), true
}

// groupPatch is a group PATCH reduced to what changes.
type groupPatch struct {
	displayName, externalID *string
	replaceMembers          *[]string
	add, remove             []string
	removeAll               bool
}

// parseGroupPatch reads PATCH operations on a group. Member operations accept
// a value list, a `members[value eq "id"]` path, and a path-less value object.
func parseGroupPatch(ops []SCIMPatchOp) (*groupPatch, error) {
	if len(ops) > config.Config().SCIMMaxPatchOperations {
		return nil, ErrSCIMTooMany
	}
	p := &groupPatch{}
	for _, op := range ops {
		kind := strings.ToLower(op.Op)
		path := strings.ToLower(strings.TrimSpace(op.Path))
		if id, ok := memberPathValue(op.Path); ok {
			if kind != "remove" {
				return nil, fmt.Errorf("%w: %s on a member filter", ErrSCIMInvalidPath, op.Op)
			}
			p.remove = append(p.remove, id)
			continue
		}
		switch {
		case kind == "remove" && path == "members":
			ids, err := memberValues(op.Value)
			if err != nil {
				return nil, err
			}
			if len(ids) == 0 {
				p.removeAll, p.add, p.replaceMembers = true, nil, nil
			}
			p.remove = append(p.remove, ids...)
		case (kind == "add" || kind == "replace") && path == "members":
			ids, err := memberValues(op.Value)
			if err != nil {
				return nil, err
			}
			if kind == "replace" {
				p.replaceMembers, p.add, p.remove, p.removeAll = &ids, nil, nil, false
			} else {
				p.add = append(p.add, ids...)
			}
		case (kind == "add" || kind == "replace") && (path == "displayname" || path == "externalid"):
			var v string
			if err := json.Unmarshal(op.Value, &v); err != nil {
				return nil, fmt.Errorf("%w: %s: %v", ErrSCIMInvalidValue, op.Path, err)
			}
			if path == "displayname" {
				p.displayName = &v
			} else {
				p.externalID = &v
			}
		case kind == "remove" && path == "externalid":
			empty := ""
			p.externalID = &empty
		case (kind == "add" || kind == "replace") && path == "":
			var v struct {
				DisplayName *string         `json:"displayName"`
				ExternalID  *string         `json:"externalId"`
				Members     json.RawMessage `json:"members"`
			}
			if err := json.Unmarshal(op.Value, &v); err != nil {
				return nil, fmt.Errorf("%w: value: %v", ErrSCIMInvalidValue, err)
			}
			if v.DisplayName != nil {
				p.displayName = v.DisplayName
			}
			if v.ExternalID != nil {
				p.externalID = v.ExternalID
			}
			if len(v.Members) > 0 {
				ids, err := memberValues(v.Members)
				if err != nil {
					return nil, err
				}
				if kind == "replace" {
					p.replaceMembers, p.add, p.remove = &ids, nil, nil
				} else {
					p.add = append(p.add, ids...)
				}
			}
		default:
			return nil, fmt.Errorf("%w: %s %s", ErrSCIMInvalidPath, op.Op, op.Path)
		}
	}
	return p, nil
}

func memberValues(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var refs []SCIMRef
	if err := json.Unmarshal(raw, &refs); err != nil {
		return nil, fmt.Errorf("%w: members: %v", ErrSCIMInvalidValue, err)
	}
	if len(refs) > config.Config().SCIMMaxGroupMembers {
		return nil, ErrSCIMTooMany
	}
	ids := make([]string, 0, len(refs))
	for _, r := range refs {
		if r.Value == "" {
			return nil, fmt.Errorf("%w: member without value", ErrSCIMInvalidValue)
		}
		ids = append(ids, r.Value)
	}
	return ids, nil
}

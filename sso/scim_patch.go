package sso

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nauticana/keel/config"
)

// scimUserAttributes are the RFC 7643 User and common attributes; a PATCH of
// one keel does not keep is ignored, since directories send them routinely.
var (
	scimUserAttributes = scimSet("id", "externalid", "meta", "schemas", "username", "name", "displayname", "nickname",
		"profileurl", "title", "usertype", "preferredlanguage", "locale", "timezone", "active", "password", "emails",
		"phonenumbers", "ims", "photos", "addresses", "groups", "entitlements", "roles", "x509certificates")
	scimNameAttributes       = scimSet("formatted", "familyname", "givenname", "middlename", "honorificprefix", "honorificsuffix")
	scimEnterpriseAttributes = scimSet("employeenumber", "costcenter", "organization", "division", "department", "manager")
	scimEmailPath            = scimValuePath("emails", "type")
)

func scimSet(names ...string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out
}

// applyUserPatch applies PATCH operations to a user resource.
func applyUserPatch(u *SCIMUser, ops []SCIMPatchOp) error {
	if len(ops) > config.Config().SCIMMaxPatchOperations {
		return ErrSCIMTooMany
	}
	for _, op := range ops {
		kind := strings.ToLower(op.Op)
		if kind != "add" && kind != "replace" && kind != "remove" {
			return fmt.Errorf("%w: op %q", ErrSCIMInvalidValue, op.Op)
		}
		if strings.TrimSpace(op.Path) == "" {
			if kind == "remove" {
				return fmt.Errorf("%w: remove needs a path", ErrSCIMNoTarget)
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
	attr := strings.ToLower(strings.TrimSpace(path))
	if enterprise := strings.ToLower(SchemaEnterpriseUser); attr == enterprise || strings.HasPrefix(attr, enterprise+":") {
		if attr != enterprise && !scimEnterpriseAttributes[scimBaseAttribute(attr[len(enterprise)+1:])] {
			return fmt.Errorf("%w: %s", ErrSCIMInvalidPath, path)
		}
		return nil
	}
	attr = strings.TrimPrefix(attr, strings.ToLower(SchemaUser)+":")
	switch attr {
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
		base := scimBaseAttribute(attr)
		switch {
		case base == "emails":
			return patchEmail(u, attr, raw, remove)
		case base == "name":
			if !strings.HasPrefix(attr, "name.") || !scimNameAttributes[attr[len("name."):]] {
				return fmt.Errorf("%w: %s", ErrSCIMInvalidPath, path)
			}
		case !scimUserAttributes[base]:
			return fmt.Errorf("%w: %s", ErrSCIMInvalidPath, path)
		}
	}
	return nil
}

// scimBaseAttribute is the attribute name before a sub-attribute or filter.
func scimBaseAttribute(path string) string {
	if i := strings.IndexAny(path, ".["); i >= 0 {
		return strings.TrimSpace(path[:i])
	}
	return path
}

// patchEmail applies `emails[type eq "x"]` and `emails[type eq "x"].value`
// to the emails of that type only. A new type is added as a further,
// non-primary address.
func patchEmail(u *SCIMUser, path string, raw json.RawMessage, remove bool) error {
	typ, sub, ok := scimEmailPath.match(path)
	if !ok {
		return fmt.Errorf("%w: %s", ErrSCIMInvalidPath, path)
	}
	switch sub {
	case "", "value":
	case "primary", "type", "display":
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrSCIMInvalidPath, path)
	}
	if remove {
		kept := u.Emails[:0]
		for _, e := range u.Emails {
			if !strings.EqualFold(e.Type, typ) {
				kept = append(kept, e)
			}
		}
		u.Emails = kept
		return nil
	}
	var email SCIMEmail
	var err error
	if sub == "value" {
		err = json.Unmarshal(raw, &email.Value)
	} else {
		err = json.Unmarshal(raw, &email)
	}
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrSCIMInvalidValue, path, err)
	}
	matched := false
	for i := range u.Emails {
		if strings.EqualFold(u.Emails[i].Type, typ) {
			u.Emails[i].Value = email.Value
			if sub == "" {
				u.Emails[i].Primary = email.Primary
			}
			matched = true
		}
	}
	if !matched {
		u.Emails = append(u.Emails, SCIMEmail{Value: email.Value, Type: typ, Primary: email.Primary || len(u.Emails) == 0})
	}
	return nil
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
		raw := strings.TrimSpace(op.Path)
		if prefix := SchemaGroup + ":"; len(raw) > len(prefix) && strings.EqualFold(raw[:len(prefix)], prefix) {
			raw = raw[len(prefix):]
		}
		path := strings.ToLower(raw)
		if id, ok := memberPathValue(raw); ok {
			if kind != "remove" {
				// The filter selects a member whose only writable sub-attribute, value, is immutable.
				return nil, fmt.Errorf("%w: %s on a member filter; add or replace members instead", ErrSCIMMutability, op.Op)
			}
			p.remove = append(p.remove, id)
			continue
		}
		switch {
		case kind == "remove" && path == "":
			return nil, fmt.Errorf("%w: remove needs a path", ErrSCIMNoTarget)
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

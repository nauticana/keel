package sso

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SCIM schema URNs (RFC 7643, RFC 7644).
const (
	SchemaUser         = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup        = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaListResponse = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaPatchOp      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaError        = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// SCIMBool reads a JSON boolean, or the strings "True" and "False" some
// directories send, in any case.
type SCIMBool bool

func (b *SCIMBool) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch t := v.(type) {
	case bool:
		*b = SCIMBool(t)
	case string:
		switch strings.ToLower(t) {
		case "true":
			*b = true
		case "false":
			*b = false
		default:
			return fmt.Errorf("%w: boolean %q", ErrSCIMInvalidValue, t)
		}
	default:
		return fmt.Errorf("%w: boolean", ErrSCIMInvalidValue)
	}
	return nil
}

// SCIMUser is the core User resource keel keeps.
type SCIMUser struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id,omitempty"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	Name        *SCIMName   `json:"name,omitempty"`
	DisplayName string      `json:"displayName,omitempty"`
	Emails      []SCIMEmail `json:"emails,omitempty"`
	Active      *SCIMBool   `json:"active,omitempty"`
	Groups      []SCIMRef   `json:"groups,omitempty"`
	Meta        *SCIMMeta   `json:"meta,omitempty"`
}

type SCIMName struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	Formatted  string `json:"formatted,omitempty"`
}

type SCIMEmail struct {
	Value   string   `json:"value"`
	Type    string   `json:"type,omitempty"`
	Primary SCIMBool `json:"primary,omitempty"`
}

// SCIMRef is a group member or a user's group.
type SCIMRef struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

type SCIMMeta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
}

// SCIMGroup is the core Group resource keel keeps.
type SCIMGroup struct {
	Schemas     []string  `json:"schemas"`
	ID          string    `json:"id,omitempty"`
	ExternalID  string    `json:"externalId,omitempty"`
	DisplayName string    `json:"displayName"`
	Members     []SCIMRef `json:"members,omitempty"`
	Meta        *SCIMMeta `json:"meta,omitempty"`
}

// SCIMList is a ListResponse page.
type SCIMList[T any] struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []T      `json:"Resources"`
}

// SCIMPatch is a PatchOp request.
type SCIMPatch struct {
	Schemas    []string      `json:"schemas"`
	Operations []SCIMPatchOp `json:"Operations"`
}

// SCIMPatchOp is one operation; Op is matched without regard to case.
type SCIMPatchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// email returns the address keel stores: the primary email, else the first,
// else a userName that is an address.
func (u *SCIMUser) email() string {
	for _, e := range u.Emails {
		if e.Primary && e.Value != "" {
			return e.Value
		}
	}
	for _, e := range u.Emails {
		if e.Value != "" {
			return e.Value
		}
	}
	if strings.Contains(u.UserName, "@") {
		return u.UserName
	}
	return ""
}

func (u *SCIMUser) active() bool { return u.Active == nil || bool(*u.Active) }

func (u *SCIMUser) names() (string, string) {
	if u.Name == nil {
		return "", ""
	}
	return u.Name.GivenName, u.Name.FamilyName
}

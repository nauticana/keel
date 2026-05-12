package model

import "strings"

// ReservedActionNames are the generic-CRUD subpaths an action_name
// must not collide with — registering a table_action row whose
// action_name equals one of these would shadow the abstract CRUD
// endpoint for that table.
var ReservedActionNames = map[string]struct{}{
	"list":          {},
	"get":           {},
	"post":          {},
	"delete":        {},
	"get-paginated": {},
}

// IsReservedActionName reports whether action_name is in the reserved
// set. Case-insensitive — action_name is normalised to lowercase
// before the lookup.
func IsReservedActionName(actionName string) bool {
	_, ok := ReservedActionNames[strings.ToLower(actionName)]
	return ok
}

// TableAction is one custom button registered against a table — surfaced
// in sail's CRUD UIs alongside the built-in edit/delete/new-record
// controls. Populated by RestService.Init from the basis table_action
// table and attached to each TableDefinition.Actions slice.
//
// authorization gating uses the existing authorization_role_permission
// path: the auth_object id is the uppercased TableName, the action is
// the uppercased ActionName. Downstream apps insert the matching
// authorization_object + authorization_object_action rows in their
// seed alongside the table_action row itself.
//
// URL contract (record-level + table-level): POST {restPrefix}/{table_name}/{action_name}
// — the downstream app registers the HTTP handler at that path via its
// existing Routes(prefix) map. MethodName, when non-empty, overrides
// the {action_name} segment of the URL (useful for routing two tables'
// actions through a single shared handler).
type TableAction struct {
	TableName       string `json:"-"`              // for index keying only — not serialised to the wire
	ActionName      string `json:"action"`         // lowercase action_name
	Caption         string `json:"caption"`
	Icon            string `json:"icon,omitempty"` // Material icon name; empty → label-only
	RecordSpecific  bool   `json:"recordSpecific"` // TRUE: per-row button; FALSE: table-level
	MethodName      string `json:"-"`              // optional URL-path override; resolved into Method server-side
	Method          string `json:"method"`         // resolved URL path (POST target)
	DisplayOrder    int    `json:"displayOrder"`
	ConfirmMessage  string `json:"confirmMessage,omitempty"`
	AuthorityObject string `json:"authorityObject"` // uppercased TableName — for canExecute() check on client
	AuthorityAction string `json:"authorityCheck"`  // uppercased ActionName — for canExecute() check on client
}

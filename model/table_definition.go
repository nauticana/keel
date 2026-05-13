package model

import "fmt"

type TableDefinition struct {
	TableName          string
	PascalName         string
	Caption            string
	PartnerSpecific    bool
	// UserSpecific is set when the table has a column literally named
	// `user_id` whose FK references the user_account table. The CRUD
	// path (Get/Insert/Update/Delete) auto-injects user_id = <auth user>
	// so a row owner can never see, mutate, or delete another user's
	// rows via the generic /api/<table> endpoints. Detected by
	// LoadForeignKeys; tables that own a different user FK column
	// (e.g. ride.rider_id, ride.cancelled_by_user_id) are NOT auto-
	// scoped because they are multi-actor and need custom handlers.
	UserSpecific bool
	// PartnerUserScoped is set when the table is the user-account table
	// itself. Rows of this table belong globally (no partner_id column);
	// access by a partner-scoped role must be filtered through
	// partner_user so a PARTNER_ADMIN sees only their partner's users.
	//
	// The CRUD path (Get / Delete) injects
	//   id IN (SELECT user_id FROM partner_user WHERE partner_id = $sessionPartnerID)
	// when the caller is NOT a global-trust role (see
	// data.GlobalRoleIDs). SUPER / BUSINESS_ADMIN / SECURITY_ADMIN /
	// SECURITY_OPER / APP_ADMIN bypass the filter to manage cross-
	// partner data legitimately.
	//
	// Auto-set in AbstractRepository.Init on the table whose name matches
	// AbstractRepository.UserTableName.
	PartnerUserScoped bool
	QuotaResource      string
	QuotaPartnerColumn string
	QuotaStringColumn  string
	QuotaStringFilter  string
	QuotaDateColumn    string
	Keys               []*TableColumn
	Columns            []*TableColumn
	Children           []*ForeignKey
	Parents            []*ForeignKey
	// Actions are the custom buttons registered against this table via
	// the basis table_action seed — populated by RestService.Init.
	// Empty when no custom actions are registered. Sail consumes this
	// over the wire (TableDefinition.Actions) to render extra buttons
	// next to the built-in edit / delete / new-record controls.
	Actions []*TableAction
}

func (t *TableDefinition) TypeScriptColumnsNouser(indent string) string {
	s := ""
	for _, col := range t.Columns {
		if col.LookupStyle != "H" {
			s = s + col.GetTSDefinition(indent)
		}
	}
	return s
}

func (t *TableDefinition) TypeScriptWithChildren(baseClass string, indent string) string {
	sep := "\n"
	b := ""
	if baseClass != "" {
		b = " extends " + baseClass
	}
	s := indent + "export class " + t.PascalName + b + " {" + sep + t.TypeScriptColumnsNouser(indent+"  ")
	for _, relation := range t.Children {
		s = s + fmt.Sprintf("%s  %-30s %s[];\n", indent, relation.PascalName+"?:", relation.Child.PascalName)
	}
	return s + indent + "}" + sep
}

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
	UserSpecific       bool
	QuotaResource      string
	QuotaPartnerColumn string
	QuotaStringColumn  string
	QuotaStringFilter  string
	QuotaDateColumn    string
	Keys               []*TableColumn
	Columns            []*TableColumn
	Children           []*ForeignKey
	Parents            []*ForeignKey
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

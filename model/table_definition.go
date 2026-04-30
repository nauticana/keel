package model

import "fmt"

type TableDefinition struct {
	TableName          string
	PascalName         string
	Caption            string
	PartnerSpecific    bool
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

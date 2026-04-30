package model

type ForeignKey struct {
	Parent         *TableDefinition `json:"-"`
	Child          *TableDefinition `json:"-"`
	ParentTable    string           `json:"ParentTable"`
	ChildTable     string           `json:"ChildTable"`
	PascalName     string           `json:"PascalName"`
	ConstraintName string           `json:"ConstraintName"`
	LookupStyle    string           `json:"LookupStyle"`
	ChildColumns   []*TableColumn   `json:"Columns"`
	Columns        []string         `json:"-"`
}

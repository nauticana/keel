package model

// ParentColumns[i] can be the primary or unique key columns of the parent.
type ForeignKey struct {
	Parent         *TableDefinition `json:"-"`
	Child          *TableDefinition `json:"-"`
	ParentTable    string           `json:"ParentTable"`
	ChildTable     string           `json:"ChildTable"`
	PascalName     string           `json:"PascalName"`
	ConstraintName string           `json:"ConstraintName"`
	LookupStyle    string           `json:"LookupStyle"`
	ChildColumns   []*TableColumn   `json:"Columns"`
	ParentColumns  []*TableColumn   `json:"ParentColumns"`
	Columns        []string         `json:"-"`
}

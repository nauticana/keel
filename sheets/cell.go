package sheets

// Cell is one value written to an A1 cell such as 'Leads'!C7.
type Cell struct {
	A1    string
	Value string
}

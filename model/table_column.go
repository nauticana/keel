package model

import "fmt"

const (
	DT_STRING = "string"
	DT_INT    = "integer"
	DT_FLOAT  = "float"
	DT_BOOL   = "boolean"
	DT_TEXT   = "text"
	DT_TIME   = "timestamp"
)

var TypescriptNames = map[string]string{
	DT_BOOL:   "boolean",
	DT_INT:    "number",
	DT_FLOAT:  "number",
	DT_STRING: "string",
	DT_TEXT:   "string",
	DT_TIME:   "Date",
}

type TableColumn struct {
	ColumnName   string
	PascalName   string
	Caption      string
	DataType     string
	InputType    string
	Size         int
	Scale        int
	Step         string
	Order        int
	IsKey        bool
	Required     bool
	SequenceName string
	LookupDomain string
	LookupTable  string
	LookupStyle  string
	HasDefault   bool
	DefaultValue string
}

func (f *TableColumn) GetTypeScriptDecorator() string {
	switch f.DataType {
	case DT_INT:
		return fmt.Sprintf("@IsNumeric(%d, 0)", f.Size)
	case DT_FLOAT:
		return fmt.Sprintf("@IsNumeric(%d, %d)", f.Size, f.Scale)
	case DT_STRING:
		return fmt.Sprintf("@IsString(%d)", f.Size)
	case DT_TEXT:
		return "@IsString(4000)"
	default:
		return ""
	}
}

func (f *TableColumn) GetTsAssertion() string {
	if f.Required {
		return "!"
	}
	return "?"
}

func (f *TableColumn) GetTSDefinition(indent string) string {
	s := f.GetTypeScriptDecorator()
	if s != "" {
		s = indent + s + "\n"
	}
	return s + indent + fmt.Sprintf("%-30s %s;\n\n", f.PascalName+f.GetTsAssertion()+":", TypescriptNames[f.DataType])
}

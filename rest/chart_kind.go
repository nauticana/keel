package rest

// ChartKind is a rest_report_header.chart_kind code.
type ChartKind string

const (
	ChartNone ChartKind = "N"
	ChartBar  ChartKind = "B"
	ChartLine ChartKind = "L"
	ChartPie  ChartKind = "P"
)

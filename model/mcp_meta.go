package model

// Transport-neutral MCP response-envelope DTOs: no mcp-go dependency, so HTTP
// and chat surfaces reuse the same {data, _meta} shape. keel/mcp projects them
// onto mcp-go CallToolResults.

// Envelope wraps every MCP tool response. Meta is optional.
type Envelope struct {
	Data any           `json:"data"`
	Meta *EnvelopeMeta `json:"_meta,omitempty"`
}

// EnvelopeMeta is the provenance/pagination sidecar. Source is injected per-server.
type EnvelopeMeta struct {
	GeneratedAt string          `json:"generated_at"`
	Source      string          `json:"source,omitempty"`
	Provenance  *ProvenanceMeta `json:"provenance,omitempty"`
	Pagination  *PaginationMeta `json:"pagination,omitempty"`
}

// ProvenanceMeta carries data-quality signals for one record. VerificationLevel
// is an app-defined string; keel prescribes no enum.
type ProvenanceMeta struct {
	VerificationLevel string         `json:"verification_level,omitempty"`
	CompletenessScore float64        `json:"completeness_score,omitempty"`
	UpdatedAt         string         `json:"updated_at,omitempty"`
	VerifiedAt        string         `json:"verified_at,omitempty"`
	Sources           []SourceAttrib `json:"sources,omitempty"`
	Attribution       string         `json:"attribution,omitempty"`
}

// SourceAttrib names one upstream source a record was derived from.
type SourceAttrib struct {
	Source     string `json:"source"`
	ExternalID string `json:"external_id,omitempty"`
	ImportedAt string `json:"imported_at,omitempty"`
}

// PaginationMeta describes a list tool's result window. Total is rows on THIS
// page, not the full set (offset pagination can't know that without a COUNT).
// NextOffset is only meaningful when HasMore.
type PaginationMeta struct {
	Limit      int  `json:"limit"`
	Offset     int  `json:"offset"`
	Total      int  `json:"total"`
	HasMore    bool `json:"has_more"`
	NextOffset int  `json:"next_offset,omitempty"`
}

// FieldDescriptor describes one field of a domain schema for list_fields /
// describe_field style tools. Kind/ValueType/SourceOfTruth are app-defined.
type FieldDescriptor struct {
	Name              string   `json:"name"`
	Kind              string   `json:"kind"`
	Category          string   `json:"category,omitempty"`
	Label             string   `json:"label,omitempty"`
	Description       string   `json:"description,omitempty"`
	ValueType         string   `json:"value_type,omitempty"`
	AllowedValues     []string `json:"allowed_values,omitempty"`
	Example           string   `json:"example,omitempty"`
	RelatedQuestionID string   `json:"related_question_id,omitempty"`
	SourceOfTruth     string   `json:"source_of_truth,omitempty"`
}

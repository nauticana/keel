package document

import (
	"strings"

	"github.com/nauticana/keel/common"
)

// DocumentType is one document_type row: where documents of the type are
// stored and what an upload must satisfy.
type DocumentType struct {
	ID             string
	ContRepID      string
	MaxBytes       int64
	MediaTypes     []string
	RequiresReview bool
}

func documentTypeFromRow(id string, r []any) *DocumentType {
	var media []string
	for _, m := range strings.Split(common.AsString(r[2]), ",") {
		if m = strings.TrimSpace(m); m != "" {
			media = append(media, m)
		}
	}
	return &DocumentType{ID: id, ContRepID: common.AsString(r[0]), MaxBytes: common.AsInt64(r[1]), MediaTypes: media, RequiresReview: common.AsBool(r[3])}
}

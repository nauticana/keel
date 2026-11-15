package document

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"mime"
	"slices"
	"unicode/utf8"

	"github.com/nauticana/keel/common"
)

// textFormats are the formats a body sniffed as text/plain is admitted as
// when its type declares one and the body passes the format's check.
var textFormats = map[string]func([]byte) bool{
	"text/markdown":    func([]byte) bool { return true },
	"application/json": json.Valid,
	"text/csv": func(raw []byte) bool {
		_, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
		return err == nil
	},
}

// sniff returns the media type detected from the bytes, or the first declared
// text format a UTF-8 text/plain body satisfies, refusing anything the type
// does not allow. The client's claim is never used.
func sniff(raw []byte, allowed []string) (string, error) {
	mediaType, _, err := mime.ParseMediaType(common.DetectMediaType(raw))
	if err == nil && slices.Contains(allowed, mediaType) {
		return mediaType, nil
	}
	if err == nil && mediaType == "text/plain" && utf8.Valid(raw) {
		for _, declared := range allowed {
			if valid, ok := textFormats[declared]; ok && valid(raw) {
				return declared, nil
			}
		}
	}
	return "", fmt.Errorf("%w: %s", ErrMediaType, mediaType)
}

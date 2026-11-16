package document

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"mime"
	"slices"
	"unicode/utf8"

	"github.com/nauticana/keel/common"
)

const svgNamespace = "http://www.w3.org/2000/svg"

// textFormats are, per sniffed text type, the formats a body is admitted as
// when its type declares one and the body passes the format's check.
var textFormats = map[string]map[string]func([]byte) bool{
	"text/plain": {
		"text/markdown":    func([]byte) bool { return true },
		"application/json": json.Valid,
		"text/csv": func(raw []byte) bool {
			_, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
			return err == nil
		},
		"image/svg+xml": isSVG,
	},
	"text/xml": {"image/svg+xml": isSVG},
}

// isSVG reports whether the root element is svg in the SVG namespace.
func isSVG(raw []byte) bool {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		if root, ok := tok.(xml.StartElement); ok {
			return root.Name.Local == "svg" && root.Name.Space == svgNamespace
		}
	}
}

// sniff returns the media type detected from the bytes, or the first declared
// text format a UTF-8 text body satisfies, refusing anything the type does
// not allow. The client's claim is never used.
func sniff(raw []byte, allowed []string) (string, error) {
	mediaType, _, err := mime.ParseMediaType(common.DetectMediaType(raw))
	if err == nil && slices.Contains(allowed, mediaType) {
		return mediaType, nil
	}
	if err == nil && utf8.Valid(raw) {
		for _, declared := range allowed {
			if valid, ok := textFormats[mediaType][declared]; ok && valid(raw) {
				return declared, nil
			}
		}
	}
	return "", fmt.Errorf("%w: %s", ErrMediaType, mediaType)
}

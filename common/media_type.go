package common

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"net/http"
	"strings"
)

const (
	ooxmlTypePrefix      = "application/vnd.openxmlformats-officedocument."
	ooxmlMainPartSuffix  = ".main+xml"
	maxContentTypesBytes = 1 << 20
)

// DetectMediaType is http.DetectContentType, except that an OOXML container
// (DOCX, XLSX, PPTX), which it reports as application/zip, is reported by the
// media type of its main part.
func DetectMediaType(raw []byte) string {
	detected := http.DetectContentType(raw)
	if detected != "application/zip" {
		return detected
	}
	if ooxml := ooxmlMediaType(raw); ooxml != "" {
		return ooxml
	}
	return detected
}

func ooxmlMediaType(raw []byte) string {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return ""
	}
	part, err := zr.Open("[Content_Types].xml")
	if err != nil {
		return ""
	}
	defer part.Close()
	var types struct {
		Overrides []struct {
			PartName    string `xml:"PartName,attr"`
			ContentType string `xml:"ContentType,attr"`
		} `xml:"Override"`
	}
	if err := xml.NewDecoder(io.LimitReader(part, maxContentTypesBytes)).Decode(&types); err != nil {
		return ""
	}
	for _, o := range types.Overrides {
		if strings.HasPrefix(o.ContentType, ooxmlTypePrefix) && strings.HasSuffix(o.ContentType, ooxmlMainPartSuffix) &&
			hasZipPart(zr, strings.TrimPrefix(o.PartName, "/")) {
			return strings.TrimSuffix(o.ContentType, ooxmlMainPartSuffix)
		}
	}
	return ""
}

func hasZipPart(zr *zip.Reader, name string) bool {
	for _, file := range zr.File {
		if strings.EqualFold(file.Name, name) {
			return true
		}
	}
	return false
}

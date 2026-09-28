package common

import (
	"archive/zip"
	"bytes"
	"testing"
)

func zipWith(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func contentTypes(partName, mainPart string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
<Override PartName="/` + partName + `" ContentType="` + mainPart + `"/>
</Types>`
}

func TestDetectMediaType(t *testing.T) {
	cases := map[string]struct {
		raw  []byte
		want string
	}{
		"docx": {zipWith(t, map[string]string{"[Content_Types].xml": contentTypes("word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"), "word/document.xml": ""}),
			"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
		"xlsx": {zipWith(t, map[string]string{"[Content_Types].xml": contentTypes("xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"), "xl/workbook.xml": ""}),
			"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
		"part name case": {zipWith(t, map[string]string{"[Content_Types].xml": contentTypes("word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"), "Word/Document.xml": ""}),
			"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
		"missing main part":       {zipWith(t, map[string]string{"[Content_Types].xml": contentTypes("word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml")}), "application/zip"},
		"macro-enabled stays zip": {zipWith(t, map[string]string{"[Content_Types].xml": contentTypes("word/document.xml", "application/vnd.ms-word.document.macroEnabled.main+xml"), "word/document.xml": ""}), "application/zip"},
		"plain zip":               {zipWith(t, map[string]string{"a.txt": "a"}), "application/zip"},
		"malformed content types": {zipWith(t, map[string]string{"[Content_Types].xml": "<Types"}), "application/zip"},
		"pdf":                     {[]byte("%PDF-1.7\n"), "application/pdf"},
	}
	for name, c := range cases {
		if got := DetectMediaType(c.raw); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

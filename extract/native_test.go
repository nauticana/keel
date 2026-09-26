package extract

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/lzw"
	"compress/zlib"
	"context"
	"encoding/ascii85"
	"errors"
	"fmt"
	"hash/adler32"
	"io"
	"strings"
	"testing"
)

var native = Native{MaxBytes: 1 << 20}

func section(t *testing.T, e Extracted, i int) Section {
	t.Helper()
	if i >= len(e.Sections) {
		t.Fatalf("section %d missing: %+v in %q", i, e.Sections, e.Text)
	}
	return e.Sections[i]
}

func text(e Extracted, s Section) string { return e.Text[s.Start:s.End] }

func TestMarkdown(t *testing.T) {
	e, err := native.Extract(context.Background(), "text/markdown; charset=utf-8", []byte("## Title\r\nBody line\n\nSecond.\n\n#hashtag"))
	if err != nil {
		t.Fatal(err)
	}
	if s := section(t, e, 0); s.Kind != Heading || s.Level != 2 || text(e, s) != "## Title" {
		t.Errorf("heading: %+v %q", s, text(e, s))
	}
	if s := section(t, e, 1); s.Kind != Paragraph || text(e, s) != "Body line" {
		t.Errorf("body under the heading: %+v %q", s, text(e, s))
	}
	if s := section(t, e, 3); s.Kind != Paragraph {
		t.Errorf("#hashtag is not a heading: %+v", s)
	}
	e, _ = native.Extract(context.Background(), mediaMarkdown, []byte("Intro\n## Section\nBody"))
	var got []string
	for _, s := range e.Sections {
		got = append(got, fmt.Sprintf("%s/%d:%s", s.Kind, s.Level, text(e, s)))
	}
	if strings.Join(got, "|") != "paragraph/0:Intro|heading/2:## Section|paragraph/0:Body" {
		t.Errorf("a heading inside a block: %v", got)
	}
	if e, _ := native.Extract(context.Background(), "text/plain", []byte("# not a heading")); e.Sections[0].Kind != Paragraph {
		t.Error("plain text has no headings")
	}
}

const docNS = `xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"`

func docx(t *testing.T, body, styles string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("word/document.xml")
	fmt.Fprintf(w, "<?xml version=\"1.0\"?>\n<w:document %s>\n  <w:body>\n%s\n  </w:body>\n</w:document>", docNS, body)
	if styles != "" {
		s, _ := zw.Create("word/styles.xml")
		fmt.Fprintf(s, `<w:styles %s>%s</w:styles>`, docNS, styles)
	}
	zw.Close()
	return buf.Bytes()
}

func extractDoc(t *testing.T, body, styles string) Extracted {
	t.Helper()
	e, err := native.Extract(context.Background(), mediaDOCX, docx(t, body, styles))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestDOCXBodyTextOnly(t *testing.T) {
	e := extractDoc(t, `
    <w:p>
      <w:pPr><w:tabs><w:tab w:val="left" w:pos="720"/><w:tab w:val="left" w:pos="1440"/></w:tabs></w:pPr>
      <w:r><w:t>Clause</w:t></w:r>
    </w:p>
    <w:p><w:r><w:t xml:space="preserve">Pay </w:t></w:r><w:del><w:r><w:delText>100</w:delText></w:r></w:del><w:ins><w:r><w:t>200</w:t></w:r></w:ins></w:p>
    <w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText> HYPERLINK "http://x" </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>link</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>
    <w:p><w:r><w:t>a</w:t><w:tab/><w:t>b</w:t></w:r></w:p>`, "")
	want := []string{"Clause", "Pay 200", "link", "a\tb"}
	for i, w := range want {
		if s := section(t, e, i); text(e, s) != w {
			t.Errorf("section %d = %q, want %q", i, text(e, s), w)
		}
	}
	if strings.Contains(e.Text, "  ") || strings.Contains(e.Text, "HYPERLINK") {
		t.Errorf("indentation or field code leaked: %q", e.Text)
	}
}

func TestDOCXHeadingsAndTables(t *testing.T) {
	styles := `<w:style w:styleId="berschrift2"><w:name w:val="heading 2"/></w:style>` +
		`<w:style w:styleId="Titel"><w:name w:val="Title"/></w:style>` +
		`<w:style w:styleId="Kapitel"><w:name w:val="Kapitel"/><w:pPr><w:outlineLvl w:val="2"/></w:pPr></w:style>`
	e := extractDoc(t, `
    <w:p><w:pPr><w:pStyle w:val="Titel"/></w:pPr><w:r><w:t>Vertrag</w:t></w:r></w:p>
    <w:p><w:pPr><w:pStyle w:val="berschrift2"/></w:pPr><w:r><w:t>Zahlung</w:t></w:r></w:p>
    <w:p><w:pPr><w:pStyle w:val="Kapitel"/></w:pPr><w:r><w:t>Anhang</w:t></w:r></w:p>
    <w:tbl><w:tr>
      <w:tc><w:p><w:r><w:t>line1</w:t></w:r></w:p><w:p><w:r><w:t>line2</w:t></w:r></w:p></w:tc>
      <w:tc><w:p><w:r><w:t>b</w:t></w:r></w:p></w:tc>
    </w:tr></w:tbl>`, styles)
	for i, want := range []struct {
		kind  string
		level int
		text  string
	}{{Heading, 1, "Vertrag"}, {Heading, 2, "Zahlung"}, {Heading, 3, "Anhang"}, {Table, 0, "line1\nline2\tb\t\n"}} {
		if s := section(t, e, i); s.Kind != want.kind || s.Level != want.level || text(e, s) != want.text {
			t.Errorf("section %d = %s/%d %q, want %s/%d %q", i, s.Kind, s.Level, text(e, s), want.kind, want.level, want.text)
		}
	}
}

func kinds(e Extracted) string {
	var got []string
	for _, s := range e.Sections {
		got = append(got, fmt.Sprintf("%s/%d:%s", s.Kind, s.Level, text(e, s)))
	}
	return strings.Join(got, "|")
}

func TestDOCXTextBoxOnce(t *testing.T) {
	e := extractDoc(t, `<w:p xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006">
      <w:r><w:t xml:space="preserve">Before </w:t></w:r>
      <w:r><mc:AlternateContent>
        <mc:Choice Requires="wps"><w:drawing><w:txbxContent><w:p><w:r><w:t>Boxed</w:t></w:r></w:p></w:txbxContent></w:drawing></mc:Choice>
        <mc:Fallback><w:pict><w:txbxContent><w:p><w:r><w:t>Boxed</w:t></w:r></w:p></w:txbxContent></w:pict></mc:Fallback>
      </mc:AlternateContent></w:r>
      <w:r><w:t xml:space="preserve"> After</w:t></w:r>
    </w:p>`, "")
	if got := kinds(e); got != "paragraph/0:Before  After|paragraph/0:Boxed" {
		t.Errorf("text box: %s in %q", got, e.Text)
	}
	if strings.Count(e.Text, "Boxed") != 1 {
		t.Errorf("the legacy copy must be skipped: %q", e.Text)
	}
}

func TestDOCXTrackedChanges(t *testing.T) {
	e := extractDoc(t, `
    <w:p><w:pPr><w:pStyle w:val="Normal"/><w:pPrChange><w:pPr><w:pStyle w:val="Heading1"/></w:pPr></w:pPrChange></w:pPr><w:r><w:t>Now body</w:t></w:r></w:p>
    <w:p><w:moveFrom><w:r><w:t>Moved</w:t></w:r></w:moveFrom></w:p>
    <w:p><w:moveTo><w:r><w:t>Moved</w:t></w:r></w:moveTo></w:p>`, "")
	if got := kinds(e); got != "paragraph/0:Now body|paragraph/0:Moved" {
		t.Errorf("tracked changes: %s", got)
	}
}

func TestDOCXDerivedAndDefaultStyles(t *testing.T) {
	styles := `<w:style w:styleId="Heading1"><w:name w:val="heading 1"/></w:style>` +
		`<w:style w:styleId="ContractHeading"><w:name w:val="Contract Heading"/><w:basedOn w:val="Heading1"/></w:style>`
	e := extractDoc(t, `<w:p><w:pPr><w:pStyle w:val="ContractHeading"/></w:pPr><w:r><w:t>Terms</w:t></w:r></w:p>`, styles)
	if got := kinds(e); got != "heading/1:Terms" {
		t.Errorf("derived style: %s", got)
	}
	e = extractDoc(t, `<w:p><w:pPr><w:pStyle w:val="Heading3"/></w:pPr><w:r><w:t>Scope</w:t></w:r></w:p>`, "")
	if got := kinds(e); got != "heading/3:Scope" {
		t.Errorf("default id without styles.xml: %s", got)
	}
}

func TestDOCXDecompressionCap(t *testing.T) {
	body := `<w:p><w:r><w:t>` + strings.Repeat("A", 4<<20) + `</w:t></w:r></w:p>`
	raw := docx(t, body, "")
	if len(raw) > 64<<10 {
		t.Fatalf("fixture should compress well: %d", len(raw))
	}
	if _, err := native.Extract(context.Background(), mediaDOCX, raw); !errors.Is(err, ErrTooLarge) {
		t.Errorf("a zip bomb must stop at MaxBytes: %v", err)
	}
	if _, err := native.Extract(context.Background(), mediaDOCX, []byte("not a zip")); err == nil {
		t.Error("garbage must be an error")
	}
}

// pdfFixture writes a PDF whose pages hold the given texts ("" = no text layer).
func pdfFixture(pages ...string) []byte {
	var objects []string
	objects = append(objects, "<< /Type /Catalog /Pages 2 0 R >>", "")
	var kids []string
	for _, p := range pages {
		pageObj, streamObj := len(objects)+1, len(objects)+2
		kids = append(kids, fmt.Sprintf("%d 0 R", pageObj))
		stream := ""
		if p != "" {
			stream = fmt.Sprintf("BT /F1 12 Tf 72 720 Td (%s) Tj ET", p)
		}
		objects = append(objects,
			fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents %d 0 R /Resources << /Font << /F1 %d 0 R >> >> >>", streamObj, 3+2*len(pages)),
			fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream))
	}
	objects[1] = fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(pages))
	objects = append(objects, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	var b strings.Builder
	b.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects))
	for i, obj := range objects {
		offsets[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, obj)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, off := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return []byte(b.String())
}

func TestPDF(t *testing.T) {
	e, err := native.Extract(context.Background(), mediaPDF, pdfFixture("Hello PDF", ""))
	if err != nil {
		t.Fatal(err)
	}
	if s := section(t, e, 0); s.Kind != Page || s.Page != 1 || !strings.Contains(text(e, s), "Hello PDF") {
		t.Errorf("page 1: %+v %q", s, text(e, s))
	}
	if pages := e.EmptyPages(); len(pages) != 1 || pages[0] != 2 {
		t.Errorf("a page without a text layer must be reported for OCR: %v", pages)
	}
	if _, err := native.Extract(context.Background(), mediaPDF, []byte("%PDF-1.4 garbage")); err == nil {
		t.Error("a malformed PDF must be an error, not a panic")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := native.Extract(ctx, mediaPDF, pdfFixture("x")); !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled request must stop: %v", err)
	}
}

// streamPDF wraps stream objects, given as (dict, data) pairs, in a PDF shell.
func streamPDF(objects ...[2]string) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	for i, o := range objects {
		fmt.Fprintf(&b, "%d 0 obj\n%s\nstream\n%s\nendstream\nendobj\n", i+1, o[0], o[1])
	}
	return b.Bytes()
}

func zlibBytes(n int) []byte {
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write(make([]byte, n))
	zw.Close()
	return z.Bytes()
}

func TestPDFDecompressionBombs(t *testing.T) {
	const limit = 1 << 20
	n := Native{MaxBytes: limit}
	bomb := zlibBytes(4 << 20)

	var a85 bytes.Buffer
	enc := ascii85.NewEncoder(&a85)
	enc.Write(bomb)
	enc.Close()

	var lz bytes.Buffer
	lw := lzw.NewWriter(&lz, lzw.MSB, 8)
	lw.Write(make([]byte, 4<<20))
	lw.Close()

	// A literal "endstream" in a stored (uncompressed) deflate block at the
	// start, followed by compressed zeros: an endstream search stops early.
	marker, zeros := []byte("endstream"), make([]byte, 4<<20)
	var hidden bytes.Buffer
	hidden.Write([]byte{0x78, 0x01, 0x00, byte(len(marker)), 0, ^byte(len(marker)), 0xff})
	hidden.Write(marker)
	fw, _ := flate.NewWriter(&hidden, flate.BestCompression)
	fw.Write(zeros)
	fw.Close()
	sum := adler32.New()
	sum.Write(marker)
	sum.Write(zeros)
	hidden.Write(sum.Sum(nil))
	if r, err := zlib.NewReader(bytes.NewReader(hidden.Bytes())); err != nil {
		t.Fatal(err)
	} else if n, err := io.Copy(io.Discard, r); err != nil || n != int64(len(marker)+len(zeros)) {
		t.Fatalf("hidden-endstream fixture is not valid zlib: %d %v", n, err)
	}

	image := zlibBytes(limit / 4)
	var images [][2]string
	for range 8 {
		images = append(images, [2]string{fmt.Sprintf("<< /Type /XObject /Subtype /Image /Length %d /Filter /FlateDecode >>", len(image)), string(image)})
	}

	for name, raw := range map[string][]byte{
		"flate":            streamPDF([2]string{fmt.Sprintf("<< /Length %d /Filter /FlateDecode >>", len(bomb)), string(bomb)}),
		"ascii85 + flate":  streamPDF([2]string{fmt.Sprintf("<< /Length %d /Filter [/ASCII85Decode /FlateDecode] >>", a85.Len()+2), a85.String() + "~>"}),
		"lzw":              streamPDF([2]string{fmt.Sprintf("<< /Length %d /Filter /LZWDecode >>", lz.Len()), lz.String()}),
		"hidden endstream": streamPDF([2]string{fmt.Sprintf("<< /Length %d /Filter /FlateDecode >>", hidden.Len()), hidden.String()}),
		"indirect length":  append(streamPDF([2]string{"<< /Length 9 0 R /Filter /FlateDecode >>", string(bomb)}), []byte(fmt.Sprintf("9 0 obj\n%d\nendobj\n", len(bomb)))...),
		"8 images":         streamPDF(images...),
	} {
		if len(raw) > 512<<10 {
			t.Fatalf("%s: fixture should be small: %d", name, len(raw))
		}
		if _, err := n.Extract(context.Background(), mediaPDF, raw); !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: must be refused before parsing: %v", name, err)
		}
	}
	if !bytes.Contains(hidden.Bytes(), []byte("endstream")) {
		t.Fatal("the hidden-endstream fixture lost its marker")
	}
	if _, err := n.Extract(context.Background(), mediaPDF, append(pdfFixture("x"), []byte("trailer << /Encrypt 7 0 R >>")...)); !errors.Is(err, ErrEncrypted) {
		t.Errorf("an encrypted PDF cannot be measured and must be refused: %v", err)
	}
}

// TestPDFParserMismatchBombs holds files that read differently to the
// regex-based pre-check than to gopdf's parser; each is a bomb gopdf decodes.
// They pass until gopdf enforces decode limits itself (gopdf#44, TODO C15).
func TestPDFParserMismatchBombs(t *testing.T) {
	t.Skip("known gap: the pre-check is not a PDF parser; waits for gopdf#44 (TODO C15)")
	bomb := zlibBytes(4 << 20)
	obj := func(dict, keyword string) []byte {
		return []byte(fmt.Sprintf("%%PDF-1.4\n1 0 obj\n%s\n%s%s\nendstream\nendobj\n", dict, keyword, bomb))
	}
	n := len(bomb)
	for name, raw := range map[string][]byte{
		"fake object header in a string": obj(fmt.Sprintf("<< /Filter /FlateDecode /Length %d /T (9 9 obj) >>", n), "stream\n"),
		"nested dict first":              obj(fmt.Sprintf("<< /X << /Filter /DCTDecode >> /Filter /FlateDecode /Length %d >>", n), "stream\n"),
		"same key twice":                 obj(fmt.Sprintf("<< /Filter /DCTDecode /Filter /FlateDecode /Length %d >>", n), "stream\n"),
		"escaped name":                   obj(fmt.Sprintf("<< /Filter /Flate#44ecode /Length %d >>", n), "stream\n"),
		"space after the keyword":        obj(fmt.Sprintf("<< /Filter /FlateDecode /Length %d >>", n), "stream \n"),
		"nested short length first":      obj(fmt.Sprintf("<< /X << /Length 3 >> /Filter /FlateDecode /Length %d >>", n), "stream\n"),
	} {
		if _, err := (Native{MaxBytes: 1 << 20}).Extract(context.Background(), mediaPDF, raw); !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: must be refused: %v", name, err)
		}
	}
}

func TestLimitsUnsupportedAndFactory(t *testing.T) {
	if _, err := (Native{MaxBytes: 4}).Extract(context.Background(), mediaPlain, []byte("too long")); !errors.Is(err, ErrTooLarge) {
		t.Errorf("plain over the cap: %v", err)
	}
	if _, err := (Native{}).Extract(context.Background(), mediaPlain, nil); err == nil {
		t.Error("a zero MaxBytes must be refused")
	}
	if _, err := native.Extract(context.Background(), "image/png", nil); !errors.Is(err, ErrUnsupportedMediaType) {
		t.Errorf("image: %v", err)
	}
	if native.Supports("image/png") || !native.Supports("application/pdf") {
		t.Error("Supports")
	}
	if _, err := New("native", 1); err != nil {
		t.Error(err)
	}
	if _, err := New("native", 0); err == nil {
		t.Error("a zero cap must fail at construction")
	}
	if _, err := New("tesseract", 1); err == nil {
		t.Error("unknown mode must fail")
	}
}

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
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/carlos7ags/folio/document"
	"github.com/carlos7ags/folio/font"
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

// pdfDoc writes a PDF whose objects are objs[i] for object number i+1,
// with the catalog first.
func pdfDoc(objs ...string) []byte {
	var b strings.Builder
	b.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objs))
	for i, obj := range objs {
		offsets[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, obj)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, off := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return []byte(b.String())
}

func streamObj(dict, data string) string {
	return fmt.Sprintf("<< %s /Length %d >>\nstream\n%s\nendstream", dict, len(data), data)
}

// pdfFixture writes a PDF whose pages hold the given texts ("" = no text layer).
func pdfFixture(pages ...string) []byte {
	objs := []string{"<< /Type /Catalog /Pages 2 0 R >>", ""}
	var kids []string
	for _, p := range pages {
		pageObj, contentObj := len(objs)+1, len(objs)+2
		kids = append(kids, fmt.Sprintf("%d 0 R", pageObj))
		content := ""
		if p != "" {
			content = fmt.Sprintf("BT /F1 12 Tf 72 720 Td (%s) Tj ET", p)
		}
		objs = append(objs,
			fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents %d 0 R /Resources << /Font << /F1 %d 0 R >> >> >>", contentObj, 3+2*len(pages)),
			streamObj("", content))
	}
	objs[1] = fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(pages))
	objs = append(objs, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	return pdfDoc(objs...)
}

// onePage writes a one-page PDF with the given resources whose content
// stream is object 4; more objects follow from 5.
func onePage(resources, content string, more ...string) []byte {
	return pdfDoc(append([]string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << %s >> >>", resources),
		content,
	}, more...)...)
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

// A scanned page carries its OCR text in render mode 3 (invisible).
func TestPDFInvisibleTextLayer(t *testing.T) {
	raw := onePage("/Font << /F1 5 0 R >>", streamObj("", "BT 3 Tr /F1 12 Tf 72 720 Td (Scanned words) Tj ET"),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	e, err := native.Extract(context.Background(), mediaPDF, raw)
	if err != nil {
		t.Fatal(err)
	}
	if s := section(t, e, 0); text(e, s) != "Scanned words" {
		t.Errorf("the invisible OCR layer must be extracted: %q", text(e, s))
	}
}

func TestPDFEncryption(t *testing.T) {
	encrypted := func(user, owner string) []byte {
		doc := document.NewDocument(document.PageSizeLetter)
		doc.SetEncryption(document.EncryptionConfig{Algorithm: document.EncryptAES256, UserPassword: user, OwnerPassword: owner})
		doc.AddPage().AddText("Protected text", font.Helvetica, 12, 72, 700)
		var buf bytes.Buffer
		if _, err := doc.WriteTo(&buf); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	e, err := native.Extract(context.Background(), mediaPDF, encrypted("", "owner"))
	if err != nil || !strings.Contains(e.Text, "Protected text") {
		t.Errorf("an empty user password opens the document: %q %v", e.Text, err)
	}
	if _, err := native.Extract(context.Background(), mediaPDF, encrypted("user", "owner")); !errors.Is(err, ErrEncrypted) {
		t.Errorf("a password-protected PDF must be refused: %v", err)
	}
}

func zlibBytes(n int) []byte {
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write(make([]byte, n))
	zw.Close()
	return z.Bytes()
}

// allocated returns the bytes the Go heap allocated while f ran.
func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// Each fixture is a few hundred KB that inflates to 64 MiB. With a 1 MiB
// limit, extraction must not allocate anywhere near the inflated size, and
// a stream the parser does decode must be refused with ErrTooLarge. The dictionary variants are
// ones a pattern-based pre-check misreads; the parser itself enforces the
// limit, so they are no different.
func TestPDFDecompressionBombs(t *testing.T) {
	const limit, inflated = 1 << 20, 64 << 20
	n := Native{MaxBytes: limit}
	bomb := string(zlibBytes(inflated))

	var a85 bytes.Buffer
	enc := ascii85.NewEncoder(&a85)
	enc.Write([]byte(bomb))
	enc.Close()

	var lz bytes.Buffer
	lw := lzw.NewWriter(&lz, lzw.MSB, 8)
	lw.Write(make([]byte, inflated))
	lw.Close()

	// A literal "endstream" in a stored deflate block, then compressed zeros.
	marker, zeros := []byte("endstream"), make([]byte, inflated)
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

	raw := func(dict, keyword, data string) string {
		return fmt.Sprintf("<< %s >>\n%s%s\nendstream", dict, keyword, data)
	}
	flateDict := fmt.Sprintf("/Filter /FlateDecode /Length %d", len(bomb))
	image := zlibBytes(limit / 4)
	var imageRes, draws []string
	var images []string
	for i := range 8 {
		imageRes = append(imageRes, fmt.Sprintf("/Im%d %d 0 R", i, 5+i))
		draws = append(draws, fmt.Sprintf("q 10 0 0 10 0 0 cm /Im%d Do Q", i))
		images = append(images, streamObj("/Type /XObject /Subtype /Image /Width 512 /Height 512 /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode", string(image)))
	}

	refused := map[string][]byte{
		"flate":                          onePage("", raw(flateDict, "stream\n", bomb)),
		"ascii85 + flate":                onePage("", streamObj("/Filter [/ASCII85Decode /FlateDecode]", a85.String()+"~>")),
		"hidden endstream":               onePage("", streamObj("/Filter /FlateDecode", hidden.String())),
		"indirect length":                onePage("", raw("/Filter /FlateDecode /Length 5 0 R", "stream\n", bomb), strconv.Itoa(len(bomb))),
		"fake object header in a string": onePage("", raw(flateDict+" /T (9 9 obj)", "stream\n", bomb)),
		"nested dict first":              onePage("", raw("/X << /Filter /DCTDecode >> "+flateDict, "stream\n", bomb)),
		"same key twice":                 onePage("", raw("/Filter /DCTDecode "+flateDict, "stream\n", bomb)),
		"escaped name":                   onePage("", raw(fmt.Sprintf("/Filter /Flate#44ecode /Length %d", len(bomb)), "stream\n", bomb)),
		"nested short length first":      onePage("", raw("/X << /Length 3 >> "+flateDict, "stream\n", bomb)),
	}
	bounded := map[string][]byte{
		"lzw, which the parser leaves encoded": onePage("", streamObj("/Filter /LZWDecode", lz.String())),
		"space after the keyword":              onePage("", raw(flateDict, "stream \n", bomb)),
		"8 images":                             onePage("/XObject << "+strings.Join(imageRes, " ")+" >>", streamObj("", strings.Join(draws, " ")), images...),
	}
	for name, fixture := range refused {
		var err error
		if a := allocated(func() { _, err = n.Extract(context.Background(), mediaPDF, fixture) }); a > inflated/4 {
			t.Errorf("%s: allocated %d MiB", name, a>>20)
		}
		if !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: must be refused: %v", name, err)
		}
	}
	for name, fixture := range bounded {
		if a := allocated(func() { n.Extract(context.Background(), mediaPDF, fixture) }); a > inflated/4 {
			t.Errorf("%s: allocated %d MiB", name, a>>20)
		}
	}
}

// The tests below wait for folio fixes (TODO C15); un-skip them when keel
// pins a folio release that contains them.

func TestPDFFormOwnResources(t *testing.T) {
	t.Skip("waits for folio#458: a form's fonts are looked up in the page's resources")
	cmap := "/CIDInit /ProcSet findresource begin 12 dict begin begincmap /CMapName /T def 1 begincodespacerange <00> <FF> endcodespacerange 2 beginbfchar <01> <0048> <02> <0069> endbfchar endcmap CMapName currentdict /CMap defineresource pop end end"
	raw := onePage("/XObject << /Fm1 5 0 R >>", streamObj("", "/Fm1 Do"),
		streamObj("/Type /XObject /Subtype /Form /BBox [0 0 612 792] /Resources << /Font << /F1 6 0 R >> >>", "BT /F1 12 Tf 72 720 Td <0102> Tj ET"),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /ToUnicode 7 0 R >>",
		streamObj("", cmap))
	e, err := native.Extract(context.Background(), mediaPDF, raw)
	if err != nil || e.Text != "Hi\f" {
		t.Errorf("text in a form's own font: %q %v", e.Text, err)
	}
}

func TestPDFSimpleFontWideCodespace(t *testing.T) {
	t.Skip("waits for folio#459: a simple font is split by its ToUnicode codespace width")
	cmap := "/CIDInit /ProcSet findresource begin 12 dict begin begincmap /CMapName /W def 1 begincodespacerange <0000> <FFFF> endcodespacerange 2 beginbfchar <48> <0048> <69> <0069> endbfchar endcmap CMapName currentdict /CMap defineresource pop end end"
	raw := onePage("/Font << /F1 5 0 R >>", streamObj("", "BT /F1 12 Tf 72 720 Td (Hi) Tj ET"),
		"<< /Type /Font /Subtype /TrueType /BaseFont /Arial /Encoding /WinAnsiEncoding /ToUnicode 6 0 R >>",
		streamObj("", cmap))
	e, err := native.Extract(context.Background(), mediaPDF, raw)
	if err != nil || e.Text != "Hi\f" {
		t.Errorf("one-byte codes in a simple font: %q %v", e.Text, err)
	}
}

// 40 forms, each drawing the next twice, is 2^39 draws from a few KB.
func TestPDFNestedFormsBounded(t *testing.T) {
	t.Skip("waits for folio#457: nested forms are bounded by depth only, so this runs for days")
	var names, forms []string
	for i := range 40 {
		names = append(names, fmt.Sprintf("/X%d %d 0 R", i, 5+i))
	}
	res := "/XObject << " + strings.Join(names, " ") + " >>"
	for i := range 40 {
		body := "0 0 m 1 1 l S"
		if i < 39 {
			body = fmt.Sprintf("/X%d Do /X%d Do", i+1, i+1)
		}
		forms = append(forms, streamObj("/Type /XObject /Subtype /Form /BBox [0 0 1 1] /Resources << "+res+" >>", body))
	}
	start := time.Now()
	if _, err := native.Extract(context.Background(), mediaPDF, onePage(res, streamObj("", "/X0 Do"), forms...)); err == nil {
		t.Error("an exponential form graph must be refused")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("took %v", d)
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

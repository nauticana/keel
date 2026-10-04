package extract

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
)

func runChildMain(args []string, stdin []byte) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := ChildMain(args, bytes.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestChildMain(t *testing.T) {
	raw := pdfFixture("Hello <child> & \x01")
	code, stdout, stderr := runChildMain([]string{"--media_type=application/pdf", "--max_bytes=1048576"}, raw)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	got, err := decodeResult([]byte(stdout))
	want, _ := native.Extract(context.Background(), mediaPDF, raw)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("round trip: %+v %v, want %+v", got, err, want)
	}

	for name, tc := range map[string]struct {
		args  []string
		stdin []byte
		code  int
	}{
		"no flags":      {nil, nil, childExitUsage},
		"no max":        {[]string{"--media_type=text/plain"}, nil, childExitUsage},
		"positional":    {[]string{"--media_type=text/plain", "--max_bytes=9", "extra"}, nil, childExitUsage},
		"unknown flag":  {[]string{"--media_type=text/plain", "--max_bytes=9", "--x=1"}, nil, childExitUsage},
		"stdin too big": {[]string{"--media_type=application/pdf", "--max_bytes=4"}, []byte("%PDF-1.4"), childExitTooLarge},
		"text too big":  {[]string{"--media_type=application/pdf", "--max_bytes=300"}, pdfFixture(strings.Repeat("long text ", 30)), childExitTooLarge},
		"encrypted":     {[]string{"--media_type=application/pdf", "--max_bytes=1048576"}, encryptedPDF(t, "user", "owner"), childExitEncrypted},
		"unsupported":   {[]string{"--media_type=image/png", "--max_bytes=9"}, nil, childExitUnsupported},
		"malformed":     {[]string{"--media_type=application/pdf", "--max_bytes=1048576"}, []byte("%PDF-1.4 garbage"), childExitUnreadable},
	} {
		if code, stdout, _ := runChildMain(tc.args, tc.stdin); code != tc.code || stdout != "" {
			t.Errorf("%s: exit %d with %q, want %d", name, code, stdout, tc.code)
		}
	}
}

func TestDecodeResultStrict(t *testing.T) {
	var ok bytes.Buffer
	if err := encodeResult(&ok, Extracted{Text: "ab", Sections: []Section{{Kind: Paragraph, Start: 0, End: 2}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeResult(ok.Bytes()); err != nil {
		t.Errorf("a valid result: %v", err)
	}
	for _, bad := range []string{
		``, `null`, `[]`, `{"version":1,"Text":"a"} x`, `{"version":1,"Text":"a"}}`,
		`{"Text":"a"}`, `{"version":1,"Text":"a","Sections":[{"Kind":"img","Start":0,"End":1}]}`,
		`{"version":1,"Text":"a","Sections":[{"Kind":"page","Start":1,"End":0}]}`,
		`{"version":1,"Text":"a","Sections":[{"Kind":"page","Start":-1,"End":0}]}`,
		`{"version":1,"Text":"a","Sections":[{"Kind":"heading","Level":10,"Start":0,"End":1}]}`,
		`{"version":1,"Text":"a","Sections":[{"Kind":"page","Page":-1,"Start":0,"End":1}]}`,
	} {
		if _, err := decodeResult([]byte(bad)); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestCappedBuffer(t *testing.T) {
	calls := 0
	b := &cappedBuffer{max: 4, overflowed: func() { calls++ }}
	for _, p := range []string{"ab", "cdef", "gh"} {
		if n, err := b.Write([]byte(p)); n != len(p) || err != nil {
			t.Fatalf("write %q: %d %v", p, n, err)
		}
	}
	if b.String() != "abcd" || !b.overflow || calls != 1 {
		t.Errorf("%q overflow=%v calls=%d", b.String(), b.overflow, calls)
	}
}

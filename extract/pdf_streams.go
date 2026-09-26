package extract

import (
	"bytes"
	"compress/lzw"
	"compress/zlib"
	"context"
	"encoding/ascii85"
	"encoding/hex"
	"io"
	"regexp"
	"sort"
	"strconv"
)

var (
	pdfLength  = regexp.MustCompile(`/Length\s+(\d+)(?:\s+(\d+)\s+R)?`)
	pdfFilter  = regexp.MustCompile(`/Filter\s*(\[[^\]]*\]|/[A-Za-z0-9]+)`)
	pdfName    = regexp.MustCompile(`/([A-Za-z0-9]+)`)
	pdfObject  = regexp.MustCompile(`(\d+)\s+(\d+)\s+obj\b`)
	pdfInt     = regexp.MustCompile(`^\s*(\d+)`)
	pdfEncrypt = []byte("/Encrypt")
)

// pdfObjects indexes the "N G obj" headers of a file once: their offsets in
// order, for the dictionary before a stream, and by number, for an indirect
// /Length.
type pdfObjects struct {
	starts []int
	body   map[string]int
}

func indexObjects(raw []byte) pdfObjects {
	idx := pdfObjects{body: map[string]int{}}
	for _, m := range pdfObject.FindAllSubmatchIndex(raw, -1) {
		idx.starts = append(idx.starts, m[0])
		idx.body[string(raw[m[2]:m[3]])+" "+string(raw[m[4]:m[5]])] = m[1]
	}
	return idx
}

// before returns the start of the last object header before at, or -1.
func (o pdfObjects) before(at int) int {
	i := sort.SearchInts(o.starts, at)
	if i == 0 {
		return -1
	}
	return o.starts[i-1]
}

// checkPDFStreams decodes every stream the way the parser will — located by
// /Length (or the endstream fallback), through its whole /Filter chain — into
// a bounded buffer, and returns ErrTooLarge once the document's decoded total
// passes maxBytes. The parser decodes and caches streams without a limit,
// images included, so this bounds what it may allocate. Every "stream"
// keyword is measured, so a planted one only costs time. An encrypted
// document cannot be measured before decryption and is refused.
func checkPDFStreams(ctx context.Context, raw []byte, maxBytes int64) error {
	if bytes.Contains(raw, pdfEncrypt) {
		return ErrEncrypted
	}
	objects := indexObjects(raw)
	remaining := maxBytes
	for pos := 0; ; {
		i := bytes.Index(raw[pos:], []byte("stream"))
		if i < 0 {
			return nil
		}
		at := pos + i
		pos = at + len("stream")
		if at >= 3 && string(raw[at-3:at]) == "end" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		dictStart := objects.before(at)
		if dictStart < 0 {
			continue
		}
		dict := raw[dictStart:at]
		if remaining -= decodedSize(streamData(raw, pos, dict, objects), filters(dict), remaining); remaining < 0 {
			return ErrTooLarge
		}
	}
}

// streamData returns the stream bytes as the parser takes them: after an
// optional CR and LF, /Length long, or up to endstream when /Length is absent.
func streamData(raw []byte, start int, dict []byte, objects pdfObjects) []byte {
	if start < len(raw) && raw[start] == '\r' {
		start++
	}
	if start < len(raw) && raw[start] == '\n' {
		start++
	}
	rest := raw[start:]
	if length, ok := streamLength(raw, dict, objects); ok {
		return rest[:min(length, len(rest))]
	}
	if end := bytes.Index(rest, []byte("endstream")); end >= 0 {
		return bytes.TrimRight(rest[:end], "\r\n")
	}
	return rest
}

// streamLength reads /Length, following an indirect "N G R" reference.
func streamLength(raw, dict []byte, objects pdfObjects) (int, bool) {
	m := pdfLength.FindSubmatch(dict)
	if m == nil {
		return 0, false
	}
	value := m[1]
	if m[2] != nil {
		body, ok := objects.body[string(m[1])+" "+string(m[2])]
		if !ok {
			return 0, false
		}
		v := pdfInt.FindSubmatch(raw[body:min(body+32, len(raw))])
		if v == nil {
			return 0, false
		}
		value = v[1]
	}
	n, err := strconv.Atoi(string(value))
	return n, err == nil
}

func filters(dict []byte) []string {
	m := pdfFilter.FindSubmatch(dict)
	if m == nil {
		return nil
	}
	var names []string
	for _, n := range pdfName.FindAllSubmatch(m[1], -1) {
		names = append(names, string(n[1]))
	}
	return names
}

// decodedSize runs data through the filter chain, each stage reading at most
// limit+1 bytes, and returns the final size. Filters the parser passes
// through unchanged (DCT, JPX, CCITT, JBIG2, unknown) keep their input size;
// a stage the parser would fail on ends the chain at what it decoded.
func decodedSize(data []byte, chain []string, limit int64) int64 {
	cur := data
	for i, f := range chain {
		var r io.Reader
		switch f {
		case "FlateDecode":
			zr, err := zlib.NewReader(bytes.NewReader(cur))
			if err != nil {
				return 0
			}
			r = zr
		case "LZWDecode":
			r = lzw.NewReader(bytes.NewReader(cur), lzw.MSB, 8)
		case "ASCII85Decode":
			s := cur
			if end := bytes.Index(s, []byte("~>")); end >= 0 {
				s = s[:end]
			}
			r = ascii85.NewDecoder(bytes.NewReader(s))
		case "ASCIIHexDecode":
			r = hex.NewDecoder(bytes.NewReader(hexDigits(cur)))
		default:
			continue
		}
		if i == len(chain)-1 {
			n, _ := io.Copy(io.Discard, io.LimitReader(r, limit+1))
			closeReader(r)
			return n
		}
		next, _ := io.ReadAll(io.LimitReader(r, limit+1))
		closeReader(r)
		if int64(len(next)) > limit {
			return int64(len(next))
		}
		cur = next
	}
	return int64(len(cur))
}

func closeReader(r io.Reader) {
	if c, ok := r.(io.Closer); ok {
		c.Close()
	}
}

// hexDigits keeps the hex digits before ">", padding an odd count as the
// ASCIIHexDecode filter does.
func hexDigits(data []byte) []byte {
	out := make([]byte, 0, len(data)+1)
	for _, c := range data {
		if c == '>' {
			break
		}
		if ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F') {
			out = append(out, c)
		}
	}
	if len(out)%2 == 1 {
		out = append(out, '0')
	}
	return out
}

package extract

import (
	"context"
	"encoding/xml"
	"io"
	"strings"
)

// docxFrame is the text being built for the body or for one text box.
type docxFrame struct {
	text       strings.Builder
	sections   []Section
	paraStart  int
	paraLevel  int
	tableDepth int
	tableStart int
	cellStart  int
	boxes      []*docxFrame // text boxes met in the open paragraph
}

func (f *docxFrame) section(kind string, level, start int) {
	if end := f.text.Len(); end > start {
		f.sections = append(f.sections, Section{Kind: kind, Level: level, Start: start, End: end})
	}
}

// appendBoxes places the text boxes of a closed paragraph after it.
func (f *docxFrame) appendBoxes() {
	for _, box := range f.boxes {
		offset := f.text.Len()
		f.text.WriteString(box.text.String())
		for _, s := range box.sections {
			s.Start, s.End = s.Start+offset, s.End+offset
			f.sections = append(f.sections, s)
		}
	}
	f.boxes = nil
}

// docxWalker takes body text from w:t inside runs, in the w: namespace only.
// Skipped whole: tab-stop definitions and the previous formatting of tracked
// changes (w:pPrChange, w:rPrChange), deleted and moved-away text (w:del,
// w:moveFrom), field codes (w:instrText) and the legacy copy of a text box
// (mc:Fallback). A text box's paragraphs follow the paragraph that holds it.
// A table is one section: rows on lines, cells ending in a tab, paragraphs
// inside a cell separated by a newline.
type docxWalker struct {
	styles   docxStyles
	maxBytes int64
	written  int64
	frames   []*docxFrame
	skip     int // depth inside a skipped element
	inText   int
	inPPr    int
}

func newDocxWalker(styles docxStyles, maxBytes int64) *docxWalker {
	return &docxWalker{styles: styles, maxBytes: maxBytes, frames: []*docxFrame{{}}}
}

func (w *docxWalker) cur() *docxFrame { return w.frames[len(w.frames)-1] }

func (w *docxWalker) write(s string) {
	w.written += int64(len(s))
	w.cur().text.WriteString(s)
}

func skipped(name xml.Name) bool {
	switch name.Space {
	case markupC:
		return name.Local == "Fallback"
	case wordML:
		switch name.Local {
		case "pPrChange", "rPrChange", "del", "moveFrom", "instrText", "delText", "tabs":
			return true
		}
	}
	return false
}

func (w *docxWalker) walk(ctx context.Context, dec *xml.Decoder) (Extracted, error) {
	for tokens := 0; ; tokens++ {
		if tokens%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return Extracted{}, err
			}
		}
		if w.written > w.maxBytes {
			return Extracted{}, ErrTooLarge
		}
		tok, err := dec.Token()
		if err == io.EOF {
			body := w.frames[0]
			body.appendBoxes()
			return Extracted{Text: body.text.String(), Sections: body.sections}, nil
		}
		if err != nil {
			return Extracted{}, docxErr(err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case w.skip > 0:
				w.skip++
			case skipped(t.Name):
				w.skip = 1
			case t.Name.Space == wordML:
				w.start(t)
			}
		case xml.EndElement:
			switch {
			case w.skip > 0:
				w.skip--
			case t.Name.Space == wordML:
				w.end(t.Name.Local)
			}
		case xml.CharData:
			if w.skip == 0 && w.inText > 0 {
				w.write(validUTF8(string(t)))
			}
		}
	}
}

func (w *docxWalker) start(el xml.StartElement) {
	f := w.cur()
	switch el.Name.Local {
	case "t":
		w.inText++
	case "pPr":
		w.inPPr++
	case "pStyle":
		if w.inPPr > 0 {
			f.paraLevel = w.styles.level(attr(el, "val"))
		}
	case "outlineLvl":
		if w.inPPr > 0 {
			if lvl := outlineLevel(el); lvl > 0 {
				f.paraLevel = lvl
			}
		}
	case "tab":
		w.write("\t")
	case "br", "cr":
		w.write("\n")
	case "txbxContent":
		w.frames = append(w.frames, &docxFrame{})
	case "p":
		if f.tableDepth > 0 && f.text.Len() > f.cellStart {
			w.write("\n")
		}
		f.paraStart, f.paraLevel = f.text.Len(), 0
	case "tbl":
		if f.tableDepth == 0 {
			f.tableStart = f.text.Len()
		}
		f.tableDepth++
	case "tc":
		f.cellStart = f.text.Len()
	}
}

func (w *docxWalker) end(local string) {
	f := w.cur()
	switch local {
	case "t":
		w.inText--
	case "pPr":
		w.inPPr--
	case "txbxContent":
		if len(w.frames) > 1 {
			box := f
			box.appendBoxes()
			w.frames = w.frames[:len(w.frames)-1]
			w.cur().boxes = append(w.cur().boxes, box)
		}
	case "p":
		if f.tableDepth == 0 {
			if f.paraLevel > 0 {
				f.section(Heading, f.paraLevel, f.paraStart)
			} else {
				f.section(Paragraph, 0, f.paraStart)
			}
			w.write("\n")
			f.appendBoxes()
		}
	case "tc":
		w.write("\t")
	case "tr":
		w.write("\n")
	case "tbl":
		if f.tableDepth--; f.tableDepth == 0 {
			f.section(Table, 0, f.tableStart)
			w.write("\n")
			f.appendBoxes()
		}
	}
}

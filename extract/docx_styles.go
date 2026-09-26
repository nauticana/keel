package extract

import (
	"archive/zip"
	"encoding/xml"
	"io"
	"strconv"
	"strings"
)

type docxStyle struct {
	level   int // 0 when the style itself names no outline level
	basedOn string
}

// docxStyles resolves a paragraph style id to a heading level (1-9, 0 for
// body text): the style's own w:outlineLvl or built-in English name
// ("heading N", "Title"), else the style it is based on. Without
// styles.xml the default English ids (Heading1…Heading9, Title) apply.
type docxStyles map[string]docxStyle

func (s docxStyles) level(id string) int {
	for hops := 0; id != "" && hops < 16; hops++ {
		st, ok := s[id]
		if !ok {
			return defaultStyleLevel(id)
		}
		if st.level > 0 {
			return st.level
		}
		id = st.basedOn
	}
	return 0
}

func defaultStyleLevel(id string) int {
	if id == "Title" {
		return 1
	}
	if n, ok := strings.CutPrefix(id, "Heading"); ok {
		if lvl, err := strconv.Atoi(n); err == nil && lvl >= 1 && lvl <= 9 {
			return lvl
		}
	}
	return 0
}

func outlineLevel(el xml.StartElement) int {
	if lvl, err := strconv.Atoi(attr(el, "val")); err == nil && lvl >= 0 && lvl <= 8 {
		return lvl + 1
	}
	return 0
}

func readStyles(zr *zip.Reader, maxBytes int64) (docxStyles, error) {
	part, err := openPart(zr, "word/styles.xml", maxBytes)
	if err != nil || part == nil {
		return docxStyles{}, err
	}
	defer part.Close()
	styles := docxStyles{}
	dec := xml.NewDecoder(part)
	var id string
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return styles, nil
		}
		if err != nil {
			return nil, docxErr(err)
		}
		el, ok := tok.(xml.StartElement)
		if !ok || el.Name.Space != wordML {
			continue
		}
		st := styles[id]
		switch el.Name.Local {
		case "style":
			id = attr(el, "styleId")
			continue
		case "name":
			if name := strings.ToLower(attr(el, "val")); name == "title" {
				st.level = 1
			} else if n, ok := strings.CutPrefix(name, "heading "); ok {
				if lvl, err := strconv.Atoi(n); err == nil && lvl >= 1 && lvl <= 9 {
					st.level = lvl
				}
			}
		case "basedOn":
			st.basedOn = attr(el, "val")
		case "outlineLvl":
			if lvl := outlineLevel(el); lvl > 0 {
				st.level = lvl
			}
		default:
			continue
		}
		styles[id] = st
	}
}

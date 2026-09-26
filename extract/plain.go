package extract

import (
	"strings"
	"unicode/utf8"
)

// extractPlain splits on blank lines. In Markdown every ATX "#" line is a
// heading with its level, and the lines between headings in a block are a
// paragraph.
func extractPlain(raw []byte, markdown bool) Extracted {
	text := validUTF8(strings.ReplaceAll(string(raw), "\r\n", "\n"))
	out := Extracted{Text: text}
	add := func(kind string, level, start, end int) {
		if strings.TrimSpace(text[start:end]) != "" {
			out.Sections = append(out.Sections, Section{Kind: kind, Level: level, Start: start, End: end})
		}
	}
	offset := 0
	for _, block := range strings.Split(text, "\n\n") {
		end := offset + len(block)
		if !markdown {
			add(Paragraph, 0, offset, end)
		} else {
			paraStart, lineStart := offset, offset
			for _, line := range strings.Split(block, "\n") {
				if level := headingLevel(line); level > 0 {
					add(Paragraph, 0, paraStart, max(paraStart, lineStart-1))
					add(Heading, level, lineStart, lineStart+len(line))
					paraStart = lineStart + len(line) + 1
				}
				lineStart += len(line) + 1
			}
			if paraStart < end {
				add(Paragraph, 0, paraStart, end)
			}
		}
		offset = end + len("\n\n")
	}
	return out
}

// headingLevel is the ATX heading level of a Markdown line, 0 if none.
func headingLevel(line string) int {
	trimmed := strings.TrimLeft(line, " ")
	level := len(trimmed) - len(strings.TrimLeft(trimmed, "#"))
	if level < 1 || level > 6 || (len(trimmed) > level && trimmed[level] != ' ') {
		return 0
	}
	return level
}

func validUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "\uFFFD")
}

package sheets

import (
	"strconv"
	"strings"
)

// QuoteSheet renders a sheet name for A1 notation; on its own it is the whole sheet.
func QuoteSheet(sheet string) string {
	return "'" + strings.ReplaceAll(sheet, "'", "''") + "'"
}

// ColumnLetter is the A1 letter of a 0-based column index; "" for a negative index.
func ColumnLetter(i int) string {
	letters := ""
	for i++; i > 0; i = (i - 1) / 26 {
		letters = string(rune('A'+(i-1)%26)) + letters
	}
	return letters
}

// CellA1 is the A1 reference of a 0-based column and 1-based row on sheet.
func CellA1(sheet string, column, row int) string {
	return QuoteSheet(sheet) + "!" + ColumnLetter(column) + strconv.Itoa(row)
}

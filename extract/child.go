package extract

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
)

// Child exit codes carry the sentinel errors across the process boundary.
// Go itself exits 2 on a panic or fatal runtime error, so 2 is never a document fault.
const (
	childExitFailed      = 1
	childExitUsage       = 2
	childExitTooLarge    = 3
	childExitEncrypted   = 4
	childExitUnsupported = 5
	childExitUnreadable  = 6
)

// ChildMain is the main of the binary Isolated runs: it extracts the document
// on stdin with Native and writes the result to stdout.
func ChildMain(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("extract-child", flag.ContinueOnError)
	flags.SetOutput(stderr)
	mediaType := flags.String("media_type", "", "media type of the document on stdin")
	maxBytes := flags.Int64("max_bytes", 0, "extract_max_bytes: the largest input, decoded stream or extracted text (bytes)")
	if err := flags.Parse(args); err != nil || flags.NArg() > 0 || *mediaType == "" || *maxBytes <= 0 || *maxBytes > maxIsolatedBytes {
		fmt.Fprintln(stderr, "usage: --media_type=<type> --max_bytes=<n> < document")
		return childExitUsage
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, *maxBytes+1))
	if err != nil {
		fmt.Fprintf(stderr, "read document: %v\n", err)
		return childExitFailed
	}
	if int64(len(raw)) > *maxBytes {
		return childExitTooLarge
	}
	out, err := Native{MaxBytes: *maxBytes}.Extract(context.Background(), *mediaType, raw)
	switch {
	case errors.Is(err, ErrTooLarge):
		return childExitTooLarge
	case errors.Is(err, ErrEncrypted):
		return childExitEncrypted
	case errors.Is(err, ErrUnsupportedMediaType):
		return childExitUnsupported
	case err != nil:
		fmt.Fprintln(stderr, err)
		return childExitUnreadable
	}
	if err := encodeResult(stdout, out); err != nil {
		fmt.Fprintf(stderr, "write result: %v\n", err)
		return childExitFailed
	}
	return 0
}

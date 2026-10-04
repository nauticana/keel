package extract

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	isolatedTimeout  = time.Minute
	stderrMax        = 4 << 10
	waitDelay        = time.Second
	maxIsolatedBytes = (1<<63 - 1 - (64 << 10)) / 8
)

// Isolated extracts the chosen media types in a child process that a
// deadline kills, since a parser stuck inside one PDF page never checks ctx.
// Other media types go to the wrapped in-process extractor.
type Isolated struct {
	inProcess  TextExtractor
	path       string
	args       []string
	mediaTypes []string
	maxBytes   int64
	timeout    time.Duration
	slots      chan struct{}
}

var _ TextExtractor = (*Isolated)(nil)

func NewIsolated(inProcess TextExtractor, cfg IsolatedConfig) (*Isolated, error) {
	switch {
	case inProcess == nil:
		return nil, errors.New("extract: Isolated needs an in-process extractor")
	case !filepath.IsAbs(cfg.Path):
		return nil, fmt.Errorf("extract: Isolated child path %q must be absolute", cfg.Path)
	case cfg.MaxBytes <= 0:
		return nil, errors.New("extract: Isolated MaxBytes must be positive")
	case cfg.MaxBytes > maxIsolatedBytes:
		return nil, errors.New("extract: Isolated MaxBytes is too large")
	case cfg.Timeout < 0 || cfg.Concurrency < 0:
		return nil, errors.New("extract: Isolated Timeout and Concurrency must not be negative")
	}
	i := &Isolated{inProcess: inProcess, path: cfg.Path, args: slices.Clone(cfg.Args),
		maxBytes: cfg.MaxBytes, timeout: cfg.Timeout}
	if i.timeout == 0 {
		i.timeout = isolatedTimeout
	}
	concurrency := cfg.Concurrency
	if concurrency == 0 {
		concurrency = runtime.GOMAXPROCS(0)
	}
	i.slots = make(chan struct{}, concurrency)
	mediaTypes := cfg.MediaTypes
	if len(mediaTypes) == 0 {
		mediaTypes = []string{mediaPDF}
	}
	for _, t := range mediaTypes {
		if !(Native{}).Supports(t) {
			return nil, fmt.Errorf("%w: the isolated child cannot extract %s", ErrUnsupportedMediaType, t)
		}
		i.mediaTypes = append(i.mediaTypes, baseType(t))
	}
	return i, nil
}

func (i *Isolated) Supports(mediaType string) bool {
	return i.isolates(mediaType) || i.inProcess.Supports(mediaType)
}

func (i *Isolated) Extract(ctx context.Context, mediaType string, raw []byte) (Extracted, error) {
	if !i.isolates(mediaType) {
		return i.inProcess.Extract(ctx, mediaType, raw)
	}
	if int64(len(raw)) > i.maxBytes {
		return Extracted{}, ErrTooLarge
	}
	if err := ctx.Err(); err != nil {
		return Extracted{}, err
	}
	select {
	case i.slots <- struct{}{}:
	case <-ctx.Done():
		return Extracted{}, ctx.Err()
	}
	defer func() { <-i.slots }()
	return i.runChild(ctx, baseType(mediaType), raw)
}

func (i *Isolated) isolates(mediaType string) bool {
	return slices.Contains(i.mediaTypes, baseType(mediaType))
}

func (i *Isolated) runChild(ctx context.Context, mediaType string, raw []byte) (Extracted, error) {
	runCtx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()
	killCtx, kill := context.WithCancel(runCtx)
	defer kill()
	args := append(slices.Clone(i.args), "--media_type="+mediaType, "--max_bytes="+strconv.FormatInt(i.maxBytes, 10))
	cmd := exec.CommandContext(killCtx, i.path, args...)
	cmd.Env = []string{} // the child needs nothing from the parent, least of all its credentials
	cmd.Stdin = bytes.NewReader(raw)
	stdout := &cappedBuffer{max: resultMax(i.maxBytes), overflowed: kill}
	stderr := &cappedBuffer{max: stderrMax}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = waitDelay

	err := cmd.Run()
	switch {
	case stdout.overflow:
		return Extracted{}, ErrTooLarge
	case err == nil:
		return decodeResult(stdout.Bytes())
	case ctx.Err() != nil:
		return Extracted{}, ctx.Err()
	case runCtx.Err() != nil:
		return Extracted{}, ErrTimeout
	}
	return Extracted{}, childError(err, strings.TrimSpace(stderr.String()))
}

func childError(err error, stderr string) error {
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return fmt.Errorf("%w: %w", ErrIsolationFailed, err)
	}
	switch exit.ExitCode() {
	case childExitTooLarge:
		return ErrTooLarge
	case childExitEncrypted:
		return ErrEncrypted
	case childExitUnsupported:
		return ErrUnsupportedMediaType
	case childExitUnreadable:
		return fmt.Errorf("extract: isolated child: %s", stderr)
	}
	return fmt.Errorf("%w: %v: %s", ErrIsolationFailed, err, stderr)
}

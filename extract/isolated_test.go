package extract

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

const childMarker = "extract-test-child"

// TestMain lets the test binary stand in for the child binary, including
// children that misbehave.
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == childMarker {
		os.Exit(fakeChild(os.Args[2], os.Args[3:]))
	}
	os.Exit(m.Run())
}

func fakeChild(mode string, args []string) int {
	if len(os.Environ()) != 0 {
		return 99
	}
	switch mode {
	case "real":
		return ChildMain(args, os.Stdin, os.Stdout, os.Stderr)
	case "spin": // a parser stuck on one page, never checking ctx
		for {
		}
	case "flood":
		chunk := []byte(strings.Repeat("x", 1<<16))
		for {
			os.Stdout.Write(chunk)
		}
	case "sleep":
		time.Sleep(time.Hour)
	case "garbage":
		os.Stdout.WriteString("not json")
	case "trailing":
		os.Stdout.WriteString(`{"version":1,"Text":"a","Sections":null}{}`)
	case "unknown_field":
		os.Stdout.WriteString(`{"version":1,"Text":"a","Extra":1}`)
	case "old_version":
		os.Stdout.WriteString(`{"version":2,"Text":"a"}`)
	case "bad_section":
		os.Stdout.WriteString(`{"version":1,"Text":"a","Sections":[{"Kind":"page","Page":1,"Start":0,"End":5}]}`)
	default:
		code, _ := strconv.Atoi(mode)
		os.Stderr.WriteString("child says " + mode)
		return code
	}
	return 0
}

func testExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func newIsolated(t *testing.T, mode string, cfg IsolatedConfig) *Isolated {
	t.Helper()
	cfg.Path, cfg.Args = testExe(t), []string{childMarker, mode}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = 1 << 20
	}
	i, err := NewIsolated(native, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func TestIsolatedRoundTrip(t *testing.T) {
	raw := pdfFixture("Hello PDF", "")
	want, err := native.Extract(context.Background(), mediaPDF, raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := newIsolated(t, "real", IsolatedConfig{}).Extract(context.Background(), "application/pdf; x=y", raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("isolated %+v, in-process %+v", got, want)
	}
}

func TestIsolatedSentinels(t *testing.T) {
	i := newIsolated(t, "real", IsolatedConfig{})
	if _, err := i.Extract(context.Background(), mediaPDF, encryptedPDF(t, "user", "owner")); !errors.Is(err, ErrEncrypted) {
		t.Errorf("encrypted: %v", err)
	}
	_, err := i.Extract(context.Background(), mediaPDF, []byte("%PDF-1.4 garbage"))
	if err == nil || errors.Is(err, ErrIsolationFailed) || !strings.Contains(err.Error(), "extract pdf") {
		t.Errorf("a malformed document is the document's fault, with the child's reason: %v", err)
	}
	small := newIsolated(t, "real", IsolatedConfig{MaxBytes: 300})
	if _, err := small.Extract(context.Background(), mediaPDF, pdfFixture(strings.Repeat("long text ", 30))); !errors.Is(err, ErrTooLarge) {
		t.Errorf("text over the cap: %v", err)
	}

	for code, want := range map[string]error{
		"3": ErrTooLarge, "4": ErrEncrypted, "5": ErrUnsupportedMediaType,
		"1": ErrIsolationFailed, "2": ErrIsolationFailed, "7": ErrIsolationFailed,
		"garbage": ErrIsolationFailed, "trailing": ErrIsolationFailed, "unknown_field": ErrIsolationFailed,
		"old_version": ErrIsolationFailed, "bad_section": ErrIsolationFailed,
	} {
		if _, err := newIsolated(t, code, IsolatedConfig{}).Extract(context.Background(), mediaPDF, []byte("%PDF")); !errors.Is(err, want) {
			t.Errorf("child %s: %v, want %v", code, err, want)
		}
	}
	if _, err := newIsolated(t, "6", IsolatedConfig{}).Extract(context.Background(), mediaPDF, []byte("%PDF")); err == nil ||
		errors.Is(err, ErrIsolationFailed) || !strings.Contains(err.Error(), "child says 6") {
		t.Errorf("child 6: %v", err)
	}
	i, err = NewIsolated(native, IsolatedConfig{Path: "/nonexistent/extract-child", MaxBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i.Extract(context.Background(), mediaPDF, []byte("%")); !errors.Is(err, ErrIsolationFailed) {
		t.Errorf("a missing binary: %v", err)
	}
}

func TestIsolatedKillsStalledChild(t *testing.T) {
	for _, mode := range []string{"spin", "sleep"} {
		start := time.Now()
		_, err := newIsolated(t, mode, IsolatedConfig{Timeout: 200 * time.Millisecond}).Extract(context.Background(), mediaPDF, []byte("%PDF"))
		if !errors.Is(err, ErrTimeout) {
			t.Errorf("%s: %v", mode, err)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: took %v", mode, d)
		}
	}
}

func TestIsolatedOutputCap(t *testing.T) {
	start := time.Now()
	_, err := newIsolated(t, "flood", IsolatedConfig{MaxBytes: 1 << 10}).Extract(context.Background(), mediaPDF, []byte("%PDF"))
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("flood: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
}

func TestIsolatedConcurrencyAndCancellation(t *testing.T) {
	i := newIsolated(t, "sleep", IsolatedConfig{Concurrency: 1, Timeout: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := i.Extract(ctx, mediaPDF, []byte("%PDF"))
		done <- err
	}()
	for len(i.slots) == 0 {
		time.Sleep(time.Millisecond)
	}

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer waitCancel()
	if _, err := i.Extract(waitCtx, mediaPDF, []byte("%PDF")); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a second child must wait for the slot, then give up with ctx: %v", err)
	}
	if e, err := i.Extract(context.Background(), mediaPlain, []byte("plain")); err != nil || e.Text != "plain" {
		t.Errorf("in-process types do not take a child slot: %q %v", e.Text, err)
	}

	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("cancelled: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelling ctx must kill the child")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
	if len(i.slots) != 0 {
		t.Error("the slot must be released")
	}
	if _, err := i.Extract(ctx, mediaPDF, []byte("%PDF")); !errors.Is(err, context.Canceled) {
		t.Errorf("an already cancelled ctx: %v", err)
	}
}

func TestIsolatedInProcessAndLimits(t *testing.T) {
	i := newIsolated(t, "99", IsolatedConfig{MaxBytes: 16}) // the child would fail every call
	if e, err := i.Extract(context.Background(), "text/markdown", []byte("# Title")); err != nil || e.Sections[0].Kind != Heading {
		t.Errorf("markdown runs in-process: %+v %v", e, err)
	}
	if _, err := i.Extract(context.Background(), mediaPDF, make([]byte, 17)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("input over MaxBytes is refused before spawning: %v", err)
	}
	if !i.Supports("application/pdf") || !i.Supports(mediaDOCX) || i.Supports("image/png") {
		t.Error("Supports")
	}
	docx := newIsolated(t, "99", IsolatedConfig{MediaTypes: []string{mediaDOCX}})
	if _, err := docx.Extract(context.Background(), mediaDOCX, []byte("x")); !errors.Is(err, ErrIsolationFailed) {
		t.Errorf("a configured type goes to the child: %v", err)
	}
}

func TestNewIsolatedValidates(t *testing.T) {
	exe := testExe(t)
	for name, tc := range map[string]struct {
		in  TextExtractor
		cfg IsolatedConfig
	}{
		"nil in-process":    {nil, IsolatedConfig{Path: exe, MaxBytes: 1}},
		"relative path":     {native, IsolatedConfig{Path: "extract-child", MaxBytes: 1}},
		"zero MaxBytes":     {native, IsolatedConfig{Path: exe}},
		"huge MaxBytes":     {native, IsolatedConfig{Path: exe, MaxBytes: maxIsolatedBytes + 1}},
		"negative timeout":  {native, IsolatedConfig{Path: exe, MaxBytes: 1, Timeout: -1}},
		"negative slots":    {native, IsolatedConfig{Path: exe, MaxBytes: 1, Concurrency: -1}},
		"type Native lacks": {native, IsolatedConfig{Path: exe, MaxBytes: 1, MediaTypes: []string{"image/png"}}},
	} {
		if _, err := NewIsolated(tc.in, tc.cfg); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	i, err := NewIsolated(native, IsolatedConfig{Path: exe, MaxBytes: 1})
	if err != nil || i.timeout != isolatedTimeout || cap(i.slots) < 1 || !i.isolates(mediaPDF) || i.isolates(mediaPlain) {
		t.Errorf("defaults: %+v %v", i, err)
	}
}

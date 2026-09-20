package browser

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSweepRemovesOnlyStaleBrowserDirs(t *testing.T) {
	tmp := t.TempDir()
	old := time.Now().Add(-2 * time.Hour)
	mk := func(name string, stale bool) string {
		path := filepath.Join(tmp, name)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if stale {
			os.Chtimes(path, old, old)
		}
		return path
	}
	staleProfile := mk("chromedp-userdata-1", true)
	staleChrome := mk("com.google.Chrome.abc", true)
	liveProfile := mk("chromedp-userdata-2", false)
	unrelated := mk("someone-elses-dir", true)

	(&Launcher{TempDir: tmp}).sweepStaleProfiles()

	for path, wantGone := range map[string]bool{staleProfile: true, staleChrome: true, liveProfile: false, unrelated: false} {
		_, err := os.Stat(path)
		if gone := errors.Is(err, os.ErrNotExist); gone != wantGone {
			t.Errorf("%s: gone=%v, want %v", filepath.Base(path), gone, wantGone)
		}
	}
}

func TestChromeEnv(t *testing.T) {
	withHome := chromeEnv([]string{"HOME=/home/app", "PATH=/bin"}, "/tmp/p")
	if slices.Contains(withHome, "HOME=/tmp/p") || !slices.Contains(withHome, "TMPDIR=/tmp/p") {
		t.Errorf("env = %v", withHome)
	}
	for _, parent := range [][]string{{"PATH=/bin"}, {"HOME="}} {
		if env := chromeEnv(parent, "/tmp/p"); !slices.Contains(env, "HOME=/tmp/p") {
			t.Errorf("parent %v: env = %v", parent, env)
		}
	}
}

func TestExecPath(t *testing.T) {
	present := filepath.Join(t.TempDir(), "chrome")
	os.WriteFile(present, nil, 0o700)
	if got := (&Launcher{ExecPaths: []string{"/nonexistent/chrome", present}}).execPath(); got != present {
		t.Errorf("execPath = %q", got)
	}
	if got := (&Launcher{ExecPaths: []string{}}).execPath(); got != "" {
		t.Errorf("empty candidates: %q", got)
	}
}

func TestAllocatorCancelRemovesProfileDir(t *testing.T) {
	tmp := t.TempDir()
	_, cancel, err := (&Launcher{TempDir: tmp}).NewAllocator(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if dirs, _ := filepath.Glob(filepath.Join(tmp, profileDirPattern)); len(dirs) != 1 {
		t.Fatalf("profile dirs = %v", dirs)
	}
	cancel()
	if dirs, _ := filepath.Glob(filepath.Join(tmp, profileDirPattern)); len(dirs) != 0 {
		t.Fatalf("profile dir survived cancel: %v", dirs)
	}
	if _, _, err := (&Launcher{TempDir: filepath.Join(tmp, "missing")}).NewAllocator(context.Background()); err == nil {
		t.Fatal("unwritable temp dir must fail the launch")
	}
}

func TestTruthy(t *testing.T) {
	r := &RenderResult{Evaluations: map[string]any{
		"yes": true, "no": false, "zero": 0.0, "one": 1.0, "empty": "", "text": "x", "null": nil, "obj": map[string]any{},
	}}
	for label, want := range map[string]bool{
		"yes": true, "no": false, "zero": false, "one": true, "empty": false, "text": true, "null": false, "obj": true, "missing": false,
	} {
		if got := r.Truthy(label); got != want {
			t.Errorf("Truthy(%s) = %v", label, got)
		}
	}
}

func TestRenderRejectsEmptyURL(t *testing.T) {
	if _, err := (&DOMRenderer{Launcher: &Launcher{}}).Render(context.Background(), RenderRequest{URL: "  "}); !errors.Is(err, ErrEmptyURL) {
		t.Fatalf("err = %v", err)
	}
}

func installedChrome() string {
	for _, path := range append([]string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/usr/bin/chromium", "/usr/bin/chromium-browser",
	}, DefaultExecPaths...) {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func TestRenderAgainstRealChrome(t *testing.T) {
	chrome := installedChrome()
	if testing.Short() || chrome == "" {
		t.Skip("needs an installed Chrome")
	}
	var seenUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenUA = r.Header.Get("User-Agent")
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc", SameSite: http.SameSiteLaxMode})
		w.Write([]byte(`<html><body><div id="app"></div><script>document.getElementById("app").textContent="hydrated"</script></body></html>`))
	}))
	defer srv.Close()

	tmp := t.TempDir()
	renderer := &DOMRenderer{Launcher: &Launcher{Headless: true, ExecPaths: []string{chrome}, TempDir: tmp}}
	res, err := renderer.Render(context.Background(), RenderRequest{
		URL:       srv.URL,
		Timeout:   60 * time.Second,
		UserAgent: "keel-browser-test",
		Evaluations: map[string]string{
			"hydrated": `document.getElementById("app").textContent === "hydrated"`,
			"throws":   `window.nope.nope`,
			"count":    `document.querySelectorAll("div").length`,
		},
		CaptureCookies: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.RenderedHTML, "hydrated") || !res.Truthy("hydrated") || res.Truthy("throws") || res.Evaluations["count"] != 1.0 {
		t.Errorf("result = %+v", res)
	}
	if len(res.EvaluationErrors) != 0 {
		t.Errorf("evaluation errors = %v", res.EvaluationErrors)
	}
	if seenUA != "keel-browser-test" {
		t.Errorf("user agent = %q", seenUA)
	}
	if len(res.Cookies) != 1 || res.Cookies[0].Name != "sid" || res.Cookies[0].SameSite != http.SameSiteLaxMode {
		t.Errorf("cookies = %+v", res.Cookies)
	}
	if dirs, _ := filepath.Glob(filepath.Join(tmp, profileDirPattern)); len(dirs) != 0 {
		t.Errorf("profile dir leaked: %v", dirs)
	}
}

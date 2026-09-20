// Package browser runs headless Chrome through chromedp: a Launcher that owns
// the profile directory lifecycle, a Session of tabs on one Chrome, and a
// Renderer for the load-evaluate-capture case. Chrome is a runtime requirement
// of any binary that uses it.
package browser

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/nauticana/keel/logger"
)

const (
	DefaultStaleProfileAge = time.Hour

	profileDirPattern = "chromedp-userdata-*"
	// Chrome's own IPC/V8 temp dirs, leaked by launches that predate the TMPDIR redirect.
	chromeTempPattern = "com.google.Chrome.*"
)

// DefaultExecPaths prefers Google Chrome over a distro Chromium: Chromium 147+
// on Debian spawns a crashpad handler without --database and dies before
// DevTools connects.
var DefaultExecPaths = []string{"/usr/bin/google-chrome", "/usr/bin/google-chrome-stable"}

// Launcher starts Chrome processes. The zero value launches a headed Chrome;
// production wiring sets Headless.
type Launcher struct {
	Headless bool
	// ExecPaths are candidate Chrome binaries, first existing wins; nil means
	// DefaultExecPaths. When none exists chromedp searches the usual locations.
	ExecPaths []string
	// StaleProfileAge is how old a leftover profile dir must be before a launch
	// sweeps it; 0 means DefaultStaleProfileAge. It must exceed the longest session.
	StaleProfileAge time.Duration
	TempDir         string // parent of profile dirs; empty means os.TempDir()
	Journal         logger.ApplicationLogger
}

// NewAllocator returns a chromedp allocator context on a fresh profile dir;
// cancel stops Chrome and removes the dir. Leftovers of launches killed before
// their cancel ran are swept first.
func (l *Launcher) NewAllocator(ctx context.Context) (context.Context, context.CancelFunc, error) {
	l.sweepStaleProfiles()
	profileDir, err := os.MkdirTemp(l.tempDir(), profileDirPattern)
	if err != nil {
		return nil, nil, fmt.Errorf("browser: create profile dir: %w", err)
	}
	allocCtx, cancel := chromedp.NewExecAllocator(ctx, l.allocatorOptions(profileDir)...)
	return allocCtx, func() {
		cancel()
		// chromedp only removes profile dirs it created itself.
		if err := os.RemoveAll(profileDir); err != nil {
			l.warn("remove profile dir " + profileDir + ": " + err.Error())
		}
	}, nil
}

// allocatorOptions deliberately omits chromedp.DefaultExecAllocatorOptions:
// their bare --headless is the old mode, which Chromium 147+ breaks on.
func (l *Launcher) allocatorOptions(profileDir string) []chromedp.ExecAllocatorOption {
	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.DisableGPU,
		chromedp.NoSandbox,
		chromedp.UserDataDir(profileDir),
		chromedp.Flag("disable-setuid-sandbox", true),
		// Without a crash-dumps dir the crashpad handler exits with "--database is required".
		chromedp.Flag("crash-dumps-dir", filepath.Join(profileDir, "Crashes")),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-crash-reporter", true),
		chromedp.Flag("disable-breakpad", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("hide-scrollbars", true),
		chromedp.Flag("mute-audio", true),
		chromedp.ModifyCmdFunc(func(cmd *exec.Cmd) {
			cmd.Env = chromeEnv(os.Environ(), profileDir)
			l.info("launch: " + strings.Join(cmd.Args, " "))
		}),
	}
	if l.Headless {
		opts = append(opts, chromedp.Flag("headless", "new"))
	}
	if path := l.execPath(); path != "" {
		opts = append(opts, chromedp.ExecPath(path))
	}
	return opts
}

// chromeEnv points TMPDIR into the profile dir so Chrome's temp files are
// removed with it, and supplies a HOME when the service has none — crashpad
// derives its database path from it.
func chromeEnv(parent []string, profileDir string) []string {
	env := append([]string{}, parent...)
	hasHome := false
	for _, kv := range parent {
		if strings.HasPrefix(kv, "HOME=") && kv != "HOME=" {
			hasHome = true
		}
	}
	if !hasHome {
		env = append(env, "HOME="+profileDir)
	}
	return append(env, "TMPDIR="+profileDir)
}

func (l *Launcher) execPath() string {
	candidates := l.ExecPaths
	if candidates == nil {
		candidates = DefaultExecPaths
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func (l *Launcher) tempDir() string {
	if l.TempDir != "" {
		return l.TempDir
	}
	return os.TempDir()
}

func (l *Launcher) sweepStaleProfiles() {
	age := l.StaleProfileAge
	if age <= 0 {
		age = DefaultStaleProfileAge
	}
	cutoff := time.Now().Add(-age)
	for _, pattern := range []string{profileDirPattern, chromeTempPattern} {
		matches, _ := filepath.Glob(filepath.Join(l.tempDir(), pattern))
		for _, path := range matches {
			info, err := os.Lstat(path)
			if err != nil || info.ModTime().After(cutoff) {
				continue
			}
			if err := os.RemoveAll(path); err != nil {
				l.warn("sweep " + path + ": " + err.Error())
			}
		}
	}
}

func (l *Launcher) info(msg string) {
	if l.Journal != nil {
		l.Journal.Info("browser: " + msg)
	}
}

func (l *Launcher) warn(msg string) {
	if l.Journal != nil {
		l.Journal.Warning("browser: " + msg)
	}
}

package browser

import (
	"context"
	"fmt"
	"time"

	"github.com/chromedp/chromedp"
)

// Session is one running Chrome. Tabs share its cookies and cache; Close stops
// Chrome and removes its profile dir.
type Session struct {
	browserCtx context.Context
	close      context.CancelFunc
}

// Start launches Chrome and waits until DevTools answers.
func (l *Launcher) Start(ctx context.Context) (*Session, error) {
	allocCtx, cancelAlloc, err := l.NewAllocator(ctx)
	if err != nil {
		return nil, err
	}
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	s := &Session{browserCtx: browserCtx, close: func() {
		cancelBrowser()
		cancelAlloc()
	}}
	if err := chromedp.Run(browserCtx); err != nil {
		s.Close()
		return nil, fmt.Errorf("browser: start chrome: %w", err)
	}
	return s, nil
}

// Context is the browser-level chromedp context, which is also the first tab.
func (s *Session) Context() context.Context { return s.browserCtx }

// NewTab opens a tab that closes on cancel or after timeout; timeout <= 0 means no deadline.
func (s *Session) NewTab(timeout time.Duration) (context.Context, context.CancelFunc) {
	tabCtx, cancelTab := chromedp.NewContext(s.browserCtx)
	if timeout <= 0 {
		return tabCtx, cancelTab
	}
	timedCtx, cancelTimeout := context.WithTimeout(tabCtx, timeout)
	return timedCtx, func() {
		cancelTimeout()
		cancelTab()
	}
}

func (s *Session) Close() { s.close() }

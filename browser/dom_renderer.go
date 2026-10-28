package browser

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

var ErrEmptyURL = errors.New("browser: empty URL")

// DOMRenderer renders each request on its own Chrome, so it is safe for
// concurrent use and one page's state never reaches the next.
type DOMRenderer struct {
	Launcher *Launcher
}

var _ Renderer = (*DOMRenderer)(nil)

func (r *DOMRenderer) Render(ctx context.Context, req RenderRequest) (*RenderResult, error) {
	if strings.TrimSpace(req.URL) == "" {
		return nil, ErrEmptyURL
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = DefaultRenderTimeout
	}
	session, err := r.Launcher.Start(ctx)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	tabCtx, closeTab := session.NewTab(timeout)
	defer closeTab()

	if ua := strings.TrimSpace(req.UserAgent); ua != "" {
		if _, err := chromedp.Call(tabCtx, emulation.SetUserAgentOverride, emulation.SetUserAgentOverrideParams{UserAgent: ua}); err != nil {
			return nil, fmt.Errorf("browser: user agent for %s: %w", req.URL, err)
		}
	}
	var requests *requestLog
	if req.CaptureRequests {
		requests = newRequestLog(req.MaxRequests)
		requests.listen(tabCtx)
	}
	out := &RenderResult{URL: req.URL, Evaluations: map[string]any{}, EvaluationErrors: map[string]error{}}
	start := time.Now()
	err = chromedp.Do(tabCtx,
		chromedp.Navigate(req.URL),
		// body visible = the static shell of an asynchronously hydrating app is in place.
		chromedp.WaitVisible(chromedp.CSS("body")),
		chromedp.Func(func(context.Context, *chromedp.Target) error {
			out.Loaded = time.Since(start)
			return nil
		}),
		chromedp.Sleep(req.Settle),
	)
	if err == nil {
		out.RenderedHTML, err = chromedp.Run(tabCtx, chromedp.OuterHTML(chromedp.CSS("html")))
	}
	if err != nil {
		return nil, fmt.Errorf("browser: render %s: %w", req.URL, err)
	}
	if requests != nil {
		out.Requests, out.RequestsTruncated = requests.snapshot()
	}

	for label, expr := range req.Evaluations {
		// A throwing expression evaluates to nil: "feature absent" is a regular
		// outcome for a probe, distinct from an expression that could not run.
		guarded := fmt.Sprintf("(function(){try{return (%s);}catch(e){return null;}})()", expr)
		value, err := chromedp.Run(tabCtx, chromedp.Evaluate[any](guarded))
		if err != nil {
			out.EvaluationErrors[label] = err
			continue
		}
		out.Evaluations[label] = value
	}
	if req.CaptureCookies {
		if out.Cookies, err = cookies(tabCtx); err != nil {
			return nil, fmt.Errorf("browser: cookies of %s: %w", req.URL, err)
		}
	}
	return out, nil
}

func cookies(tabCtx context.Context) ([]http.Cookie, error) {
	res, err := chromedp.Call(tabCtx, network.GetCookies, network.GetCookiesParams{})
	if err != nil {
		return nil, err
	}
	out := make([]http.Cookie, 0, len(res.Cookies))
	for _, c := range res.Cookies {
		out = append(out, http.Cookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
			Secure: c.Secure, HttpOnly: c.HTTPOnly, SameSite: sameSite(c.SameSite),
		})
	}
	return out, nil
}

func sameSite(s network.CookieSameSite) http.SameSite {
	switch s {
	case network.CookieSameSiteStrict:
		return http.SameSiteStrictMode
	case network.CookieSameSiteLax:
		return http.SameSiteLaxMode
	case network.CookieSameSiteNone:
		return http.SameSiteNoneMode
	}
	return http.SameSiteDefaultMode
}

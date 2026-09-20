package browser

import (
	"context"
	"encoding/json"
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

	var actions chromedp.Tasks
	if ua := strings.TrimSpace(req.UserAgent); ua != "" {
		actions = append(actions, emulation.SetUserAgentOverride(ua))
	}
	out := &RenderResult{URL: req.URL, Evaluations: map[string]any{}, EvaluationErrors: map[string]error{}}
	start := time.Now()
	actions = append(actions,
		chromedp.Navigate(req.URL),
		// body visible = the static shell of an asynchronously hydrating app is in place.
		chromedp.WaitVisible("body", chromedp.ByQuery),
		chromedp.OuterHTML("html", &out.RenderedHTML),
	)
	if err := chromedp.Run(tabCtx, actions); err != nil {
		return nil, fmt.Errorf("browser: render %s: %w", req.URL, err)
	}
	out.Loaded = time.Since(start)

	for label, expr := range req.Evaluations {
		value, err := evaluate(tabCtx, expr)
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

// evaluate turns a throwing expression into nil: "feature absent" is a regular
// outcome for a probe, distinct from an expression that could not run.
func evaluate(tabCtx context.Context, expr string) (any, error) {
	var raw json.RawMessage
	guarded := fmt.Sprintf("(function(){try{return (%s);}catch(e){return null;}})()", expr)
	if err := chromedp.Run(tabCtx, chromedp.Evaluate(guarded, &raw)); err != nil {
		return nil, err
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func cookies(tabCtx context.Context) ([]http.Cookie, error) {
	var found []*network.Cookie
	err := chromedp.Run(tabCtx, chromedp.ActionFunc(func(ctx context.Context) (err error) {
		found, err = network.GetCookies().Do(ctx)
		return err
	}))
	if err != nil {
		return nil, err
	}
	out := make([]http.Cookie, 0, len(found))
	for _, c := range found {
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

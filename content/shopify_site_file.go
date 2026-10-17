package content

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/nauticana/keel/common"
)

var _ SiteFileWriter = (*ShopifyWriter)(nil)

const (
	shopifyRobotsPath     = "/robots.txt"
	shopifyRobotsTemplate = "templates/robots.txt.liquid"
	// shopifyRobotsDefaults is Shopify's own template; a written robots.txt
	// follows it so the platform's default rules stay.
	shopifyRobotsDefaults = `{% for group in robots.default_groups %}
  {{- group.user_agent }}

  {%- for rule in group.rules -%}
    {{ rule }}
  {%- endfor -%}

  {%- if group.sitemap != blank -%}
    {{ group.sitemap }}
  {%- endif -%}
{% endfor %}
`
)

// A site file is read back only from this host, through every redirect.
const shopifyFileHost = "cdn.shopify.com"

var sitePath = regexp.MustCompile(`^/[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ReadSiteFile reads /robots.txt from the main theme's robots.txt.liquid,
// without the defaults a write put before it, and any other path from the
// shop file its redirect points at.
func (w *ShopifyWriter) ReadSiteFile(ctx context.Context, ref ResourceRef, path string) (string, error) {
	if err := checkSitePath(path); err != nil {
		return "", err
	}
	if path == shopifyRobotsPath {
		_, body, err := mainThemeFile(ctx, ref, shopifyRobotsTemplate)
		if err != nil || body == nil {
			return "", err
		}
		return strings.TrimPrefix(*body, shopifyRobotsDefaults), nil
	}
	redirect, err := w.findRedirect(ctx, ref, path)
	if err != nil || redirect == nil {
		return "", err
	}
	return w.fetchShopFile(ctx, common.HTTPClient(), redirect.Target)
}

// WriteSiteFile writes /robots.txt into the main theme, after Shopify's
// defaults unless the theme's own template already replaced them, and any
// other path as an uploaded file behind a redirect, which Shopify follows only
// for a path it does not serve itself.
func (w *ShopifyWriter) WriteSiteFile(ctx context.Context, ref ResourceRef, path, content string) (WriteResult, error) {
	if err := checkSitePath(path); err != nil {
		return WriteResult{}, err
	}
	if path == shopifyRobotsPath {
		return w.writeRobots(ctx, ref, content)
	}
	redirect, err := w.findRedirect(ctx, ref, path)
	if err != nil {
		return WriteResult{}, err
	}
	if content == "" {
		if redirect == nil {
			return WriteResult{}, nil
		}
		return deleteShopifyRedirect(ctx, ref, redirect.ID)
	}
	url, uploaded, err := w.Upload(ctx, ref, strings.TrimPrefix(path, "/"), "text/plain", strings.NewReader(content))
	if err != nil {
		return uploaded, err
	}
	redirected, err := w.putRedirect(ctx, ref, redirect, path, url)
	return WriteResult{Response: uploaded.Response + "\n" + redirected.Response}, err
}

func (w *ShopifyWriter) writeRobots(ctx context.Context, ref ResourceRef, content string) (WriteResult, error) {
	themeID, current, err := mainThemeFile(ctx, ref, shopifyRobotsTemplate)
	if err != nil {
		return WriteResult{}, err
	}
	if (current == nil || strings.HasPrefix(*current, shopifyRobotsDefaults)) && !strings.Contains(content, "robots.default_groups") {
		content = shopifyRobotsDefaults + content
	}
	const mutation = `mutation($id:ID!,$files:[OnlineStoreThemeFilesUpsertFileInput!]!){` +
		`themeFilesUpsert(themeId:$id,files:$files){job{id} userErrors{field message}}}`
	payload, result, err := shopifyMutate(ctx, ref, "themeFilesUpsert", mutation, map[string]any{
		"id":    themeID,
		"files": []map[string]any{{"filename": shopifyRobotsTemplate, "body": map[string]any{"type": "TEXT", "value": content}}},
	})
	if err != nil {
		return result, err
	}
	var job *struct {
		ID string `json:"id"`
	}
	if raw := payload["job"]; raw != nil {
		if err := json.Unmarshal(raw, &job); err != nil {
			return result, fmt.Errorf("decode shopify theme job: %w", err)
		}
	}
	if job == nil || job.ID == "" {
		return result, nil
	}
	// The upsert may finish in a job; wait so a read-back sees the new file.
	return result, w.poll(ctx, "shopify theme job "+job.ID, func() (bool, error) {
		var data struct {
			Job *struct {
				Done bool `json:"done"`
			} `json:"job"`
		}
		if _, err := shopifyGraphQL(ctx, ref, `query($id:ID!){job(id:$id){done}}`, map[string]any{"id": job.ID}, &data); err != nil {
			return false, err
		}
		return data.Job == nil || data.Job.Done, nil
	})
}

// mainThemeFile returns the published theme's id and the file's text, nil
// when the theme has no such file.
func mainThemeFile(ctx context.Context, ref ResourceRef, filename string) (string, *string, error) {
	const query = `query($f:[String!]){themes(first:1,roles:[MAIN]){nodes{id ` +
		`files(filenames:$f,first:1){nodes{body{... on OnlineStoreThemeFileBodyText{content}}}}}}}`
	var data struct {
		Themes struct {
			Nodes []struct {
				ID    string `json:"id"`
				Files struct {
					Nodes []struct {
						Body struct {
							Content *string `json:"content"`
						} `json:"body"`
					} `json:"nodes"`
				} `json:"files"`
			} `json:"nodes"`
		} `json:"themes"`
	}
	if _, err := shopifyGraphQL(ctx, ref, query, map[string]any{"f": []string{filename}}, &data); err != nil {
		return "", nil, err
	}
	if len(data.Themes.Nodes) == 0 {
		return "", nil, fmt.Errorf("%w: the shop has no published theme", ErrResourceNotFound)
	}
	theme := data.Themes.Nodes[0]
	if len(theme.Files.Nodes) == 0 {
		return theme.ID, nil, nil
	}
	if theme.Files.Nodes[0].Body.Content == nil {
		return "", nil, fmt.Errorf("%w: theme file %s is not text", ErrRejected, filename)
	}
	return theme.ID, theme.Files.Nodes[0].Body.Content, nil
}

// fetchShopFile reads a file the shop hosts over base, capped at
// MaxUploadBytes. A URL or redirect off the Shopify CDN is not a file this
// writer put there.
func (w *ShopifyWriter) fetchShopFile(ctx context.Context, base *http.Client, url string) (string, error) {
	if !isShopifyFileURL(url) {
		return "", fmt.Errorf("%w: site file redirects to %q, not a shop file", ErrRejected, url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	client := *base
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !isShopifyFileURL(req.URL.String()) {
			return fmt.Errorf("%w: site file redirected off the Shopify CDN", ErrRejected)
		}
		if base.CheckRedirect != nil {
			return base.CheckRedirect(req, via)
		}
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("content: fetch site file: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: site file %s answered HTTP %d", ErrRejected, url, resp.StatusCode)
	}
	body, err := w.readCapped(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func isShopifyFileURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && strings.EqualFold(u.Host, shopifyFileHost) && u.User == nil
}

func checkSitePath(path string) error {
	if !sitePath.MatchString(path) {
		return fmt.Errorf("%w: %q is not a site-root file path", ErrRejected, path)
	}
	return nil
}

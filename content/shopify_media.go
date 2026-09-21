package content

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
)

// Defaults for ShopifyWriter's upload path.
const (
	DefaultMaxUploadBytes = 20 << 20 // Shopify's own image ceiling
	defaultPollAttempts   = 12
	defaultPollInterval   = 500 * time.Millisecond
)

var _ MediaUploader = (*ShopifyWriter)(nil)

// Upload puts a file on the shop's own CDN in Shopify's three steps — stage,
// POST the bytes to the staged target, register the file — and waits for the
// asset to leave PROCESSING so the returned URL is one a field can actually
// hold. The bytes are buffered because the staged upload is signed for an exact
// size, so the cap is what keeps that buffer bounded.
func (w *ShopifyWriter) Upload(ctx context.Context, ref ResourceRef, name, contentType string, r io.Reader) (string, WriteResult, error) {
	if name == "" || r == nil {
		return "", WriteResult{}, fmt.Errorf("%w: upload needs a filename and a reader", ErrRejected)
	}
	body, err := w.readCapped(r)
	if err != nil {
		return "", WriteResult{}, err
	}
	if contentType == "" {
		contentType = http.DetectContentType(body)
	}
	resource := "FILE"
	if strings.HasPrefix(contentType, "image/") {
		resource = "IMAGE"
	}
	target, err := stageShopifyUpload(ctx, ref, name, contentType, resource, len(body))
	if err != nil {
		return "", WriteResult{}, err
	}
	if err := postStagedUpload(ctx, target, name, body); err != nil {
		return "", WriteResult{}, err
	}
	fileID, result, err := createShopifyFile(ctx, ref, target.ResourceURL, resource, name)
	if err != nil {
		return "", result, err
	}
	url, err := w.awaitFileURL(ctx, ref, fileID)
	if err != nil {
		return "", result, err
	}
	return url, result, nil
}

func (w *ShopifyWriter) readCapped(r io.Reader) ([]byte, error) {
	max := w.MaxUploadBytes
	if max <= 0 {
		max = DefaultMaxUploadBytes
	}
	body, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, fmt.Errorf("content: read media: %w", err)
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("%w: %d bytes", ErrMediaTooLarge, max)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("%w: media is empty", ErrRejected)
	}
	return body, nil
}

type stagedTarget struct {
	URL         string `json:"url"`
	ResourceURL string `json:"resourceUrl"`
	Parameters  []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"parameters"`
}

func stageShopifyUpload(ctx context.Context, ref ResourceRef, name, contentType, resource string, size int) (stagedTarget, error) {
	const query = `mutation($in:[StagedUploadInput!]!){stagedUploadsCreate(input:$in){` +
		`stagedTargets{url resourceUrl parameters{name value}} userErrors{field message}}}`
	payload, _, err := shopifyMutate(ctx, ref, "stagedUploadsCreate", query, map[string]any{
		"in": []map[string]any{{
			"filename":   name,
			"mimeType":   contentType,
			"resource":   resource,
			"httpMethod": "POST",
			"fileSize":   strconv.Itoa(size),
		}},
	})
	if err != nil {
		return stagedTarget{}, err
	}
	var targets []stagedTarget
	if raw, ok := payload["stagedTargets"]; ok {
		if err := json.Unmarshal(raw, &targets); err != nil {
			return stagedTarget{}, fmt.Errorf("decode shopify staged target: %w", err)
		}
	}
	if len(targets) == 0 || targets[0].URL == "" || targets[0].ResourceURL == "" {
		return stagedTarget{}, fmt.Errorf("%w: shopify staged no upload target", ErrRejected)
	}
	return targets[0], nil
}

// postStagedUpload sends the bytes to the staged target. The target is a signed
// third-party URL, so the shop's access token is deliberately not attached, and
// its parameters must precede the file part.
func postStagedUpload(ctx context.Context, target stagedTarget, name string, body []byte) error {
	var buf bytes.Buffer
	form := multipart.NewWriter(&buf)
	for _, p := range target.Parameters {
		if err := form.WriteField(p.Name, p.Value); err != nil {
			return fmt.Errorf("content: staged upload form: %w", err)
		}
	}
	part, err := form.CreateFormFile("file", name)
	if err != nil {
		return fmt.Errorf("content: staged upload form: %w", err)
	}
	if _, err := part.Write(body); err != nil {
		return fmt.Errorf("content: staged upload form: %w", err)
	}
	if err := form.Close(); err != nil {
		return fmt.Errorf("content: staged upload form: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.URL, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", form.FormDataContentType())
	resp, err := common.HTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("content: staged upload: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%w: staged upload HTTP %d: %s", ErrRejected, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func createShopifyFile(ctx context.Context, ref ResourceRef, resourceURL, resource, name string) (string, WriteResult, error) {
	const query = `mutation($in:[FileCreateInput!]!){fileCreate(files:$in){files{id} userErrors{field message}}}`
	payload, result, err := shopifyMutate(ctx, ref, "fileCreate", query, map[string]any{
		"in": []map[string]any{{"originalSource": resourceURL, "contentType": resource, "alt": name}},
	})
	if err != nil {
		return "", result, err
	}
	var files []struct {
		ID string `json:"id"`
	}
	if raw, ok := payload["files"]; ok {
		if err := json.Unmarshal(raw, &files); err != nil {
			return "", result, fmt.Errorf("decode shopify file: %w", err)
		}
	}
	if len(files) == 0 || files[0].ID == "" {
		return "", result, fmt.Errorf("%w: shopify fileCreate returned no file", ErrRejected)
	}
	return files[0].ID, result, nil
}

// Shopify file processing states.
const (
	shopifyFileReady  = "READY"
	shopifyFileFailed = "FAILED"
)

// awaitFileURL polls until the asset is servable. A file that is still
// PROCESSING has no URL, and a caller that wrote "" into a CMS field would
// publish a broken image.
func (w *ShopifyWriter) awaitFileURL(ctx context.Context, ref ResourceRef, fileID string) (string, error) {
	const query = `query($id:ID!){node(id:$id){... on MediaImage{fileStatus image{url}} ... on GenericFile{fileStatus url}}}`
	attempts, interval := w.PollAttempts, w.PollInterval
	if attempts <= 0 {
		attempts = defaultPollAttempts
	}
	if interval <= 0 {
		interval = defaultPollInterval
	}
	for attempt := range attempts {
		if attempt > 0 {
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return "", ctx.Err()
			case <-timer.C:
			}
		}
		var data struct {
			Node *struct {
				FileStatus string `json:"fileStatus"`
				URL        string `json:"url"`
				Image      *struct {
					URL string `json:"url"`
				} `json:"image"`
			} `json:"node"`
		}
		if _, err := shopifyGraphQL(ctx, ref, query, map[string]any{"id": fileID}, &data); err != nil {
			return "", err
		}
		if data.Node == nil {
			return "", fmt.Errorf("%w: shopify file %s", ErrResourceNotFound, fileID)
		}
		if data.Node.FileStatus == shopifyFileFailed {
			return "", fmt.Errorf("%w: shopify could not process the file", ErrRejected)
		}
		url := data.Node.URL
		if url == "" && data.Node.Image != nil {
			url = data.Node.Image.URL
		}
		if data.Node.FileStatus == shopifyFileReady && url != "" {
			return url, nil
		}
	}
	return "", fmt.Errorf("%w: shopify file %s is still processing", ErrThrottled, fileID)
}

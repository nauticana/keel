package content

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// stagedUploadServer plays both halves of Shopify's upload: the Admin GraphQL
// endpoint and the signed third-party target the bytes are POSTed to.
type stagedUploadServer struct {
	t         *testing.T
	responses []string // GraphQL replies, in order
	requests  []gqlRequest

	gotFields map[string]string
	gotFile   []byte
	gotName   string
	uploadTo  string
	uploadErr int
}

func (s *stagedUploadServer) start() ResourceRef {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.uploadErr != 0 {
			w.WriteHeader(s.uploadErr)
			_, _ = w.Write([]byte("denied"))
			return
		}
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			s.t.Errorf("content type: %v", err)
			return
		}
		s.gotFields = map[string]string{}
		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				s.t.Errorf("multipart: %v", err)
				return
			}
			body, _ := io.ReadAll(part)
			if part.FormName() == "file" {
				s.gotFile, s.gotName = body, part.FileName()
				continue
			}
			s.gotFields[part.FormName()] = string(body)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	s.t.Cleanup(target.Close)
	s.uploadTo = target.URL

	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req gqlRequest
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			s.t.Errorf("request body %q: %v", body, err)
		}
		s.requests = append(s.requests, req)
		reply := s.responses[len(s.requests)-1]
		_, _ = w.Write([]byte(strings.ReplaceAll(reply, "{{TARGET}}", target.URL)))
	}))
	s.t.Cleanup(admin.Close)
	return ResourceRef{Endpoint: admin.URL + "/admin/api/v1", Token: "shpat"}
}

func fastUploader(t *testing.T) *ShopifyWriter {
	w := newTestWriter(t)
	w.PollInterval = time.Millisecond
	return w
}

const stagedReply = `{"data":{"stagedUploadsCreate":{"stagedTargets":[{"url":"{{TARGET}}",` +
	`"resourceUrl":"https://shopify-staged/tmp/hero.png","parameters":[{"name":"key","value":"tmp/hero.png"},` +
	`{"name":"policy","value":"POLICY"}]}],"userErrors":[]}}}`

func TestShopifyUploadReturnsCDNURL(t *testing.T) {
	srv := &stagedUploadServer{t: t, responses: []string{
		stagedReply,
		`{"data":{"fileCreate":{"files":[{"id":"gid://shopify/MediaImage/5"}],"userErrors":[]}}}`,
		`{"data":{"node":{"fileStatus":"PROCESSING","image":null}}}`,
		`{"data":{"node":{"fileStatus":"READY","image":{"url":"https://cdn.shopify.com/hero.png"}}}}`,
	}}
	ref := srv.start()

	url, res, err := fastUploader(t).Upload(context.Background(), ref, "hero.png", "image/png", bytes.NewReader([]byte("PNGDATA")))
	if err != nil {
		t.Fatal(err)
	}
	if url != "https://cdn.shopify.com/hero.png" {
		t.Fatalf("url = %q", url)
	}
	if res.Response == "" {
		t.Error("raw fileCreate response should be kept for audit")
	}
	// The staged parameters must be sent, and the bytes must arrive intact.
	if srv.gotFields["policy"] != "POLICY" || srv.gotFields["key"] != "tmp/hero.png" {
		t.Errorf("staged parameters not forwarded: %v", srv.gotFields)
	}
	if string(srv.gotFile) != "PNGDATA" || srv.gotName != "hero.png" {
		t.Errorf("file part = %q %q", srv.gotFile, srv.gotName)
	}
	// An image stages and registers as IMAGE, with the exact byte count.
	in := srv.requests[0].Variables["in"].([]any)[0].(map[string]any)
	if in["resource"] != "IMAGE" || in["fileSize"] != "7" || in["mimeType"] != "image/png" {
		t.Errorf("staged input = %v", in)
	}
	if got := srv.requests[1].Variables["in"].([]any)[0].(map[string]any); got["originalSource"] != "https://shopify-staged/tmp/hero.png" {
		t.Errorf("fileCreate input = %v", got)
	}
}

// A non-image is staged as a generic file and reports its own url member.
func TestShopifyUploadGenericFile(t *testing.T) {
	srv := &stagedUploadServer{t: t, responses: []string{
		stagedReply,
		`{"data":{"fileCreate":{"files":[{"id":"gid://shopify/GenericFile/5"}],"userErrors":[]}}}`,
		`{"data":{"node":{"fileStatus":"READY","url":"https://cdn.shopify.com/spec.pdf"}}}`,
	}}
	ref := srv.start()

	url, _, err := fastUploader(t).Upload(context.Background(), ref, "spec.pdf", "application/pdf", strings.NewReader("%PDF"))
	if err != nil || url != "https://cdn.shopify.com/spec.pdf" {
		t.Fatalf("url = %q err = %v", url, err)
	}
	if in := srv.requests[0].Variables["in"].([]any)[0].(map[string]any); in["resource"] != "FILE" {
		t.Errorf("resource = %v, want FILE", in["resource"])
	}
}

func TestShopifyUploadCapsSize(t *testing.T) {
	w := newTestWriter(t)
	w.MaxUploadBytes = 8
	ref := ResourceRef{Endpoint: "https://x/admin/api/v1"}

	_, _, err := w.Upload(context.Background(), ref, "big.png", "image/png", bytes.NewReader(make([]byte, 9)))
	if !errors.Is(err, ErrMediaTooLarge) {
		t.Fatalf("err = %v, want ErrMediaTooLarge", err)
	}
	if _, _, err := w.Upload(context.Background(), ref, "empty.png", "image/png", strings.NewReader("")); !errors.Is(err, ErrRejected) {
		t.Fatalf("empty media: %v", err)
	}
	if _, _, err := w.Upload(context.Background(), ref, "", "image/png", strings.NewReader("x")); !errors.Is(err, ErrRejected) {
		t.Fatalf("missing name: %v", err)
	}
}

// A file Shopify could not process is a refusal, not a URL.
func TestShopifyUploadFailedProcessing(t *testing.T) {
	srv := &stagedUploadServer{t: t, responses: []string{
		stagedReply,
		`{"data":{"fileCreate":{"files":[{"id":"gid://shopify/MediaImage/5"}],"userErrors":[]}}}`,
		`{"data":{"node":{"fileStatus":"FAILED"}}}`,
	}}
	if _, _, err := fastUploader(t).Upload(context.Background(), srv.start(), "hero.png", "image/png", strings.NewReader("x")); !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
}

// Still processing when the polls run out is retryable, not a permanent failure.
func TestShopifyUploadStillProcessingIsRetryable(t *testing.T) {
	srv := &stagedUploadServer{t: t, responses: []string{
		stagedReply,
		`{"data":{"fileCreate":{"files":[{"id":"gid://shopify/MediaImage/5"}],"userErrors":[]}}}`,
		`{"data":{"node":{"fileStatus":"PROCESSING"}}}`,
		`{"data":{"node":{"fileStatus":"PROCESSING"}}}`,
	}}
	w := fastUploader(t)
	w.PollAttempts = 2
	if _, _, err := w.Upload(context.Background(), srv.start(), "hero.png", "image/png", strings.NewReader("x")); !errors.Is(err, ErrThrottled) {
		t.Fatalf("err = %v, want ErrThrottled", err)
	}
}

// The staged target is a signed third-party URL; a refusal there must surface
// rather than register a file whose bytes never arrived.
func TestShopifyUploadStagedTargetRefusal(t *testing.T) {
	srv := &stagedUploadServer{t: t, responses: []string{stagedReply}, uploadErr: http.StatusForbidden}
	_, _, err := fastUploader(t).Upload(context.Background(), srv.start(), "hero.png", "image/png", strings.NewReader("x"))
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
	if len(srv.requests) != 1 {
		t.Error("fileCreate must not run after a failed upload")
	}
}

func TestShopifyUploadWithoutStagedTarget(t *testing.T) {
	srv := &stagedUploadServer{t: t, responses: []string{
		`{"data":{"stagedUploadsCreate":{"stagedTargets":[],"userErrors":[]}}}`,
	}}
	if _, _, err := fastUploader(t).Upload(context.Background(), srv.start(), "hero.png", "image/png", strings.NewReader("x")); !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
}

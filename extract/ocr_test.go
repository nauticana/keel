package extract

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"google.golang.org/api/option"
	"google.golang.org/api/vision/v1"
)

type stubExtractor Extracted

func (stubExtractor) Supports(string) bool { return true }
func (s stubExtractor) Extract(context.Context, string, []byte) (Extracted, error) {
	return Extracted(s), nil
}

type stubRecognizer struct {
	text  map[int]string
	asked []int
}

func (r *stubRecognizer) RecognizePages(_ context.Context, _ string, _ []byte, pages []int) (map[int]string, error) {
	r.asked = pages
	return r.text, nil
}

// threePages has a text layer on page 2 only.
var threePages = stubExtractor{Text: "\fmiddle\f\f", Sections: []Section{
	{Kind: Page, Page: 1, Start: 0, End: 0},
	{Kind: Page, Page: 2, Start: 1, End: 7},
	{Kind: Page, Page: 3, Start: 8, End: 8},
}}

func TestOCRFillsOnlyEmptyPages(t *testing.T) {
	r := &stubRecognizer{text: map[int]string{1: "first\fscan", 3: "last"}}
	got, err := OCR{Primary: threePages, Recognizer: r, MaxBytes: 1 << 10}.Extract(context.Background(), mediaPDF, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.asked, []int{1, 3}) {
		t.Errorf("recognized pages %v, want [1 3]", r.asked)
	}
	if got.Text != "first\nscan\fmiddle\flast\f" {
		t.Errorf("text = %q", got.Text)
	}
	for i, want := range []string{"first\nscan", "middle", "last"} {
		if s := got.Sections[i]; text(got, s) != want || s.Page != i+1 {
			t.Errorf("page %d = %+v %q, want %q", i+1, s, text(got, s), want)
		}
	}
}

func TestOCRBounds(t *testing.T) {
	ctx := context.Background()
	r := &stubRecognizer{text: map[int]string{1: "a long recognized page"}}
	if _, err := (OCR{Primary: threePages, Recognizer: r, MaxBytes: 1 << 10, MaxPages: 1}).Extract(ctx, mediaPDF, nil); !errors.Is(err, ErrTooLarge) {
		t.Errorf("over the page limit: %v", err)
	}
	if r.asked != nil {
		t.Error("a document over the page limit must not reach the recognizer")
	}
	if _, err := (OCR{Primary: threePages, Recognizer: r, MaxBytes: 12}).Extract(ctx, mediaPDF, nil); !errors.Is(err, ErrTooLarge) {
		t.Errorf("over the text limit: %v", err)
	}
	r.asked = nil
	if _, err := (OCR{Primary: threePages, Recognizer: r, MaxBytes: 1 << 10}).Extract(ctx, mediaDOCX, nil); err != nil || r.asked != nil {
		t.Errorf("only PDFs go to OCR: err %v, asked %v", err, r.asked)
	}
	if _, err := (OCR{Primary: threePages, MaxBytes: 1}).Extract(ctx, mediaPDF, nil); err == nil {
		t.Error("a missing Recognizer must fail")
	}
}

func TestVisionBatchesFivePages(t *testing.T) {
	var batches [][]int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body vision.BatchAnnotateFilesRequest
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		file := body.Requests[0]
		if file.InputConfig.MimeType != mediaPDF || file.InputConfig.Content != "JVBERg==" || file.Features[0].Type != "DOCUMENT_TEXT_DETECTION" {
			t.Errorf("request = %+v", file)
		}
		batches = append(batches, file.Pages)
		var pages []*vision.AnnotateImageResponse
		for _, p := range file.Pages {
			pages = append(pages, &vision.AnnotateImageResponse{
				Context:            &vision.ImageAnnotationContext{PageNumber: p},
				FullTextAnnotation: &vision.TextAnnotation{Text: "page"},
			})
		}
		json.NewEncoder(w).Encode(vision.BatchAnnotateFilesResponse{Responses: []*vision.AnnotateFileResponse{{Responses: pages}}})
	}))
	defer server.Close()
	v, err := NewVision(context.Background(), option.WithEndpoint(server.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.RecognizePages(context.Background(), mediaPDF, []byte("%PDF"), []int{1, 2, 3, 4, 5, 6, 9})
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) != 2 || len(batches[0]) != 5 || !slices.Equal(batches[1], []int64{6, 9}) {
		t.Errorf("batches = %v", batches)
	}
	if len(got) != 7 || got[9] != "page" {
		t.Errorf("recognized = %v", got)
	}
	if _, err := v.RecognizePages(context.Background(), "image/png", nil, []int{1}); !errors.Is(err, ErrUnsupportedMediaType) {
		t.Errorf("non-PDF: %v", err)
	}
}

func TestVisionPageError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(vision.BatchAnnotateFilesResponse{Responses: []*vision.AnnotateFileResponse{{
			Responses: []*vision.AnnotateImageResponse{{Error: &vision.Status{Message: "bad page"}}},
		}}})
	}))
	defer server.Close()
	v, err := NewVision(context.Background(), option.WithEndpoint(server.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.RecognizePages(context.Background(), mediaPDF, nil, []int{1}); err == nil {
		t.Error("a page error must fail the document")
	}
}

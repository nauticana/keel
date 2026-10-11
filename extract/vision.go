package extract

import (
	"context"
	"encoding/base64"
	"fmt"

	"google.golang.org/api/option"
	"google.golang.org/api/vision/v1"
)

// visionPagesPerCall is the Cloud Vision files:annotate limit.
const visionPagesPerCall = 5

// Vision recognizes PDF pages with Google Cloud Vision document text detection.
type Vision struct {
	service *vision.Service
}

var _ PageRecognizer = (*Vision)(nil)

// NewVision authenticates with Application Default Credentials unless opts say otherwise.
func NewVision(ctx context.Context, opts ...option.ClientOption) (*Vision, error) {
	service, err := vision.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("extract: vision client: %w", err)
	}
	return &Vision{service: service}, nil
}

func (v *Vision) RecognizePages(ctx context.Context, mediaType string, raw []byte, pages []int) (map[int]string, error) {
	if baseType(mediaType) != mediaPDF {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedMediaType, mediaType)
	}
	content := base64.StdEncoding.EncodeToString(raw)
	out := make(map[int]string, len(pages))
	for len(pages) > 0 {
		n := min(len(pages), visionPagesPerCall)
		batch := make([]int64, n)
		for i, p := range pages[:n] {
			batch[i] = int64(p)
		}
		pages = pages[n:]
		resp, err := v.service.Files.Annotate(&vision.BatchAnnotateFilesRequest{Requests: []*vision.AnnotateFileRequest{{
			InputConfig: &vision.InputConfig{Content: content, MimeType: mediaPDF},
			Features:    []*vision.Feature{{Type: "DOCUMENT_TEXT_DETECTION"}},
			Pages:       batch,
		}}}).Context(ctx).Do()
		if err != nil {
			return nil, err
		}
		if len(resp.Responses) != 1 {
			return nil, fmt.Errorf("vision: %d file responses, want 1", len(resp.Responses))
		}
		file := resp.Responses[0]
		if file.Error != nil {
			return nil, fmt.Errorf("vision: %s", file.Error.Message)
		}
		for _, page := range file.Responses {
			switch {
			case page.Error != nil:
				return nil, fmt.Errorf("vision: %s", page.Error.Message)
			case page.Context == nil:
				return nil, fmt.Errorf("vision: page response without a page number")
			case page.FullTextAnnotation != nil:
				out[int(page.Context.PageNumber)] = page.FullTextAnnotation.Text
			}
		}
	}
	return out, nil
}

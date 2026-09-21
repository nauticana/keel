package reference

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIndexNowSubmitBatchesAndMapsStatus(t *testing.T) {
	var batches []indexNowRequest
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body indexNowRequest
		json.NewDecoder(r.Body).Decode(&body)
		batches = append(batches, body)
		w.WriteHeader(status)
	}))
	defer srv.Close()

	client := &IndexNowClient{APIKey: testKey, Endpoint: srv.URL}
	urls := make([]string, IndexNowMaxURLs+1)
	for i := range urls {
		urls[i] = "https://shop.example/p"
	}
	if err := client.Submit(context.Background(), "shop.example", urls); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 2 || len(batches[0].URLList) != IndexNowMaxURLs || len(batches[1].URLList) != 1 ||
		batches[0].Key != "k-123" || batches[0].Host != "shop.example" {
		t.Fatalf("unexpected batches: %d", len(batches))
	}

	status = http.StatusUnprocessableEntity
	if err := client.Submit(context.Background(), "shop.example", urls[:1]); !errors.Is(err, ErrIndexNowURLMismatch) {
		t.Fatalf("err = %v", err)
	}
}

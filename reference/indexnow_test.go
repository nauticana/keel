package reference

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestIndexNowVerifyKeyFile(t *testing.T) {
	served, status := "k-123\n", http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(served))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	client := &IndexNowClient{APIKey: testKey, KeyLocation: srv.URL + "/k-123.txt"}
	ctx := context.Background()

	if err := client.VerifyKeyFile(ctx, host); err != nil {
		t.Fatalf("served key: %v", err)
	}

	served = "another-key"
	if err := client.VerifyKeyFile(ctx, host); !errors.Is(err, ErrIndexNowKeyNotServed) {
		t.Fatalf("mismatched key: %v", err)
	}

	served, status = "k-123", http.StatusNotFound
	if err := client.VerifyKeyFile(ctx, host); !errors.Is(err, ErrIndexNowKeyNotServed) {
		t.Fatalf("missing file: %v", err)
	}

	status = http.StatusServiceUnavailable
	if err := client.VerifyKeyFile(ctx, host); err == nil || errors.Is(err, ErrIndexNowKeyNotServed) {
		t.Fatalf("transient failure must not be a verdict: %v", err)
	}

	if err := client.VerifyKeyFile(ctx, "other.example"); !errors.Is(err, ErrIndexNowKeyNotServed) {
		t.Fatalf("foreign key location: %v", err)
	}
	if err := client.VerifyKeyFile(ctx, ""); err == nil || errors.Is(err, ErrIndexNowKeyNotServed) {
		t.Fatalf("empty host: %v", err)
	}
	if err := (&IndexNowClient{}).VerifyKeyFile(ctx, host); !errors.Is(err, ErrNoAPIKey) {
		t.Fatalf("no key: %v", err)
	}
}

func TestIndexNowKeyFileURLDefaultsToProtocolLocation(t *testing.T) {
	got, err := (&IndexNowClient{}).keyFileURL("www.shop.example", "k-123")
	if err != nil || got != "https://www.shop.example/k-123.txt" {
		t.Fatalf("keyFileURL = %q, %v", got, err)
	}
}

func TestIndexNowVerifyKeyFileErrorOmitsKey(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	host := strings.TrimPrefix(srv.URL, "http://")
	client := &IndexNowClient{APIKey: testKey, KeyLocation: srv.URL + "/k-123.txt"}
	srv.Close()

	err := client.VerifyKeyFile(context.Background(), host)
	if err == nil || errors.Is(err, ErrIndexNowKeyNotServed) || strings.Contains(err.Error(), "k-123") {
		t.Fatalf("unreachable host: %v", err)
	}
}

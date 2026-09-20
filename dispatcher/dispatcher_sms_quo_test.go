package dispatcher

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/secret"
)

type quoSecretProvider struct {
	value string
	err   error
}

type quoRoundTripFunc func(*http.Request) (*http.Response, error)

func (f quoRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

var _ http.RoundTripper = quoRoundTripFunc(nil)

func (p quoSecretProvider) GetSecret(context.Context, string) (string, error) {
	return p.value, p.err
}

var _ secret.SecretProvider = quoSecretProvider{}

func TestQuoSMSDispatcherSendContract(t *testing.T) {
	var gotAuthorization string
	var gotContentType string
	var gotBody struct {
		Content string   `json:"content"`
		From    string   `json:"from"`
		To      []string `json:"to"`
	}
	client := &http.Client{Transport: quoRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		gotAuthorization = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"data":{}}`)),
			Request:    r,
		}, nil
	})}

	previous := config.Config()
	config.SetConfig(&config.KeelConfig{SMSServiceSID: " PNsender "})
	t.Cleanup(func() { config.SetConfig(previous) })

	dispatcher, err := newQuoSMSDispatcherWithClient(
		context.Background(), quoSecretProvider{value: " api-key "}, nil, nil, "https://quo.test/v1/messages", client,
	)
	if err != nil {
		t.Fatalf("newQuoSMSDispatcherWithClient: %v", err)
	}
	if err := dispatcher.Send(context.Background(), "(949) 394-6318", "", "hello", map[string]string{"country": "US"}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if gotAuthorization != "api-key" {
		t.Errorf("Authorization = %q, want raw API key", gotAuthorization)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	if gotBody.Content != "hello" || gotBody.From != "PNsender" {
		t.Errorf("body = %+v, want content hello and sender PNsender", gotBody)
	}
	if len(gotBody.To) != 1 || gotBody.To[0] != "+19493946318" {
		t.Errorf("body.to = %v, want [+19493946318]", gotBody.To)
	}
}

func TestQuoSMSDispatcherConfigurationErrors(t *testing.T) {
	previous := config.Config()
	t.Cleanup(func() { config.SetConfig(previous) })

	t.Run("secret lookup", func(t *testing.T) {
		config.SetConfig(&config.KeelConfig{SMSServiceSID: "+19493946318"})
		want := errors.New("secret unavailable")
		_, err := newQuoSMSDispatcherWithClient(context.Background(), quoSecretProvider{err: want}, nil, nil, "unused", http.DefaultClient)
		if !errors.Is(err, want) {
			t.Fatalf("error = %v, want wrapped secret error", err)
		}
	})

	t.Run("blank API key", func(t *testing.T) {
		config.SetConfig(&config.KeelConfig{SMSServiceSID: "+19493946318"})
		_, err := newQuoSMSDispatcherWithClient(context.Background(), quoSecretProvider{value: " \t "}, nil, nil, "unused", http.DefaultClient)
		if err == nil || !strings.Contains(err.Error(), "sms_auth_token is empty") {
			t.Fatalf("error = %v, want blank-token error", err)
		}
	})

	t.Run("blank sender", func(t *testing.T) {
		config.SetConfig(&config.KeelConfig{})
		_, err := newQuoSMSDispatcherWithClient(context.Background(), quoSecretProvider{value: "api-key"}, nil, nil, "unused", http.DefaultClient)
		if err == nil || !strings.Contains(err.Error(), "sms_service_sid not set") {
			t.Fatalf("error = %v, want missing-sender error", err)
		}
	})
}

func TestQuoSMSDispatcherPropagatesHTTPError(t *testing.T) {
	client := &http.Client{Transport: quoRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("carrier registration required\n")),
			Request:    r,
		}, nil
	})}

	previous := config.Config()
	config.SetConfig(&config.KeelConfig{SMSServiceSID: "+19493946318"})
	t.Cleanup(func() { config.SetConfig(previous) })

	dispatcher, err := newQuoSMSDispatcherWithClient(
		context.Background(), quoSecretProvider{value: "api-key"}, nil, nil, "https://quo.test/v1/messages", client,
	)
	if err != nil {
		t.Fatalf("newQuoSMSDispatcherWithClient: %v", err)
	}
	err = dispatcher.Send(context.Background(), "+19493946318", "", "hello", nil)
	if err == nil || !strings.Contains(err.Error(), "quo: http 400: carrier registration required") {
		t.Fatalf("error = %v, want provider HTTP error", err)
	}
}

package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWellKnownHandlerServesJSONWithoutRedirect(t *testing.T) {
	h := &WellKnownHandler{Documents: map[string][]byte{AppleAppSiteAssociationPath: []byte(`{"applinks":{}}`)}}
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.GetPublicRoutes()[AppleAppSiteAssociationPath](rec, httptest.NewRequest(http.MethodGet, AppleAppSiteAssociationPath, nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" || rec.Body.String() != `{"applinks":{}}` {
		t.Fatalf("unexpected response: %d %q %s", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.GetPublicRoutes()[AppleAppSiteAssociationPath](rec, httptest.NewRequest(http.MethodPost, AppleAppSiteAssociationPath, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.GetPublicRoutes()[AppleAppSiteAssociationPath](rec, httptest.NewRequest(http.MethodHead, AppleAppSiteAssociationPath, nil))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("HEAD status = %d, body = %q", rec.Code, rec.Body.String())
	}

	bad := &WellKnownHandler{Documents: map[string][]byte{AndroidAssetLinksPath: []byte(`not json`)}}
	if bad.Validate() == nil {
		t.Fatal("invalid JSON must fail validation")
	}
}

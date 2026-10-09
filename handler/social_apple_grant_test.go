package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/crypto"
	"github.com/nauticana/keel/oauth/oidc"
	"github.com/nauticana/keel/user"
)

type appleSecrets map[string]string

func (s appleSecrets) GetSecret(_ context.Context, name string) (string, error) {
	if v, ok := s[name]; ok {
		return v, nil
	}
	return "", errors.New("no secret")
}

// appleGrants wires oidc.AppleGrants to a fake Apple token endpoint that
// accepts only the code "good" and names subject a-1.
func appleGrants(t *testing.T, keys *socialKeys) *oidc.AppleGrants {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("code") != "good" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		idToken := keys.token(t, jwt.MapClaims{"iss": user.AppleIssuer, "aud": "apple-client", "sub": "a-1", "exp": time.Now().Add(time.Hour).Unix()})
		_ = json.NewEncoder(w).Encode(map[string]string{"refresh_token": "apple-refresh", "id_token": idToken})
	}))
	t.Cleanup(srv.Close)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	secrets := appleSecrets{
		"apple_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"kek":       base64.StdEncoding.EncodeToString(kek),
	}
	c := config.Config()
	team, keyID, secretName := c.AppleTeamID, c.AppleKeyID, c.AppleKeySecret
	c.AppleTeamID, c.AppleKeyID, c.AppleKeySecret = "TEAM", "KEY", "apple_key"
	t.Cleanup(func() { c.AppleTeamID, c.AppleKeyID, c.AppleKeySecret = team, keyID, secretName })
	sealer, err := crypto.NewSealer(context.Background(), secrets, "kek")
	if err != nil {
		t.Fatal(err)
	}
	a, err := oidc.NewAppleGrants(context.Background(), secrets, sealer)
	if err != nil {
		t.Fatal(err)
	}
	a.TokenURL, a.HTTP = srv.URL, srv.Client()
	a.AppleKeys = keys.verifier().AppleKeys
	return a
}

func TestLoginSocialKeepsAppleGrantWhenWired(t *testing.T) {
	withSocialClients(t)
	keys := newSocialKeys(t)
	users := &contractUsers{}
	h := &SocialLoginHandler{AbstractHandler: AbstractHandler{UserService: users}, Verifier: keys.verifier(), Apple: appleGrants(t, keys)}
	exp := time.Now().Add(time.Hour).Unix()
	appleToken := keys.token(t, jwt.MapClaims{"iss": user.AppleIssuer, "aud": "apple-client", "sub": "a-1", "exp": exp})
	post := func(body string) *httptest.ResponseRecorder {
		users.identity = user.ExternalIdentity{}
		w := httptest.NewRecorder()
		h.LoginSocial(w, httptest.NewRequest(http.MethodPost, "/public/login/social", strings.NewReader(body)))
		return w
	}

	if w := post(`{"provider":"apple","token":"` + appleToken + `"}`); w.Code != http.StatusBadRequest || users.identity.Subject != "" {
		t.Fatalf("apple without code = %d %s", w.Code, w.Body.String())
	}
	if w := post(`{"provider":"apple","token":"` + appleToken + `","code":"used"}`); w.Code != http.StatusUnauthorized || users.identity.Subject != "" {
		t.Fatalf("refused code = %d %s", w.Code, w.Body.String())
	}
	w := post(`{"provider":"apple","token":"` + appleToken + `","code":"good"}`)
	if w.Code != http.StatusOK || users.identity.Grant == "" || strings.Contains(users.identity.Grant, "apple-refresh") {
		t.Fatalf("apple with code = %d %s, grant %q", w.Code, w.Body.String(), users.identity.Grant)
	}
	googleToken := keys.token(t, jwt.MapClaims{"iss": "accounts.google.com", "aud": "google-client", "sub": "g-1", "exp": exp})
	if w := post(`{"provider":"google","token":"` + googleToken + `"}`); w.Code != http.StatusOK || users.identity.Grant != "" {
		t.Fatalf("google needs no code = %d %s", w.Code, w.Body.String())
	}
}

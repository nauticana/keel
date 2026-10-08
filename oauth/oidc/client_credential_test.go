package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func selfSigned(t *testing.T, key *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "keel"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func pemBundle(t *testing.T, key any, cert *x509.Certificate) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	out := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if cert != nil {
		out += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}
	return out
}

func TestPrivateKeyJWTAuthenticatesTheClient(t *testing.T) {
	withConfig(t, "", "")
	idp := newFakeIdP(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := selfSigned(t, key)
	signer, parsedCert, err := ParseClientKey(pemBundle(t, key, cert))
	if err != nil {
		t.Fatalf("ParseClientKey: %v", err)
	}
	c := idp.client(ClientCredential{Method: AuthPrivateKey, Key: signer, Certificate: parsedCert})
	_, p, pend := begin(t, c)
	idp.claims = idp.baseClaims("client-1", p.Nonce)
	if _, err := complete(c, pend, callback("st-1")); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if idp.lastReq.Get("client_secret") != "" || idp.lastReq.Get("client_assertion_type") != clientAssertionType {
		t.Fatalf("token request = %v", idp.lastReq)
	}
	tok, err := jwt.Parse(idp.lastReq.Get("client_assertion"), func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(idp.srv.URL+"/token"), jwt.WithIssuer("client-1"), jwt.WithExpirationRequired())
	if err != nil {
		t.Fatalf("client assertion: %v", err)
	}
	claims := tok.Claims.(jwt.MapClaims)
	exp, _ := claims.GetExpirationTime()
	if sub, _ := claims.GetSubject(); sub != "client-1" || claims["jti"] == "" || time.Until(exp.Time) > clientAssertionTTL {
		t.Fatalf("claims = %v", claims)
	}
	sum := sha256.Sum256(cert.Raw)
	if tok.Header["x5t#S256"] != base64.RawURLEncoding.EncodeToString(sum[:]) || tok.Header["x5t"] == nil {
		t.Fatalf("header = %v", tok.Header)
	}
}

func TestClientSecretBasicEncodesCredentials(t *testing.T) {
	form, header := url.Values{}, map[string][]string{}
	cred := ClientCredential{Method: AuthSecretBasic, Secret: "a:b c"}
	if err := cred.apply(form, header, "id/1", "https://idp/token", time.Now()); err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(header["Authorization"][0], "Basic "))
	if string(raw) != "id%2F1:a%3Ab+c" || form.Get("client_secret") != "" {
		t.Fatalf("basic = %q, form %v", raw, form)
	}
	for _, bad := range []ClientCredential{{Method: AuthSecretPost}, {Method: AuthSecretBasic}, {Method: AuthPrivateKey}, {Method: "none"}} {
		if err := bad.apply(url.Values{}, map[string][]string{}, "id", "https://idp/token", time.Now()); !errors.Is(err, ErrBadConfiguration) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

func TestParseClientKeyRefusals(t *testing.T) {
	short, _ := rsa.GenerateKey(rand.Reader, 1024)
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, bundle := range map[string]string{
		"empty":            "",
		"certificate only": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfSigned(t, key).Raw})),
		"short RSA":        pemBundle(t, short, nil),
		"unsupported curve": func() string {
			der, _ := x509.MarshalECPrivateKey(p224)
			return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
		}(),
		"foreign certificate": pemBundle(t, key, selfSigned(t, other)),
	} {
		if _, _, err := ParseClientKey(bundle); !errors.Is(err, ErrBadConfiguration) {
			t.Errorf("%s: %v", name, err)
		}
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, _, err := ParseClientKey(pemBundle(t, ec, nil)); err != nil {
		t.Fatalf("P-256 key: %v", err)
	}
}

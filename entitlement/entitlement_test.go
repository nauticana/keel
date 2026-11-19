package entitlement

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// Test vectors are generated at test time: no private key is committed.
var (
	keysOnce sync.Once
	keys     [2]*rsa.PrivateKey
)

func testKey(t *testing.T, i int) *rsa.PrivateKey {
	t.Helper()
	keysOnce.Do(func() {
		for n := range keys {
			key, err := rsa.GenerateKey(rand.Reader, MinKeyBits)
			if err != nil {
				panic(err)
			}
			keys[n] = key
		}
	})
	return keys[i]
}

var issued = time.Date(2026, 11, 16, 9, 30, 15, 0, time.UTC)

func sample() Document {
	return Document{
		Format: FormatVersion, LicenseID: "9001", Product: "example", CustomerID: "42", CustomerName: "Example Corp",
		InstallationID: "77", Plan: "MANAGED", Quotas: map[string]int64{"PROJECTS": 1, "SEATS": Unlimited, "TENANTS": 1},
		IssuedAt: issued, ExpiresAt: issued.AddDate(1, 0, 0), GraceDays: 30,
	}
}

func signerAndVerifier(t *testing.T) (*Signer, *Verifier) {
	t.Helper()
	signer, err := NewSigner(testKey(t, 0))
	if err != nil {
		t.Fatal(err)
	}
	public, err := signer.PublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(public)
	if err != nil {
		t.Fatal(err)
	}
	return signer, verifier
}

// signRaw signs arbitrary payload bytes with key 0, as a forger holding the key could, to reach the checks after
// the signature.
func signRaw(t *testing.T, payload []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(payload)
	signature, err := rsa.SignPSS(rand.Reader, testKey(t, 0), crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := KeyID(&testKey(t, 0).PublicKey)
	data, err := File{Payload: base64.RawURLEncoding.EncodeToString(payload), Algorithm: Algorithm, KeyID: id,
		Signature: base64.RawURLEncoding.EncodeToString(signature)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestASignedFileVerifiesToTheSameDocument(t *testing.T) {
	signer, verifier := signerAndVerifier(t)
	doc := sample()
	doc.IssuedAt = issued.Add(400 * time.Millisecond).In(time.FixedZone("PST", -8*3600))
	f, err := signer.Sign(doc)
	if err != nil {
		t.Fatal(err)
	}
	if f.Algorithm != Algorithm || f.KeyID != signer.KeyID() || len(f.KeyID) != 32 {
		t.Fatalf("file = %+v", f)
	}
	data, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifier.Verify(data)
	if err != nil {
		t.Fatal(err)
	}
	want := sample()
	if !got.IssuedAt.Equal(want.IssuedAt) || got.IssuedAt.Location() != time.UTC || !got.ExpiresAt.Equal(want.ExpiresAt) ||
		got.Plan != "MANAGED" || got.Quotas["PROJECTS"] != 1 || got.Quotas["SEATS"] != Unlimited || got.GraceDays != 30 ||
		got.InstallationID != "77" || got.CustomerName != "Example Corp" {
		t.Fatalf("verified = %+v", got)
	}
	// A reformatted file still verifies: the signature covers the payload only.
	var compact File
	if err := json.Unmarshal(data, &compact); err != nil {
		t.Fatal(err)
	}
	again, _ := json.Marshal(compact)
	if _, err := verifier.Verify(again); err != nil {
		t.Fatalf("a compact file: %v", err)
	}
}

func TestTheCanonicalEncodingIsStable(t *testing.T) {
	first, err := sample().Encode()
	if err != nil {
		t.Fatal(err)
	}
	second, _ := sample().Encode()
	if string(first) != string(second) {
		t.Fatal("two encodings of one document differ")
	}
	want := `{"format":1,"license_id":"9001","product":"example","customer_id":"42","customer_name":"Example Corp",` +
		`"installation_id":"77","plan":"MANAGED","quotas":{"PROJECTS":1,"SEATS":-1,"TENANTS":1},` +
		`"issued_at":"2026-11-16T09:30:15Z","expires_at":"2027-11-16T09:30:15Z","grace_days":30}`
	if string(first) != want {
		t.Fatalf("encoding = %s", first)
	}
	empty := sample()
	empty.Quotas = nil
	if data, err := empty.Encode(); err != nil || !strings.Contains(string(data), `"quotas":{}`) {
		t.Fatalf("no quotas: %s, %v", data, err)
	}
}

func TestATamperedFileIsRefused(t *testing.T) {
	signer, verifier := signerAndVerifier(t)
	f, err := signer.Sign(sample())
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(f.Payload)
	changed := strings.Replace(string(payload), `"PROJECTS":1`, `"PROJECTS":9`, 1)
	tampered := f
	tampered.Payload = base64.RawURLEncoding.EncodeToString([]byte(changed))
	data, _ := tampered.Marshal()
	if _, err := verifier.Verify(data); !errors.Is(err, ErrSignature) {
		t.Fatalf("a changed quota: %v", err)
	}
	signature, _ := base64.RawURLEncoding.DecodeString(f.Signature)
	signature[0] ^= 0xFF
	tampered = f
	tampered.Signature = base64.RawURLEncoding.EncodeToString(signature)
	data, _ = tampered.Marshal()
	if _, err := verifier.Verify(data); !errors.Is(err, ErrSignature) {
		t.Fatalf("a changed signature: %v", err)
	}
}

func TestAFileOfAnotherKeyIsRefused(t *testing.T) {
	_, verifier := signerAndVerifier(t)
	other, err := NewSigner(testKey(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	f, _ := other.Sign(sample())
	data, _ := f.Marshal()
	if _, err := verifier.Verify(data); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("another key: %v", err)
	}
	// Claiming the trusted key's id does not help another key's signature.
	trusted, _ := KeyID(&testKey(t, 0).PublicKey)
	f.KeyID = trusted
	data, _ = f.Marshal()
	if _, err := verifier.Verify(data); !errors.Is(err, ErrSignature) {
		t.Fatalf("a borrowed key id: %v", err)
	}
}

func TestAVerifierHoldingSeveralKeysVerifiesEach(t *testing.T) {
	first, _ := NewSigner(testKey(t, 0))
	second, _ := NewSigner(testKey(t, 1))
	firstPEM, _ := first.PublicKeyPEM()
	der := x509.MarshalPKCS1PublicKey(&testKey(t, 1).PublicKey)
	secondPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der})
	verifier, err := NewVerifier(firstPEM, secondPEM)
	if err != nil {
		t.Fatal(err)
	}
	for _, signer := range []*Signer{first, second} {
		f, _ := signer.Sign(sample())
		data, _ := f.Marshal()
		if _, err := verifier.Verify(data); err != nil {
			t.Fatalf("key %s: %v", signer.KeyID(), err)
		}
	}
}

func TestOnlyTheCanonicalDocumentIsAccepted(t *testing.T) {
	_, verifier := signerAndVerifier(t)
	canonical, _ := sample().Encode()
	var fields map[string]any
	if err := json.Unmarshal(canonical, &fields); err != nil {
		t.Fatal(err)
	}
	indented, _ := json.MarshalIndent(sample(), "", " ")
	withField := strings.Replace(string(canonical), `{"format":1,`, `{"format":1,"seats":5,`, 1)
	offset := strings.Replace(string(canonical), `"2026-11-16T09:30:15Z"`, `"2026-11-16T01:30:15-08:00"`, 1)
	for name, payload := range map[string]string{
		"indented":      string(indented),
		"unknown field": withField,
		"offset time":   offset,
		"trailing data": string(canonical) + `{}`,
	} {
		if _, err := verifier.Verify(signRaw(t, []byte(payload))); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	invalid := strings.Replace(string(canonical), `"plan":"MANAGED"`, `"plan":""`, 1)
	if _, err := verifier.Verify(signRaw(t, []byte(invalid))); !errors.Is(err, ErrInvalid) {
		t.Errorf("an empty plan: %v", err)
	}
	future := strings.Replace(string(canonical), `"format":1`, `"format":2`, 1)
	if _, err := verifier.Verify(signRaw(t, []byte(future))); !errors.Is(err, ErrUnsupported) {
		t.Errorf("a later format: %v", err)
	}
}

func TestAMalformedFileIsRefused(t *testing.T) {
	signer, verifier := signerAndVerifier(t)
	f, _ := signer.Sign(sample())
	other := f
	other.Algorithm = "RS256"
	unsupported, _ := other.Marshal()
	if _, err := verifier.Verify(unsupported); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("another algorithm: %v", err)
	}
	padded := f
	padded.Payload += "=="
	paddedData, _ := padded.Marshal()
	data, _ := f.Marshal()
	for name, input := range map[string]string{
		"empty":         "",
		"not json":      "license",
		"extra field":   strings.Replace(string(data), `"payload"`, `"note":"x","payload"`, 1),
		"trailing data": string(data) + "{}",
		"padded":        string(paddedData),
		"no signature":  `{"payload":"e30","algorithm":"PS256","key_id":"` + f.KeyID + `","signature":""}`,
		"too large":     strings.Repeat(" ", MaxFileBytes+1),
	} {
		if _, err := verifier.Verify([]byte(input)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDocumentsAreValidatedBeforeSigning(t *testing.T) {
	signer, _ := signerAndVerifier(t)
	for name, change := range map[string]func(*Document){
		"no customer":        func(d *Document) { d.CustomerID = "" },
		"padded plan":        func(d *Document) { d.Plan = " MANAGED" },
		"quota below -1":     func(d *Document) { d.Quotas["PROJECTS"] = -2 },
		"quota key":          func(d *Document) { d.Quotas["open seats"] = 1 },
		"expiry before":      func(d *Document) { d.ExpiresAt = d.IssuedAt },
		"no issue time":      func(d *Document) { d.IssuedAt = time.Time{} },
		"negative grace":     func(d *Document) { d.GraceDays = -1 },
		"grace too long":     func(d *Document) { d.GraceDays = MaxGraceDays + 1 },
		"long customer name": func(d *Document) { d.CustomerName = strings.Repeat("a", maxText+1) },
	} {
		doc := sample()
		change(&doc)
		if _, err := signer.Sign(doc); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	doc := sample()
	doc.Format = 0
	if _, err := signer.Sign(doc); !errors.Is(err, ErrUnsupported) {
		t.Errorf("no format: %v", err)
	}
}

func TestStateFollowsExpiryAndGrace(t *testing.T) {
	doc := sample()
	expiry, graceEnd := doc.ExpiresAt, doc.ExpiresAt.AddDate(0, 0, 30)
	for at, want := range map[time.Time]State{
		issued.Add(-48 * time.Hour):  StateActive,
		expiry.Add(-time.Second):     StateActive,
		expiry:                       StateGrace,
		graceEnd.Add(-time.Second):   StateGrace,
		graceEnd:                     StateExpired,
		graceEnd.AddDate(1, 0, 0):    StateExpired,
		issued.Add(30 * time.Minute): StateActive,
	} {
		if got := doc.StateAt(at); got != want {
			t.Errorf("at %s: %s, want %s", at, got, want)
		}
	}
	doc.GraceDays = 0
	if doc.StateAt(expiry) != StateExpired {
		t.Error("no grace: expired at expiry")
	}
}

func TestRenewalIsDueWithinItsWindow(t *testing.T) {
	doc, window := sample(), 30*24*time.Hour
	if doc.RenewalDue(doc.ExpiresAt.Add(-window-time.Second), window) {
		t.Error("due before the window")
	}
	if !doc.RenewalDue(doc.ExpiresAt.Add(-window), window) || !doc.RenewalDue(doc.ExpiresAt.Add(time.Hour), window) {
		t.Error("not due in the window or after expiry")
	}
}

func TestQuotasAdmitWithinTheirLimit(t *testing.T) {
	doc := sample()
	for _, c := range []struct {
		key   string
		count int64
		want  bool
	}{
		{"PROJECTS", 0, true}, {"PROJECTS", 1, true}, {"PROJECTS", 2, false},
		{"SEATS", 1 << 40, true}, {"UNNAMED", 0, false}, {"TENANTS", -1, false},
	} {
		if got := doc.Admits(c.key, c.count); got != c.want {
			t.Errorf("Admits(%s, %d) = %v", c.key, c.count, got)
		}
	}
}

func TestKeysAreReadFromPEMAndWeakKeysRefused(t *testing.T) {
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testKey(t, 0))})
	der, err := x509.MarshalPKCS8PrivateKey(testKey(t, 0))
	if err != nil {
		t.Fatal(err)
	}
	pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	a, err := NewSignerFromPEM(pkcs1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSignerFromPEM(pkcs8)
	if err != nil || a.KeyID() != b.KeyID() {
		t.Fatalf("PKCS#8: %v, ids %s and %s", err, a.KeyID(), b.KeyID())
	}
	for name, input := range map[string][]byte{
		"empty":       nil,
		"certificate": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}),
		"garbage":     pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
	} {
		if _, err := NewSignerFromPEM(input); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSigner(weak); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("a 1024-bit signer: %v", err)
	}
	weakDER, _ := x509.MarshalPKIXPublicKey(&weak.PublicKey)
	if _, err := NewVerifier(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: weakDER})); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("a 1024-bit verifier: %v", err)
	}
	if _, err := NewVerifier(); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("no key: %v", err)
	}
	if _, err := NewSigner(nil); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("a nil key: %v", err)
	}
}

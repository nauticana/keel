package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
)

func selfSigned(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "SAP system"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func sign(t *testing.T, data []byte, cert *x509.Certificate, key *rsa.PrivateKey) []byte {
	t.Helper()
	sd, err := pkcs7.NewSignedData(data)
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	sd.Detach()
	sig, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestVerifyPKCS7Detached(t *testing.T) {
	cert, key := selfSigned(t)
	data := []byte("contRep=K1&accessMode=r&authId=CN=SAP&expiration=20990101000000")
	sig := sign(t, data, cert, key)
	allowed := []x509.SignatureAlgorithm{x509.SHA256WithRSA}

	if err := VerifyPKCS7Detached(sig, data, cert, allowed); err != nil {
		t.Fatalf("valid signature refused: %v", err)
	}
	if err := VerifyPKCS7Detached(sig, []byte("tampered"), cert, allowed); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("tampered data: %v", err)
	}
	if err := VerifyPKCS7Detached(sig, data, nil, allowed); !errors.Is(err, ErrCertificateRequired) {
		t.Errorf("nil certificate: %v", err)
	}
	if err := VerifyPKCS7Detached(sig, data, cert, []x509.SignatureAlgorithm{x509.SHA1WithRSA}); !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Errorf("algorithm outside the allow-list: %v", err)
	}
	other, _ := selfSigned(t)
	if err := VerifyPKCS7Detached(sig, data, other, allowed); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("the embedded certificate must never be trusted over the stored one: %v", err)
	}
}

func TestParseCertificate(t *testing.T) {
	cert, _ := selfSigned(t)
	if got, err := ParseCertificate(cert.Raw); err != nil || !got.Equal(cert) {
		t.Fatalf("DER: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if got, err := ParseCertificate(pemBytes); err != nil || !got.Equal(cert) {
		t.Fatalf("PEM: %v", err)
	}
	if _, err := ParseCertificate([]byte("junk")); !errors.Is(err, ErrCertificateMalformed) {
		t.Fatalf("junk: %v", err)
	}
}

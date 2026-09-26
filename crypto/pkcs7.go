package crypto

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"

	"github.com/smallstep/pkcs7"
)

var (
	ErrCertificateRequired  = errors.New("crypto: a signer certificate is required")
	ErrAlgorithmNotAllowed  = errors.New("crypto: signature algorithm not allowed")
	ErrSignatureInvalid     = errors.New("crypto: signature verification failed")
	ErrCertificateMalformed = errors.New("crypto: certificate could not be parsed")
)

// ParseCertificate parses one X.509 certificate given as DER or PEM.
func ParseCertificate(derOrPEM []byte) (*x509.Certificate, error) {
	der := derOrPEM
	if block, _ := pem.Decode(derOrPEM); block != nil {
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertificateMalformed, err)
	}
	return cert, nil
}

// VerifyPKCS7Detached checks a detached PKCS#7 "signed data" signature over
// data against cert. Certificates embedded in the signature are never trusted:
// every signer must be cert, and its algorithm must be in allowed.
func VerifyPKCS7Detached(signature, data []byte, cert *x509.Certificate, allowed []x509.SignatureAlgorithm) error {
	if cert == nil {
		return ErrCertificateRequired
	}
	p7, err := pkcs7.Parse(signature)
	if err != nil {
		return fmt.Errorf("%w: parse: %v", ErrSignatureInvalid, err)
	}
	if len(p7.Signers) == 0 {
		return fmt.Errorf("%w: no signer", ErrSignatureInvalid)
	}
	for _, signer := range p7.Signers {
		algo := signatureAlgorithm(signer.DigestEncryptionAlgorithm.Algorithm, signer.DigestAlgorithm.Algorithm)
		if !slices.Contains(allowed, algo) {
			return fmt.Errorf("%w: %s", ErrAlgorithmNotAllowed, algo)
		}
	}
	p7.Content = data
	p7.Certificates = []*x509.Certificate{cert}
	if err := p7.Verify(); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	return nil
}

func signatureAlgorithm(encryption, digest asn1.ObjectIdentifier) x509.SignatureAlgorithm {
	byDigest := func(sha1, sha256, sha384, sha512 x509.SignatureAlgorithm) x509.SignatureAlgorithm {
		switch {
		case digest.Equal(pkcs7.OIDDigestAlgorithmSHA1):
			return sha1
		case digest.Equal(pkcs7.OIDDigestAlgorithmSHA256):
			return sha256
		case digest.Equal(pkcs7.OIDDigestAlgorithmSHA384):
			return sha384
		case digest.Equal(pkcs7.OIDDigestAlgorithmSHA512):
			return sha512
		}
		return x509.UnknownSignatureAlgorithm
	}
	switch {
	case encryption.Equal(pkcs7.OIDEncryptionAlgorithmRSA):
		return byDigest(x509.SHA1WithRSA, x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA)
	case encryption.Equal(pkcs7.OIDEncryptionAlgorithmRSASHA1):
		return x509.SHA1WithRSA
	case encryption.Equal(pkcs7.OIDEncryptionAlgorithmRSASHA256):
		return x509.SHA256WithRSA
	case encryption.Equal(pkcs7.OIDEncryptionAlgorithmRSASHA384):
		return x509.SHA384WithRSA
	case encryption.Equal(pkcs7.OIDEncryptionAlgorithmRSASHA512):
		return x509.SHA512WithRSA
	case encryption.Equal(pkcs7.OIDEncryptionAlgorithmRSAMD5):
		return x509.MD5WithRSA
	case encryption.Equal(pkcs7.OIDEncryptionAlgorithmECDSAP256), encryption.Equal(pkcs7.OIDEncryptionAlgorithmECDSAP384), encryption.Equal(pkcs7.OIDEncryptionAlgorithmECDSAP521):
		return byDigest(x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512)
	case encryption.Equal(pkcs7.OIDDigestAlgorithmECDSASHA1):
		return x509.ECDSAWithSHA1
	case encryption.Equal(pkcs7.OIDDigestAlgorithmECDSASHA256):
		return x509.ECDSAWithSHA256
	case encryption.Equal(pkcs7.OIDDigestAlgorithmECDSASHA384):
		return x509.ECDSAWithSHA384
	case encryption.Equal(pkcs7.OIDDigestAlgorithmECDSASHA512):
		return x509.ECDSAWithSHA512
	case encryption.Equal(pkcs7.OIDDigestAlgorithmDSA), encryption.Equal(pkcs7.OIDDigestAlgorithmDSASHA1):
		return x509.DSAWithSHA1
	}
	return x509.UnknownSignatureAlgorithm
}

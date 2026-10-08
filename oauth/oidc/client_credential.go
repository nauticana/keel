package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Client authentication methods at the token endpoint, as the discovery
// document names them.
const (
	AuthSecretPost  = "client_secret_post"
	AuthSecretBasic = "client_secret_basic"
	AuthPrivateKey  = "private_key_jwt"
)

const (
	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	clientAssertionTTL  = time.Minute
)

// ClientCredential authenticates the relying party at the token endpoint:
// a secret for the client_secret methods, or a private key, optionally with
// its certificate, for private_key_jwt.
type ClientCredential struct {
	Method      string
	Secret      string
	Key         crypto.Signer
	Certificate *x509.Certificate
}

// ParseClientKey reads a PEM bundle holding one private key (PKCS #8, PKCS #1
// or SEC 1) and optionally the certificate issued for it.
func ParseClientKey(bundle string) (crypto.Signer, *x509.Certificate, error) {
	var key crypto.Signer
	var cert *x509.Certificate
	rest := []byte(bundle)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: certificate: %v", ErrBadConfiguration, err)
			}
			cert = c
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			k, err := parsePrivateKey(block)
			if err != nil {
				return nil, nil, err
			}
			key = k
		}
	}
	if key == nil {
		return nil, nil, fmt.Errorf("%w: no private key in the credential", ErrBadConfiguration)
	}
	if cert != nil && !publicKeysEqual(cert.PublicKey, key.Public()) {
		return nil, nil, fmt.Errorf("%w: the certificate is not for the private key", ErrBadConfiguration)
	}
	return key, cert, nil
}

func parsePrivateKey(block *pem.Block) (crypto.Signer, error) {
	var parsed any
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: private key: %v", ErrBadConfiguration, err)
	}
	switch k := parsed.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < 2048 {
			return nil, fmt.Errorf("%w: RSA key is shorter than 2048 bits", ErrBadConfiguration)
		}
		return k, nil
	case *ecdsa.PrivateKey:
		if _, err := signingMethod(k); err != nil {
			return nil, err
		}
		return k, nil
	}
	return nil, fmt.Errorf("%w: unsupported private key type %T", ErrBadConfiguration, parsed)
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.(equaler)
	return ok && e.Equal(b)
}

func signingMethod(key crypto.Signer) (jwt.SigningMethod, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return jwt.SigningMethodRS256, nil
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().Name {
		case "P-256":
			return jwt.SigningMethodES256, nil
		case "P-384":
			return jwt.SigningMethodES384, nil
		}
	}
	return nil, fmt.Errorf("%w: unsupported signing key", ErrBadConfiguration)
}

// apply adds the credential to a token request form and its headers.
func (c ClientCredential) apply(form url.Values, header http.Header, clientID, tokenEndpoint string, now time.Time) error {
	switch c.Method {
	case AuthSecretPost:
		if c.Secret == "" {
			return fmt.Errorf("%w: empty client secret", ErrBadConfiguration)
		}
		form.Set("client_id", clientID)
		form.Set("client_secret", c.Secret)
	case AuthSecretBasic:
		if c.Secret == "" {
			return fmt.Errorf("%w: empty client secret", ErrBadConfiguration)
		}
		basic := url.QueryEscape(clientID) + ":" + url.QueryEscape(c.Secret)
		header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(basic)))
	case AuthPrivateKey:
		assertion, err := c.assertion(clientID, tokenEndpoint, now)
		if err != nil {
			return err
		}
		form.Set("client_id", clientID)
		form.Set("client_assertion_type", clientAssertionType)
		form.Set("client_assertion", assertion)
	default:
		return fmt.Errorf("%w: client authentication %q", ErrBadConfiguration, c.Method)
	}
	return nil
}

// assertion is the RFC 7523 client assertion. The certificate thumbprints
// let an issuer that registers certificates, such as Entra ID, pick the key.
func (c ClientCredential) assertion(clientID, tokenEndpoint string, now time.Time) (string, error) {
	if c.Key == nil {
		return "", fmt.Errorf("%w: private_key_jwt without a key", ErrBadConfiguration)
	}
	method, err := signingMethod(c.Key)
	if err != nil {
		return "", err
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	tok := jwt.NewWithClaims(method, jwt.RegisteredClaims{
		Issuer:    clientID,
		Subject:   clientID,
		Audience:  jwt.ClaimStrings{tokenEndpoint},
		ID:        hex.EncodeToString(jti),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(clientAssertionTTL)),
	})
	if c.Certificate != nil {
		s256 := sha256.Sum256(c.Certificate.Raw)
		s1 := sha1.Sum(c.Certificate.Raw)
		tok.Header["x5t#S256"] = base64.RawURLEncoding.EncodeToString(s256[:])
		tok.Header["x5t"] = base64.RawURLEncoding.EncodeToString(s1[:])
	}
	return tok.SignedString(c.Key)
}

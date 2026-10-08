package domain

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
)

// httpFileMaxBytes is the format limit of a verification file, which holds
// one token; anything longer is not a file keel issued.
const httpFileMaxBytes = 1024

// HTTPFileVerifier proves control of content on the host (HF): FileURL serves
// the issued token over HTTPS. Redirects may only move between the domain and
// its www host, and private or loopback addresses are never dialed.
type HTTPFileVerifier struct {
	Client *http.Client // nil uses a client that dials public addresses only
}

var _ DomainVerifier = (*HTTPFileVerifier)(nil)

func (v *HTTPFileVerifier) Method() string { return MethodHTTPFile }

func (v *HTTPFileVerifier) Verify(ctx context.Context, proof DomainProof) (string, error) {
	if proof.Domain == "" || proof.TokenHash == "" {
		return "", ErrDomainNotProven
	}
	client := v.Client
	if client == nil {
		client = publicHTTPClient()
	}
	guarded := *client
	guarded.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		host := req.URL.Hostname()
		if len(via) >= config.Config().OutboundMaxRedirects || req.URL.Scheme != "https" || (host != proof.Domain && host != "www."+proof.Domain) {
			return fmt.Errorf("%w: redirect to %s", ErrDomainNotProven, req.URL.Redacted())
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, config.Config().DefaultOutboundTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, FileURL(proof.Domain), nil)
	if err != nil {
		return "", err
	}
	resp, err := guarded.Do(req)
	if err != nil {
		if errors.Is(err, ErrDomainNotProven) {
			return "", err
		}
		return "", fmt.Errorf("domain verification: fetch file of %s: %w", proof.Domain, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout {
		return "", fmt.Errorf("domain verification: file of %s: http status %d", proof.Domain, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: file of %s: http status %d", ErrDomainNotProven, proof.Domain, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, httpFileMaxBytes+1))
	if err != nil {
		return "", fmt.Errorf("domain verification: read file of %s: %w", proof.Domain, err)
	}
	if len(body) > httpFileMaxBytes || !tokenMatches(string(body), proof.TokenHash) {
		return "", fmt.Errorf("%w: %s serves a different file", ErrDomainNotProven, proof.Domain)
	}
	return "", nil
}

func publicHTTPClient() *http.Client {
	timeout := config.Config().DefaultOutboundTimeout
	dialer := &net.Dialer{Timeout: timeout, Control: dialPublicOnly}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = dialer.DialContext
	return &http.Client{Transport: transport, Timeout: timeout}
}

// dialPublicOnly makes a host that resolves to an internal address a negative verdict.
func dialPublicOnly(network, address string, c syscall.RawConn) error {
	if err := common.DialPublicOnly(network, address, c); err != nil {
		return fmt.Errorf("%w: %w", ErrDomainNotProven, err)
	}
	return nil
}

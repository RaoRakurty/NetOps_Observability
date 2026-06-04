package tlsconfig

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"
)

// httpclient.go — hardened TLS for OUTBOUND HTTP clients (the API dialing its
// internal backends: OpenSearch / ClickHouse / VictoriaMetrics / correlation).
//
// Distinct from ClientConfig (a single-target dialer that PINS ServerName):
// an *http.Transport may reach several hosts, so we leave ServerName empty and
// let net/http set + verify it per request from the URL host. Everything else is
// still locked down — explicit roots (no system pool), no InsecureSkipVerify,
// TLS-1.3-first policy, optional client cert (mTLS) + peer allowlist.

// HTTPClientConfig builds a hardened *tls.Config for an http.Transport. RootCAs
// is required (explicit trust, no system fallback for internal services);
// ServerName is intentionally NOT required — net/http fills it per request and
// performs the hostname check, so verification can't be skipped.
func HTTPClientConfig(o ClientOptions) (*tls.Config, error) {
	if o.RootCAs == nil {
		return nil, errors.New("tlsconfig: HTTPClientConfig requires an explicit RootCAs bundle")
	}
	c := baseConfig()
	c.RootCAs = o.RootCAs.Pool()
	if o.ServerName != "" {
		c.ServerName = o.ServerName // optional pin; usually left to net/http
	}
	if o.Reloader != nil {
		c.GetClientCertificate = o.Reloader.GetClientCertificate
	}
	if !o.Peer.empty() {
		peer := o.Peer
		c.VerifyConnection = peer.verify
	}
	return c, nil
}

// HTTPTransport returns an *http.Transport with the hardened TLS config and
// sane connection-pool + timeout defaults (resource-exhaustion protection). Plain
// http:// requests through it are unaffected; https:// requests get the policy.
func HTTPTransport(o ClientOptions) (*http.Transport, error) {
	cfg, err := HTTPClientConfig(o)
	if err != nil {
		return nil, err
	}
	return &http.Transport{
		TLSClientConfig:       cfg,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}, nil
}

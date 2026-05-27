package transport

import (
	"context"
	"net/http"
)

// HTTPDialer wraps net/http with shared timeouts for REST integrations
// (Netbox, webhooks, etc.). It satisfies the Dialer contract trivially —
// HTTP calls are stateless so Dial just hands back a session that owns a
// configured client.
type HTTPDialer struct{}

func (HTTPDialer) Name() string { return "http" }

func (HTTPDialer) Dial(_ context.Context, _ string) (Session, error) {
	return &httpSession{client: &http.Client{Timeout: DefaultTimeout}}, nil
}

type httpSession struct{ client *http.Client }

func (s *httpSession) Client() *http.Client { return s.client }
func (s *httpSession) Close() error         { return nil }

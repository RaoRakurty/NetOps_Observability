// Package keycloak is a stdlib-only admin REST client for the bundled Keycloak
// broker (GUI-configurable SSO). It automates the console work the Okta guide
// walks an operator through by hand — realm, confidential client, the
// realm-roles-in-ID-token fix, realm roles, identity providers and their
// attribute/role mappers — as idempotent ensure-style reconcile operations
// (GET, then create-or-update), so a desired-state save from the admin UI can
// be applied end to end with zero console work.
//
// Zero-trust posture (CLAUDE.md §3/§9): every call carries a context timeout,
// transport errors and 5xx are retried with bounded backoff + jitter, 4xx are
// never retried (one 401 re-auth excepted), every path segment derived from
// input is URL-escaped, and every response body read is size-capped.
package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config is the admin connection, env-derived in the wiring layer
// (KEYCLOAK_INTERNAL_URL / KEYCLOAK_ADMIN / KEYCLOAK_ADMIN_PASSWORD /
// KEYCLOAK_REALM) and injected here so the package stays env-free.
type Config struct {
	BaseURL       string        // e.g. http://keycloak:8080/auth (no trailing slash needed)
	AdminUser     string        // master-realm admin (admin-cli password grant)
	AdminPassword string        //
	Realm         string        // the Correlix realm this deployment reconciles into
	Timeout       time.Duration // per-call budget; 0 = 10s
	Retries       int           // extra attempts on 5xx/transport errors; 0 = 2
}

// Client is the token-caching admin client. Safe for concurrent use.
type Client struct {
	cfg   Config
	httpc *http.Client

	// test seams — never nil after New().
	now   func() time.Time
	sleep func(time.Duration)

	mu       sync.Mutex
	token    string
	tokenExp time.Time // refresh 30s before actual expiry
}

// New builds a client. The per-attempt HTTP timeout mirrors the call budget so
// a hung TCP connection cannot outlive the context.
func New(cfg Config) *Client {
	cfg.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Retries <= 0 {
		cfg.Retries = 2
	}
	return &Client{
		cfg:   cfg,
		httpc: &http.Client{Timeout: cfg.Timeout},
		now:   time.Now,
		sleep: time.Sleep,
	}
}

// Realm returns the configured Correlix realm name.
func (c *Client) Realm() string { return c.cfg.Realm }

// APIError is a non-2xx admin-API answer, wrapped with the operation name so
// the caller's error chain reads "ensure client: keycloak PUT /admin/...: 409".
type APIError struct {
	Op     string
	Status int
	Body   string
}

func (e *APIError) Error() string {
	msg := strings.TrimSpace(e.Body)
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return fmt.Sprintf("keycloak %s: status %d: %s", e.Op, e.Status, msg)
}

// IsNotFound reports whether err is an admin-API 404 (absent resource — the
// "create" branch of every ensure operation).
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

const maxRespBytes = 1 << 20 // admin-API answers are small; 1 MiB is generous

// readBody drains a response with the F-27 size cap; hitting the cap is an
// error, not a short read.
func readBody(resp *http.Response) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxRespBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxRespBytes)
	}
	return b, nil
}

// backoff returns the bounded, jittered delay before retry attempt n (0-based):
// 200ms·2ⁿ plus up to 200ms of jitter.
func backoff(n int) time.Duration {
	d := 200 * time.Millisecond << n
	// #nosec G404 -- retry jitter only; not security-sensitive randomness.
	return d + time.Duration(rand.Int63n(int64(200*time.Millisecond)))
}

// retryable reports whether an attempt outcome warrants another try: transport
// errors and 5xx yes; every 4xx no (the caller handles the single 401 re-auth).
func retryable(resp *http.Response, err error) bool {
	if err != nil {
		return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
	}
	return resp.StatusCode >= 500
}

// send runs one request-building function with bounded retry + backoff.
// The builder is invoked per attempt because request bodies are single-use.
func (c *Client) send(ctx context.Context, op string, build func() (*http.Request, error)) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt <= c.cfg.Retries; attempt++ {
		if attempt > 0 {
			c.sleep(backoff(attempt - 1))
		}
		req, err := build()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		resp, err := c.httpc.Do(req.WithContext(ctx))
		if !retryable(resp, err) {
			if err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			return resp, nil
		}
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := readBody(resp) // best-effort: diagnostic snippet; a read error just leaves it empty
		_ = resp.Body.Close()     // body already drained by readBody; nothing to act on
		lastErr = &APIError{Op: op, Status: resp.StatusCode, Body: string(body)}
	}
	return nil, fmt.Errorf("%s: giving up after %d attempts: %w", op, c.cfg.Retries+1, lastErr)
}

// authenticate fetches (or reuses) the master-realm admin token: POST
// {base}/realms/master/protocol/openid-connect/token, grant_type=password,
// client_id=admin-cli. Cached until 30s before expiry.
func (c *Client) authenticate(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.token != "" && c.now().Before(c.tokenExp) {
		return c.token, nil
	}
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {c.cfg.AdminUser},
		"password":   {c.cfg.AdminPassword},
	}
	endpoint := c.cfg.BaseURL + "/realms/master/protocol/openid-connect/token"
	resp, err := c.send(ctx, "admin token", func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := readBody(resp)
	if err != nil {
		return "", fmt.Errorf("admin token: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", &APIError{Op: "admin token", Status: resp.StatusCode, Body: string(body)}
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("admin token: decode: %w", err)
	}
	if tok.AccessToken == "" {
		return "", errors.New("admin token: empty access_token")
	}
	c.token = tok.AccessToken
	c.tokenExp = c.now().Add(time.Duration(tok.ExpiresIn)*time.Second - 30*time.Second)
	return c.token, nil
}

// call performs one authenticated admin-API request. in (JSON-marshalled) and
// out (JSON-unmarshalled) may be nil. A cached-token 401 triggers exactly one
// re-auth + replay; any surviving non-2xx returns an *APIError (nothing is
// decoded into out). The returned status lets ensure-style callers branch on
// 200 vs 201 without error gymnastics.
func (c *Client) call(ctx context.Context, op, method, path string, in, out any) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	var payload []byte
	if in != nil {
		var err error
		if payload, err = json.Marshal(in); err != nil {
			return 0, fmt.Errorf("%s: encode request: %w", op, err)
		}
	}
	return c.callRaw(ctx, op, method, path, "application/json", payload, out)
}

// callRaw is call() with a caller-supplied content type + body (the multipart
// import-config upload path).
func (c *Client) callRaw(ctx context.Context, op, method, path, contentType string, payload []byte, out any) (int, error) {
	for auth := 0; ; auth++ {
		token, err := c.authenticate(ctx, auth > 0)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", op, err)
		}
		resp, err := c.send(ctx, op, func() (*http.Request, error) {
			var body io.Reader
			if payload != nil {
				body = bytes.NewReader(payload)
			}
			req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+path, body)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer "+token)
			if payload != nil {
				req.Header.Set("Content-Type", contentType)
			}
			return req, nil
		})
		if err != nil {
			return 0, err
		}
		respBody, readErr := readBody(resp)
		_ = resp.Body.Close() // body already drained by readBody; nothing to act on
		if resp.StatusCode == http.StatusUnauthorized && auth == 0 {
			continue // stale cached token — re-auth once and replay
		}
		if readErr != nil {
			return resp.StatusCode, fmt.Errorf("%s: %w", op, readErr)
		}
		if resp.StatusCode >= 400 {
			return resp.StatusCode, &APIError{Op: op, Status: resp.StatusCode, Body: string(respBody)}
		}
		if out != nil && len(bytes.TrimSpace(respBody)) > 0 {
			if err := json.Unmarshal(respBody, out); err != nil {
				return resp.StatusCode, fmt.Errorf("%s: decode response: %w", op, err)
			}
		}
		return resp.StatusCode, nil
	}
}

// Package cli is the host-side half of the pipeline debugger — everything
// `correlix-debug` does that the API cannot do from inside a container:
// authenticate as the platform admin, drive the debug routes, read container
// logs and the Vector event tap, assemble the session directory and package a
// bundle.
//
// It is a package (not code in cmd/) because CLAUDE.md §2 forbids business
// logic in an entrypoint: cmd/correlix-debug is a `func main` that calls
// cli.Run and nothing else, and every function below is unit-testable without
// building a binary.
package cli

// client.go — the authenticated API client.
//
// CREDENTIAL HANDLING (§8). The token is held in memory, sent only in an
// Authorization header, and NEVER written to a session file, a log line or the
// terminal: manifest.json records WHO ran the session (the username), not what
// it authenticated with. When credentials are read from
// deployment/docker/.env, only the two keys needed are taken and neither is
// echoed.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netops/backend/internal/pipedebug"
)

// maxAPIResponse bounds one API answer. The peer picks the size; an unbounded
// read is an OOM in the CLI (and the CLI runs on the production host).
const maxAPIResponse = 16 << 20

// Client talks to the Correlix API as the platform admin.
type Client struct {
	base  string
	token string
	http  *http.Client
	// user is the authenticated username, recorded in the manifest.
	user string
}

// Credentials is how the CLI was told to authenticate.
type Credentials struct {
	Base     string
	Token    string
	User     string
	Password string
}

// LoadEnvCredentials reads the deployment .env for the API base and the admin
// account, returning only what it found. An unreadable file is NOT an error —
// the operator may be passing --token instead — but a MALFORMED one is not
// silently treated as empty either: parse failures are reported by the caller
// when the resulting credentials turn out to be unusable.
func LoadEnvCredentials(envPath string) Credentials {
	var c Credentials
	// #nosec G304 -- envPath is an operator-supplied path to their own
	// deployment's .env; the CLI runs as that operator on their own host.
	raw, err := os.ReadFile(envPath)
	if err != nil {
		return c
	}
	port := ""
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "ADMIN_USERNAME":
			c.User = v
		case "ADMIN_INITIAL_PASSWORD":
			c.Password = v
		case "BASE_PORT":
			port = strings.TrimSpace(v)
		}
	}
	if port != "" {
		c.Base = "http://localhost:" + port
	}
	return c
}

// DefaultEnvPath is the deployment .env relative to a repo root.
func DefaultEnvPath(root string) string {
	return filepath.Join(root, "deployment", "docker", ".env")
}

// NewClient authenticates and returns a ready client. A supplied token is used
// as-is (no login round trip); otherwise username/password are exchanged for
// one.
func NewClient(ctx context.Context, c Credentials, timeout time.Duration) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(c.Base), "/")
	if base == "" {
		return nil, errors.New("no API base URL: pass --api or set BASE_PORT in deployment/docker/.env")
	}
	if _, err := url.Parse(base); err != nil {
		return nil, fmt.Errorf("bad API base URL: %w", err)
	}
	cl := &Client{base: base, http: &http.Client{Timeout: timeout}, user: c.User}
	if strings.TrimSpace(c.Token) != "" {
		cl.token = strings.TrimSpace(c.Token)
		if cl.user == "" {
			cl.user = "(token)"
		}
		return cl, nil
	}
	if c.User == "" || c.Password == "" {
		return nil, errors.New("no credentials: pass --token, or run where deployment/docker/.env is readable")
	}
	body, err := json.Marshal(map[string]string{"username": c.User, "password": c.Password})
	if err != nil {
		return nil, err
	}
	raw, status, err := cl.do(ctx, http.MethodPost, "/api/auth/login", body, false)
	if err != nil {
		return nil, err
	}
	if status/100 != 2 {
		// The response body of a FAILED login is not echoed: it is the one place
		// a credential could be reflected back into a terminal or a log.
		return nil, fmt.Errorf("login failed (HTTP %d)", status)
	}
	var out struct {
		Token string `json:"token"`
	}
	// Split, not conflated (§10): an undecodable body means the endpoint is not
	// the API we think it is; a decodable body with no token means the API
	// answered but the login did not mint one. They lead to different fixes.
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("login response was not decodable JSON (is %s the Correlix API?): %w", cl.base, err)
	}
	if out.Token == "" {
		return nil, errors.New("login succeeded but the response carried no token")
	}
	cl.token = out.Token
	return cl, nil
}

// User is the authenticated username (for the manifest). Never the token.
func (c *Client) User() string { return c.user }

// Base is the API base URL (for the manifest).
func (c *Client) Base() string { return c.base }

func (c *Client) do(ctx context.Context, method, path string, body []byte, auth bool) ([]byte, int, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }() // body is drained below
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponse))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if int64(len(raw)) >= maxAPIResponse {
		return nil, resp.StatusCode, fmt.Errorf("API response exceeded %d bytes — refusing a truncated body", maxAPIResponse)
	}
	return raw, resp.StatusCode, nil
}

// apiError renders a non-2xx answer without echoing a body that could contain
// anything the caller sent.
func apiError(path string, status int, raw []byte) error {
	msg := strings.TrimSpace(string(raw))
	if len(msg) > 400 {
		msg = msg[:400] + "…"
	}
	return fmt.Errorf("%s answered HTTP %d: %s", path, status, pipedebug.RedactString(msg))
}

// TraceReceipt is POST /api/debug/trace's answer.
type TraceReceipt struct {
	Marker    string    `json:"marker"`
	Kind      string    `json:"kind"`
	Device    string    `json:"device"`
	Tenant    string    `json:"tenant"`
	Injected  bool      `json:"injected"`
	InjectErr string    `json:"inject_error"`
	TTLSec    int       `json:"ttl_seconds"`
	Started   time.Time `json:"started"`
	Synthetic bool      `json:"synthetic"`
	StatusURL string    `json:"status_url"`
	Passive   bool      `json:"passive"`
	Since     string    `json:"since"`
	Path      string    `json:"path"`
}

// TraceRequest is one `trace` invocation as it goes on the wire.
type TraceRequest struct {
	Kind    pipedebug.Kind
	Device  string
	Tenant  string
	TTL     time.Duration
	Passive bool
	Since   time.Duration
	Path    string
}

// StartTrace starts a follow. With Passive set it injects NOTHING — the flag
// travels to the api, which owns the exclusive branch; the CLI never decides to
// inject on the server's behalf.
func (c *Client) StartTrace(ctx context.Context, req TraceRequest) (TraceReceipt, error) {
	body, err := json.Marshal(map[string]any{
		"kind": string(req.Kind), "device": req.Device, "tenant": req.Tenant,
		"ttl_seconds":   int(req.TTL.Seconds()),
		"passive":       req.Passive,
		"since_seconds": int(req.Since.Seconds()),
		"path":          req.Path,
	})
	if err != nil {
		return TraceReceipt{}, err
	}
	raw, status, err := c.do(ctx, http.MethodPost, "/api/debug/trace", body, true)
	if err != nil {
		return TraceReceipt{}, err
	}
	if status/100 != 2 {
		return TraceReceipt{}, apiError("/api/debug/trace", status, raw)
	}
	var out TraceReceipt
	if err := json.Unmarshal(raw, &out); err != nil {
		return TraceReceipt{}, fmt.Errorf("trace receipt was not decodable: %w", err)
	}
	return out, nil
}

// TraceStatus polls the server-side follow.
func (c *Client) TraceStatus(ctx context.Context, marker string) (pipedebug.TraceStatus, error) {
	if !pipedebug.ValidMarker(marker) {
		return pipedebug.TraceStatus{}, errors.New("invalid marker")
	}
	raw, status, err := c.do(ctx, http.MethodGet, "/api/debug/trace/"+marker, nil, true)
	if err != nil {
		return pipedebug.TraceStatus{}, err
	}
	if status/100 != 2 {
		return pipedebug.TraceStatus{}, apiError("/api/debug/trace/"+marker, status, raw)
	}
	var out pipedebug.TraceStatus
	if err := json.Unmarshal(raw, &out); err != nil {
		return pipedebug.TraceStatus{}, fmt.Errorf("trace status was not decodable: %w", err)
	}
	return out, nil
}

// Stage fetches one server-side or hybrid stage's evidence on demand.
//
// `device` and `path` are only meaningful for the stages that describe a
// PASSIVE follow (the UI-query contract for gNMI renders the device's own
// selector); they are omitted rather than sent empty so the api's closed
// grammars never see a blank value to reason about.
func (c *Client) Stage(ctx context.Context, stage pipedebug.Stage, kind pipedebug.Kind, marker, tenant, device, path string) (pipedebug.Entry, error) {
	q := url.Values{}
	q.Set("marker", marker)
	q.Set("kind", string(kind))
	if tenant != "" {
		q.Set("tenant", tenant)
	}
	if device != "" {
		q.Set("device", device)
	}
	if path != "" {
		q.Set("path", path)
	}
	route := "/api/debug/stage/" + string(stage) + "?" + q.Encode()
	raw, status, err := c.do(ctx, http.MethodGet, route, nil, true)
	if err != nil {
		return pipedebug.Entry{}, err
	}
	if status/100 != 2 {
		return pipedebug.Entry{}, apiError(route, status, raw)
	}
	var out pipedebug.Entry
	if err := json.Unmarshal(raw, &out); err != nil {
		return pipedebug.Entry{}, fmt.Errorf("stage response was not decodable: %w", err)
	}
	return out, nil
}

// SetLogLevel raises or reverts one module's runtime level.
func (c *Client) SetLogLevel(ctx context.Context, module pipedebug.Module, level pipedebug.Level, window time.Duration) (pipedebug.LevelChange, error) {
	body, err := json.Marshal(map[string]any{
		"module": string(module), "level": string(level),
		"for_seconds": int(pipedebug.ClampWindow(window).Seconds()),
	})
	if err != nil {
		return pipedebug.LevelChange{}, err
	}
	raw, status, err := c.do(ctx, http.MethodPut, "/api/debug/loglevel", body, true)
	if err != nil {
		return pipedebug.LevelChange{}, err
	}
	if status/100 != 2 {
		return pipedebug.LevelChange{}, apiError("/api/debug/loglevel", status, raw)
	}
	var out pipedebug.LevelChange
	if err := json.Unmarshal(raw, &out); err != nil {
		return pipedebug.LevelChange{}, fmt.Errorf("loglevel response was not decodable: %w", err)
	}
	return out, nil
}

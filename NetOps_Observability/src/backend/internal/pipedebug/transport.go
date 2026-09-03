package pipedebug

// transport.go — the small constructors package backend wires into Deps, plus
// the caps every one of them shares.
//
// They live HERE, not in main, so the registration hunk inside the DEBUG-ROUTES
// markers stays short and so the bounds are unit-tested next to the code that
// relies on them (the parsercov/transport.go precedent). Nothing here reads the
// environment: the client and the configured strings are handed in.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// EnvSidecarURL optionally names the correlation debug sidecar's base URL
	// explicitly. Unset, it is DERIVED from CORRELATION_URL (same host and
	// scheme, the sidecar's port) — see SidecarBase.
	EnvSidecarURL = "CORR_DEBUG_SIDECAR_URL"
	// EnvSidecarToken is the shared secret the sidecar's debug routes require.
	// UNSET IS THE SHIPPED DEFAULT and means the Kafka peek and the correlation
	// log-level control are OFF: the stage then reports "not observable", with
	// the reason, instead of silently degrading.
	EnvSidecarToken = "CORR_DEBUG_TOKEN" // #nosec G101 -- the NAME of an environment variable, not a credential
	// EnvSidecarPort is the correlation health sidecar's port (compose default
	// 8094, CORR_HEALTH_SIDECAR_PORT on the correlation service).
	EnvSidecarPort = "CORR_HEALTH_SIDECAR_PORT"

	// DefaultSidecarPort mirrors correlation/main.py's CORR_HEALTH_SIDECAR_PORT.
	DefaultSidecarPort = 8094

	// maxSidecarResponse bounds one sidecar answer. The peer chooses the size,
	// so an unbounded read here is an OOM in the API process (audit F-27).
	maxSidecarResponse = 4 << 20
	// maxVictoriaResponse bounds one /api/v1/export answer.
	maxVictoriaResponse = 8 << 20
)

// SidecarBase derives the correlation debug sidecar's base URL.
//
// explicit wins. Otherwise the host and SCHEME are taken from CORRELATION_URL
// and only the port is replaced: on the hardened deployment CORRELATION_URL is
// https://correlation:8443 and the sidecar presents the SAME service
// certificate, so deriving keeps the internal-mTLS client verifying by name
// (guessing a scheme would either fail verification or silently downgrade).
//
// THREE STATES, never two (§10). ("" , nil) is NOT CONFIGURED — an honest,
// expected state that the stage renders as "not observable". ("", err) is
// MISCONFIGURED — CORRELATION_URL is set but unusable, which is an operator
// mistake that must be named, not folded into "the feature is off". Anything
// else is the derived base. Collapsing the middle case into the first is the
// exact conflation silent_failure_guards_test.go exists to catch.
func SidecarBase(explicit, correlationURL string, port int) (string, error) {
	if e := strings.TrimSpace(explicit); e != "" {
		return strings.TrimRight(e, "/"), nil
	}
	base := strings.TrimSpace(correlationURL)
	if base == "" {
		return "", nil // not configured
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("CORRELATION_URL is not a usable URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("CORRELATION_URL %q names no host, so the debug sidecar cannot be addressed", redactURL(base))
	}
	if port <= 0 || port > 65535 {
		port = DefaultSidecarPort
	}
	u.Host = net.JoinHostPort(host, strconv.Itoa(port))
	u.Path, u.RawQuery, u.Fragment = "", "", ""
	return strings.TrimRight(u.String(), "/"), nil
}

// errSidecarUnconfigured is the honest "this deployment did not enable the
// bus peek" error. The stage renders it as NOT-OBSERVABLE with the reason.
var errSidecarUnconfigured = errors.New(
	"the correlation debug sidecar is not configured: set CORR_DEBUG_TOKEN (and, if the sidecar is not on the correlation service's own host, CORR_DEBUG_SIDECAR_URL) on both the api and correlation services")

// NewKafkaPeek builds Deps.KafkaPeek over an HTTP client (package backend
// passes backendHTTPClient, which carries the internal-mTLS transport).
func NewKafkaPeek(client *http.Client, base, token string) func(context.Context, PeekRequest) (PeekResult, error) {
	return func(ctx context.Context, req PeekRequest) (PeekResult, error) {
		if base == "" || token == "" {
			return PeekResult{}, errSidecarUnconfigured
		}
		if !ValidTopic(req.Topic) {
			return PeekResult{}, fmt.Errorf("refusing to peek topic %q: not a legal topic name", req.Topic)
		}
		if !ValidMarker(req.Marker) {
			return PeekResult{}, errors.New("refusing to peek with a malformed marker")
		}
		body := map[string]any{
			"topic": req.Topic, "marker": req.Marker,
			"max_seconds": req.MaxSeconds, "max_records": req.MaxRecords,
			"lookback_seconds": req.LookbackSeconds,
		}
		raw, err := postJSON(ctx, client, base+"/debug/kafka-peek", token, body, maxSidecarResponse)
		if err != nil {
			return PeekResult{}, err
		}
		var out PeekResult
		if err := json.Unmarshal(raw, &out); err != nil {
			return PeekResult{}, fmt.Errorf("sidecar peek response was not decodable: %w", err)
		}
		return out, nil
	}
}

// NewCorrLogLevel builds Deps.CorrLogLevel over the same sidecar.
func NewCorrLogLevel(client *http.Client, base, token string) func(context.Context, Level, time.Duration) (LevelChange, error) {
	return func(ctx context.Context, level Level, window time.Duration) (LevelChange, error) {
		if base == "" || token == "" {
			return notSwitchable(ModuleCorrelation, level, errSidecarUnconfigured.Error()), nil
		}
		w := ClampWindow(window)
		raw, err := postJSON(ctx, client, base+"/debug/loglevel", token, map[string]any{
			"level": string(level), "for_seconds": int(w.Seconds()),
		}, maxSidecarResponse)
		if err != nil {
			return LevelChange{}, err
		}
		var out struct {
			Applied      bool    `json:"applied"`
			Level        string  `json:"level"`
			Previous     string  `json:"previous"`
			RevertAtUnix float64 `json:"revert_at_unix"`
			Reason       string  `json:"reason"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return LevelChange{}, fmt.Errorf("sidecar loglevel response was not decodable: %w", err)
		}
		change := LevelChange{
			Module: ModuleCorrelation, Applied: out.Applied,
			Level: Level(out.Level), Previous: Level(out.Previous), Reason: out.Reason,
		}
		if out.RevertAtUnix > 0 {
			change.RevertAt = time.Unix(int64(out.RevertAtUnix), 0).UTC()
		}
		return change, nil
	}
}

// NewCorrHealth builds Deps.CorrHealth over the correlation service's own
// /healthz (the dead-letter counters the correlation stage reports).
func NewCorrHealth(client *http.Client, base string) func(context.Context) (map[string]any, error) {
	return func(ctx context.Context) (map[string]any, error) {
		if base == "" {
			return nil, errors.New("no correlation base URL configured")
		}
		raw, err := getBounded(ctx, client, base+"/healthz", maxSidecarResponse)
		if err != nil {
			return nil, err
		}
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("correlation health response was not decodable: %w", err)
		}
		return out, nil
	}
}

// NewVictoriaExport builds Deps.VictoriaExport over GET /api/v1/export.
func NewVictoriaExport(client *http.Client, base string) func(context.Context, string, time.Time, time.Time) ([]byte, error) {
	return func(ctx context.Context, match string, start, end time.Time) ([]byte, error) {
		if strings.TrimSpace(base) == "" {
			return nil, errors.New("no VictoriaMetrics base URL configured")
		}
		if strings.TrimSpace(match) == "" {
			return nil, errors.New("refusing an export with no series selector")
		}
		q := url.Values{}
		q.Set("match[]", match)
		q.Set("start", strconv.FormatInt(start.Unix(), 10))
		q.Set("end", strconv.FormatInt(end.Unix(), 10))
		return getBounded(ctx, client, strings.TrimRight(base, "/")+"/api/v1/export?"+q.Encode(), maxVictoriaResponse)
	}
}

// NewUDPInjector builds a one-datagram sender for a configured target. An empty
// target yields an injector that refuses with a reason rather than one that
// guesses a host.
func NewUDPInjector(target string, timeout time.Duration) func(context.Context, []byte) error {
	return func(_ context.Context, payload []byte) error {
		if strings.TrimSpace(target) == "" {
			return errors.New("no injection target configured for this kind")
		}
		return SendUDP(target, payload, timeout)
	}
}

// ── shared HTTP plumbing ────────────────────────────────────────────────────

func postJSON(ctx context.Context, client *http.Client, endpoint, token string, body any, limit int64) ([]byte, error) {
	if client == nil {
		return nil, errors.New("no HTTP client configured")
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() // body is drained below
	raw, err := readLimited(resp.Body, limit)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		// The peer's own explanation is the most useful thing we have, but it is
		// UNTRUSTED text from another service: bound it and redact it before it
		// travels into a log line or an operator's terminal.
		return nil, fmt.Errorf("%s answered %d: %s", endpoint, resp.StatusCode,
			RedactString(truncate(strings.TrimSpace(string(raw)), 512)))
	}
	return raw, nil
}

func getBounded(ctx context.Context, client *http.Client, endpoint string, limit int64) ([]byte, error) {
	if client == nil {
		return nil, errors.New("no HTTP client configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/plain")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() // body is drained below
	raw, err := readLimited(resp.Body, limit)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s answered %d", redactURL(endpoint), resp.StatusCode)
	}
	return raw, nil
}

// redactURL strips userinfo before an endpoint appears in an error string: the
// metrics upstream is configured as https://user:password@vmauth:8427 on the
// hardened deployment, and an error message is a log line (§8).
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(unparseable url)"
	}
	if u.User != nil {
		u.User = url.User("[REDACTED]")
	}
	u.RawQuery = ""
	return u.String()
}

// readLimited reads at most `limit` bytes and treats HITTING the limit as a FAILURE,
// not a truncation: a silently clipped JSON body decodes to a plausible-looking
// partial answer, which is worse than an error.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) >= limit {
		return nil, fmt.Errorf("response exceeded %d bytes — refusing a truncated body", limit)
	}
	return body, nil
}

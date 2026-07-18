package cloudconn

// exchange.go — shared plumbing for the LIVE per-provider credential exchange:
// the injectable TokenExchanger seam, the platform-identity sources the broker
// signs/asserts with, the sanitized error surface, and the bounded HTTP helper
// (timeout, capped response, bounded retry with backoff+jitter).
//
// Zero-trust posture: every outbound call has a deadline, every response body
// is size-capped, every error is structured and carries NO secret material.

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"time"
)

// TokenExchanger turns one ExchangeRequest into one short-lived provider
// credential. Implementations are per-provider (AWS STS, Azure Entra, GCP
// STS/IAM) and hold NO credentials of their own — base material comes from the
// request (decrypted legacy secret) or an injected platform-identity source.
type TokenExchanger interface {
	Exchange(ctx context.Context, req ExchangeRequest) (ScopedToken, error)
}

// AWSPlatformCredentialSource supplies the broker's own AWS platform identity —
// the credentials that SIGN sts:AssumeRole calls into customer accounts.
// Injectable so tests never touch process env and deployments can swap in an
// instance-profile/IRDS source later.
type AWSPlatformCredentialSource interface {
	Credentials(ctx context.Context) (AWSCredentials, error)
}

// WorkloadAssertionSource supplies Correlix's own signed OIDC workload
// assertion (a JWT) for federated exchanges (Azure Entra WIF client_assertion,
// GCP STS subject_token, AWS AssumeRoleWithWebIdentity). audience is the value
// the relying provider expects; subject is the per-connector identity the
// customer's trust policy names (see WorkloadSubject). A source with a fixed,
// externally-minted token (EnvWorkloadAssertionSource) may ignore both.
type WorkloadAssertionSource interface {
	Assertion(ctx context.Context, audience, subject string) (string, error)
}

// WorkloadSubject is the subject Correlix presents in its workload assertion
// for a connector — the value the customer's trust policy / federated
// credential must reference. Precedence: the connector's explicit federated
// subject (Azure FIC), then the platform trust-anchor subject, then the
// documented default the setup instructions render.
func WorkloadSubject(id IdentityConfig) string {
	if s := strings.TrimSpace(id.FederatedSubject); s != "" {
		return s
	}
	if s := strings.TrimSpace(id.Anchor.OIDCSubject); s != "" {
		return s
	}
	return "correlix:connector:" + strings.TrimSpace(id.ConnectorID)
}

// Deferral sentinels: these mean "the platform identity is not configured in
// this deployment", NOT "the provider denied us". Callers (the broker /
// validate handler) surface them as a deferred live check, never as a failure.
var (
	// ErrPlatformCredentialsMissing — no AWS platform credentials are configured
	// for the broker to sign STS calls with.
	ErrPlatformCredentialsMissing = errors.New("cloudconn: AWS platform credentials for the identity broker are not configured")
	// ErrWorkloadAssertionMissing — no workload OIDC assertion source is
	// configured for federated (WIF) exchanges.
	ErrWorkloadAssertionMissing = errors.New("cloudconn: workload identity assertion for federated exchange is not configured")
)

// EnvAWSCredentialSource reads the broker platform identity from the standard
// AWS environment variables (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY /
// AWS_SESSION_TOKEN). Returns ErrPlatformCredentialsMissing when unset.
type EnvAWSCredentialSource struct{}

// Credentials implements AWSPlatformCredentialSource.
func (EnvAWSCredentialSource) Credentials(context.Context) (AWSCredentials, error) {
	c := AWSCredentials{
		AccessKeyID:     strings.TrimSpace(os.Getenv("AWS_ACCESS_KEY_ID")),
		SecretAccessKey: strings.TrimSpace(os.Getenv("AWS_SECRET_ACCESS_KEY")),
		SessionToken:    strings.TrimSpace(os.Getenv("AWS_SESSION_TOKEN")),
	}
	if c.Empty() {
		return AWSCredentials{}, ErrPlatformCredentialsMissing
	}
	return c, nil
}

// EnvWorkloadAssertionSource reads Correlix's workload OIDC assertion from a
// projected token file (CLOUD_CONNECTOR_WORKLOAD_JWT_FILE — the K8s/CI pattern)
// or, as a fallback, directly from CLOUD_CONNECTOR_WORKLOAD_JWT. Returns
// ErrWorkloadAssertionMissing when neither is set. The audience and subject
// arguments are unused here: a mounted token is minted for a fixed audience
// and subject by the platform that projected it.
type EnvWorkloadAssertionSource struct{}

// Assertion implements WorkloadAssertionSource.
func (EnvWorkloadAssertionSource) Assertion(_ context.Context, _, _ string) (string, error) {
	if path := strings.TrimSpace(os.Getenv("CLOUD_CONNECTOR_WORKLOAD_JWT_FILE")); path != "" {
		b, err := os.ReadFile(path) // #nosec G304 -- operator-configured token path
		if err != nil {
			return "", &ExchangeError{Provider: "", Code: "assertion_read_failed", Msg: "workload assertion file unreadable"}
		}
		tok := strings.TrimSpace(string(b))
		if tok == "" {
			return "", ErrWorkloadAssertionMissing
		}
		return tok, nil
	}
	if tok := strings.TrimSpace(os.Getenv("CLOUD_CONNECTOR_WORKLOAD_JWT")); tok != "" {
		return tok, nil
	}
	return "", ErrWorkloadAssertionMissing
}

// ── sanitized error surface ───────────────────────────────────────────────────

// ExchangeError is the sanitized, structured outcome of a failed provider
// exchange. Code is a stable token ("denied" | "throttled" | "malformed_response"
// | "provider_error" | "request_invalid" | "network" | ...); Msg is short human
// text. It NEVER carries a secret, an assertion, a token, or a raw provider
// response body.
type ExchangeError struct {
	Provider   Provider
	Code       string
	HTTPStatus int
	Msg        string
	Attempts   int
}

func (e *ExchangeError) Error() string {
	if e == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("cloudconn exchange failed provider=")
	b.WriteString(string(e.Provider))
	b.WriteString(" code=")
	b.WriteString(e.Code)
	if e.HTTPStatus != 0 {
		b.WriteString(" http_status=")
		b.WriteString(itoa(e.HTTPStatus))
	}
	if e.Attempts > 1 {
		b.WriteString(" attempts=")
		b.WriteString(itoa(e.Attempts))
	}
	if e.Msg != "" {
		b.WriteString(" msg=")
		b.WriteString(e.Msg)
	}
	return b.String()
}

// Denied reports whether the provider explicitly refused the exchange (vs a
// transport / transient failure).
func (e *ExchangeError) Denied() bool { return e != nil && e.Code == "denied" }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ── bounded HTTP with retry ───────────────────────────────────────────────────

const (
	// exchangeMaxResponseBytes caps every provider response read (io.LimitReader).
	exchangeMaxResponseBytes = 1 << 20 // 1 MiB
	// exchangeMaxAttempts bounds the retry loop (1 initial + 2 retries).
	exchangeMaxAttempts = 3
	// exchangeRetryBase is the backoff base; attempt n sleeps base·2ⁿ ± 50% jitter.
	exchangeRetryBase = 250 * time.Millisecond
	// exchangeDefaultTimeout bounds a whole Exchange when the caller supplied no
	// deadline (all IO must have a timeout).
	exchangeDefaultTimeout = 30 * time.Second
	// exchangeClientTimeout bounds one HTTP attempt.
	exchangeClientTimeout = 10 * time.Second
)

// newExchangeHTTPClient returns the default per-attempt-bounded client using
// the verified default TLS transport.
func newExchangeHTTPClient() *http.Client {
	return &http.Client{Timeout: exchangeClientTimeout}
}

// ensureDeadline guarantees ctx carries a deadline.
func ensureDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, exchangeDefaultTimeout)
}

// doExchangeHTTP performs one logical provider call with bounded retries:
// network errors, 429 and 5xx are retried (backoff + jitter, context-aware);
// any other status returns immediately. The response body is size-capped.
// build must return a FRESH request each attempt (bodies are single-use).
func doExchangeHTTP(ctx context.Context, client *http.Client, provider Provider, build func() (*http.Request, error)) (status int, body []byte, attempts int, err error) {
	if client == nil {
		client = newExchangeHTTPClient()
	}
	ctx, cancel := ensureDeadline(ctx)
	defer cancel()

	var lastErr error
	for attempt := 1; attempt <= exchangeMaxAttempts; attempt++ {
		attempts = attempt
		req, berr := build()
		if berr != nil {
			return 0, nil, attempts, &ExchangeError{Provider: provider, Code: "request_invalid", Msg: berr.Error(), Attempts: attempts}
		}
		req = req.WithContext(ctx)
		resp, derr := client.Do(req)
		if derr != nil {
			lastErr = derr
			if ctx.Err() != nil {
				return 0, nil, attempts, &ExchangeError{Provider: provider, Code: "timeout", Msg: "provider call deadline exceeded", Attempts: attempts}
			}
			if !sleepBackoff(ctx, attempt) {
				break
			}
			continue
		}
		b, rerr := io.ReadAll(io.LimitReader(resp.Body, exchangeMaxResponseBytes))
		closeErr := resp.Body.Close()
		if rerr != nil || closeErr != nil {
			lastErr = errors.Join(rerr, closeErr)
			if !sleepBackoff(ctx, attempt) {
				break
			}
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = &ExchangeError{Provider: provider, Code: "throttled", HTTPStatus: resp.StatusCode, Msg: "provider throttled or unavailable", Attempts: attempts}
			if !sleepBackoff(ctx, attempt) {
				break
			}
			continue
		}
		return resp.StatusCode, b, attempts, nil
	}
	var xe *ExchangeError
	if errors.As(lastErr, &xe) {
		xe.Attempts = attempts
		return 0, nil, attempts, xe
	}
	return 0, nil, attempts, &ExchangeError{Provider: provider, Code: "network", Msg: "provider unreachable", Attempts: attempts}
}

// sleepBackoff sleeps base·2^(attempt-1) ± 50% jitter, honoring ctx. Returns
// false when the context died or the attempt budget is exhausted.
func sleepBackoff(ctx context.Context, attempt int) bool {
	if attempt >= exchangeMaxAttempts {
		return false
	}
	d := exchangeRetryBase << (attempt - 1)
	// ±50% jitter; math/rand is fine here (scheduling, not security).
	jitter := time.Duration(rand.Int64N(int64(d))) - d/2 // #nosec G404 -- retry jitter, not a security context
	t := time.NewTimer(d + jitter)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// truncateForError trims free-form provider text destined for an ExchangeError
// message: single line, bounded length, never a whole response body.
func truncateForError(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	const maxLen = 200
	if len(s) > maxLen {
		return s[:maxLen] + "…"
	}
	return s
}

// clampLifetime bounds a requested lifetime to [minL, maxL] with a fallback
// default when the request carries none.
func clampLifetime(requested, def, minL, maxL time.Duration) time.Duration {
	d := requested
	if d <= 0 {
		d = def
	}
	if d < minL {
		d = minL
	}
	if d > maxL {
		d = maxL
	}
	return d
}

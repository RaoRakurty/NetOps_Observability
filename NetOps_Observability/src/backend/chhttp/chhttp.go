// Package chhttp is the single transport seam for every ClickHouse HTTP call.
//
// # WHY THIS PACKAGE EXISTS
//
// The 2026-07-21 audit found that 19 of 20 ClickHouse insert sites discarded
// the failure they were handed (F-38), and that no site anywhere set insert
// tolerance (F-56). The reason was structural, not careless: there was no
// ClickHouse client. Every call site resolved CLICKHOUSE_URL itself, built its
// own request, and invented its own idea of what "failed" meant. Roughly a
// dozen near-copies of the same thirty lines, each of which had to learn error
// handling independently — and most never did.
//
// That is the audit's one-line diagnosis in physical form: the generator of the
// class was the absence of a seam. This package is the seam.
//
// # WHY STATUS CODES ARE NOT ENOUGH
//
// The subtle part, and the reason a hand-rolled `resp.StatusCode != 200` check
// is not sufficient even when someone remembers to write it: ClickHouse reports
// most operational failures as **HTTP 500 with a DB::Exception code in the
// body**. The two failures an operator most needs to tell apart arrive looking
// identical over HTTP:
//
//	HTTP 500  Code: 252  TOO_MANY_PARTS      → transient backpressure; retry
//	HTTP 500  Code: 16   NO_SUCH_COLUMN      → a schema bug; retrying never helps
//
// A status-only classifier either retries the schema bug forever or gives up on
// the backpressure — both wrong, and both invisible. So this package parses the
// exception code and classifies on it. Callers ask Retryable(err), never a
// status number.
//
// # SCOPE
//
// Transport and classification only. SQL construction, tenant scoping policy,
// and retry orchestration stay with the caller — this package tells the truth
// about what happened and refuses to guess what should happen next.
package chhttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultMaxBytes bounds a response body. A truncated answer must never be
// returned as a complete one (the F-67 shape), so Exec errors rather than
// silently handing back a prefix.
const DefaultMaxBytes int64 = 8 << 20

// DefaultBudget is the server-side execution ceiling applied when a Request
// leaves Budget unset. Every call is bounded (CLAUDE.md §9).
const DefaultBudget = 8 * time.Second

// ClickHouse DB::Exception codes this package classifies by name. The list is
// deliberately short: only codes whose retry semantics we are confident about.
// Anything unlisted falls back to HTTP-status classification.
//
// Ref: ClickHouse ErrorCodes.cpp.
const (
	codeUnknownSetting      = 115 // an insert-tolerance/setting key this server rejects (F-56)
	codeNoSuchColumn        = 16
	codeUnknownTable        = 60
	codeAuthFailed          = 516
	codeTooManyParts        = 252 // insert pressure — the classic production failure
	codeMemoryLimitExceeded = 241
	codeTooManySimultaneous = 202
	codeTimeoutExceeded     = 159
	codeSocketTimeout       = 209
	codeNotEnoughSpace      = 243
)

// retryableCodes are transient by nature: the same statement, unchanged, can
// succeed later. Everything else is treated as permanent — a bug or a config
// error that retrying only amplifies.
var retryableCodes = map[int]bool{
	codeTooManyParts:        true,
	codeMemoryLimitExceeded: true,
	codeTooManySimultaneous: true,
	codeTimeoutExceeded:     true,
	codeSocketTimeout:       true,
	codeNotEnoughSpace:      true,
}

// permanentCodes are the ones worth naming explicitly so a caller's log says
// "unknown setting" rather than "HTTP 500".
var permanentCodes = map[int]bool{
	codeUnknownSetting: true,
	codeNoSuchColumn:   true,
	codeUnknownTable:   true,
	codeAuthFailed:     true,
}

// Error is a classified ClickHouse failure. Callers branch on Retryable, never
// on Status — see the package doc for why the two disagree so often.
type Error struct {
	Op        string // caller-supplied label, e.g. "insert netops.flows"
	Status    int    // HTTP status; 0 when the failure was at transport level
	Code      int    // ClickHouse DB::Exception code; 0 when absent/unparsed
	Message   string
	Retryable bool
	wrapped   error // transport-level cause, if any
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("clickhouse")
	if e.Op != "" {
		b.WriteString(" " + e.Op)
	}
	switch {
	case e.Status > 0 && e.Code > 0:
		fmt.Fprintf(&b, ": HTTP %d code %d", e.Status, e.Code)
	case e.Status > 0:
		fmt.Fprintf(&b, ": HTTP %d", e.Status)
	default:
		b.WriteString(": transport")
	}
	if e.Message != "" {
		b.WriteString(": " + e.Message)
	}
	if e.Retryable {
		b.WriteString(" (retryable)")
	}
	return b.String()
}

func (e *Error) Unwrap() error { return e.wrapped }

// Retryable reports whether err is a ClickHouse failure worth retrying with
// backoff. A non-chhttp error is never assumed retryable: guessing "yes" on an
// unknown failure is how a poison statement becomes an infinite loop.
func Retryable(err error) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Retryable
	}
	return false
}

// Code returns the ClickHouse exception code carried by err, or 0.
func Code(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return 0
}

// Client is a configured ClickHouse HTTP endpoint. Construct one per process
// and share it — it is stateless beyond its http.Client, which is safe for
// concurrent use.
//
// Base/User/Password are injected rather than read from the environment here,
// which is what makes the whole surface testable against an httptest server:
// chhttp_test.go drives every failure in the taxonomy through this struct.
type Client struct {
	Base     string
	User     string
	Password string
	HTTP     *http.Client
}

// Request is one statement plus the per-call server settings.
type Request struct {
	SQL string
	// Op labels the call in errors and logs, e.g. "insert netops.tunnels".
	Op string
	// Scope sets the tenant_scope custom setting the row policies enforce on.
	// REQUIRED: an empty Scope is rejected rather than defaulted, because every
	// possible default is wrong — "__all__" silently defeats tenant isolation
	// and "__none__" silently returns nothing. The caller must state its intent
	// (CLAUDE.md §3a: default-closed, and never guess a tenant).
	Scope string
	// LogComment attributes the query in system.query_log (#100 read budgets).
	LogComment string
	// Profile optionally selects a server-side settings profile.
	Profile string
	// Settings carries additional server settings — notably the insert
	// tolerances F-56 found missing everywhere.
	Settings map[string]string
	// Budget bounds server-side execution; zero uses DefaultBudget.
	Budget time.Duration
	// MaxBytes bounds the response; zero uses DefaultMaxBytes.
	MaxBytes int64
}

// ErrNoEndpoint is returned when the client has no Base configured. A missing
// endpoint is a configuration failure, never a silent no-op.
var ErrNoEndpoint = errors.New("clickhouse endpoint not configured")

// ErrScopeRequired is returned when a Request omits Scope. See Request.Scope.
var ErrScopeRequired = errors.New("clickhouse request has no tenant scope")

// exceptionCode extracts the DB::Exception code from a ClickHouse error body.
// Bodies look like: "Code: 252. DB::Exception: Too many parts ...".
var exceptionCode = regexp.MustCompile(`Code:\s*(\d+)`)

func parseCode(body string) int {
	m := exceptionCode.FindStringSubmatch(body)
	if len(m) < 2 {
		return 0
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0
	}
	return n
}

// Exec runs one statement and returns its response body.
//
// Every failure path returns a classified *Error — there is no path on which a
// failed write returns nil, which is the defect class (F-38) this package
// exists to make unrepresentable.
func (c *Client) Exec(ctx context.Context, req Request) ([]byte, error) {
	maxBytes := req.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	resp, err := c.do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if readErr != nil {
		// A body that died mid-read is transport trouble, not a server verdict.
		return nil, &Error{Op: req.Op, Status: resp.StatusCode,
			Message: "read response: " + readErr.Error(), Retryable: true, wrapped: readErr}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, classify(req.Op, resp.StatusCode, body)
	}

	// A 200 whose body hit the cap is a TRUNCATED answer. Returning it would let
	// a partial result read as a complete one — the exact shape of F-67.
	if int64(len(body)) >= maxBytes {
		return nil, &Error{Op: req.Op, Status: resp.StatusCode,
			Message: fmt.Sprintf("response exceeded %d bytes — narrow the query", maxBytes)}
	}
	return body, nil
}

// ExecStream is Exec for callers that must stream the result rather than hold
// it in memory — the API's ClickHouse proxy, whose whole job is to pass a large
// result set through to an HTTP client.
//
// The failure path is identical to Exec's: a non-2xx is read (error bodies are
// small and bounded) and returned CLASSIFIED, so a streaming caller is not
// forced to choose between passing ClickHouse's raw DB::Exception text through
// to an end user and having no diagnosis at all.
//
// On success the caller owns the returned ReadCloser and MUST close it.
func (c *Client) ExecStream(ctx context.Context, req Request) (io.ReadCloser, error) {
	resp, err := c.do(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return nil, classify(req.Op, resp.StatusCode, body)
	}
	return resp.Body, nil
}

// do performs the request and returns the live response. Shared by Exec and
// ExecStream so URL construction, settings and auth cannot drift between them.
func (c *Client) do(ctx context.Context, req Request) (*http.Response, error) {
	if strings.TrimSpace(c.Base) == "" {
		return nil, &Error{Op: req.Op, Message: ErrNoEndpoint.Error(), wrapped: ErrNoEndpoint}
	}
	if req.Scope == "" {
		return nil, &Error{Op: req.Op, Message: ErrScopeRequired.Error(), wrapped: ErrScopeRequired}
	}
	budget := req.Budget
	if budget <= 0 {
		budget = DefaultBudget
	}
	u, err := url.Parse(c.Base)
	if err != nil {
		return nil, &Error{Op: req.Op, Message: "bad endpoint: " + err.Error(), wrapped: err}
	}
	q := u.Query()
	q.Set("tenant_scope", req.Scope)
	secs := int(budget.Seconds())
	if secs < 1 {
		secs = 1
	}
	q.Set("max_execution_time", strconv.Itoa(secs))
	q.Set("cancel_http_readonly_queries_on_client_close", "1")
	if req.LogComment != "" {
		q.Set("log_comment", req.LogComment)
	}
	if req.Profile != "" {
		q.Set("profile", req.Profile)
	}
	for k, v := range req.Settings {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader([]byte(req.SQL)))
	if err != nil {
		return nil, &Error{Op: req.Op, Message: err.Error(), wrapped: err}
	}
	httpReq.SetBasicAuth(c.User, c.Password)
	httpReq.Header.Set("Content-Type", "text/plain")

	cl := c.HTTP
	if cl == nil {
		cl = &http.Client{Timeout: budget + 2*time.Second}
	}
	resp, err := cl.Do(httpReq)
	if err != nil {
		// Transport failures (connection refused, reset, timeout) are transient
		// by nature — the server may simply be restarting.
		return nil, &Error{Op: req.Op, Message: err.Error(), Retryable: true, wrapped: err}
	}
	return resp, nil
}

// classify turns a non-200 into a typed verdict. Exception code wins over HTTP
// status whenever we recognise it, because ClickHouse reports both transient
// backpressure and permanent schema bugs as 500 (see the package doc).
func classify(op string, status int, body []byte) *Error {
	msg := strings.Join(strings.Fields(string(body)), " ")
	if len(msg) > 512 {
		msg = msg[:512] + "…"
	}
	e := &Error{Op: op, Status: status, Code: parseCode(msg), Message: msg}

	switch {
	case retryableCodes[e.Code]:
		e.Retryable = true
	case permanentCodes[e.Code]:
		e.Retryable = false
	case status == http.StatusTooManyRequests, status == http.StatusServiceUnavailable,
		status == http.StatusGatewayTimeout, status == http.StatusBadGateway:
		// Backpressure and proxy-level transients, no exception code present.
		e.Retryable = true
	case status >= 500:
		// An unrecognised server-side failure: retrying is the safer default,
		// and the caller's backoff bounds the cost.
		e.Retryable = true
	default:
		// 4xx without a known code: the request itself is wrong. Retrying an
		// unchanged bad request is how a poison statement loops forever.
		e.Retryable = false
	}
	return e
}

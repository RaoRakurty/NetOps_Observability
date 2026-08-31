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
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
// All values below were CONFIRMED against clickhouse/clickhouse-server:24.8-alpine
// (24.8.14.39), the digest-pinned image this repo deploys — not read off a wiki.
// See chhttp_integration_test.go, which re-verifies them against a live server.
const (
	codeUnknownSetting      = 115 // an insert-tolerance/setting key this server rejects (F-56)
	codeNoSuchColumn        = 16
	codeUnknownTable        = 60
	codeUnknownDatabase     = 81  // measured: SELECT FROM nope.nope → HTTP 404 + code 81
	codeAuthFailed          = 516 // measured: wrong password → HTTP 403 + code 516
	codeTooManyParts        = 252 // insert pressure — the classic production failure
	codeMemoryLimitExceeded = 241
	codeTooManySimultaneous = 202
	codeTimeoutExceeded     = 159
	codeSocketTimeout       = 209
	codeNotEnoughSpace      = 243
	codeTypeMismatch        = 53 // TYPE_MISMATCH — a malformed row, not a transient
	codeUnknownIdentifier   = 47 // measured: SELECT no_such_col → HTTP 404 + code 47
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
	codeUnknownSetting:    true,
	codeNoSuchColumn:      true,
	codeUnknownTable:      true,
	codeUnknownDatabase:   true,
	codeAuthFailed:        true,
	codeTypeMismatch:      true,
	codeUnknownIdentifier: true,
}

// classificationFor maps a code to the stable metric slug. Metrics keyed on a
// raw integer are unreadable in an alert; these names are what an operator sees.
var classificationFor = map[int]string{
	codeTooManyParts:        "too_many_parts",
	codeMemoryLimitExceeded: "memory_limit",
	codeTooManySimultaneous: "too_many_queries",
	codeTimeoutExceeded:     "server_timeout",
	codeSocketTimeout:       "socket_timeout",
	codeNotEnoughSpace:      "disk_full",
	codeUnknownSetting:      "schema_setting",
	codeNoSuchColumn:        "schema_column",
	codeUnknownTable:        "schema_table",
	codeUnknownDatabase:     "schema_database",
	codeTypeMismatch:        "schema_type",
	codeAuthFailed:          "auth",
	codeUnknownIdentifier:   "schema_identifier",
}

// exceptionMarkers identify a ClickHouse exception embedded in a body that
// already carried a 200.
//
// MEASURED on 24.8.14.39: with wait_end_of_query=0, a query that fails AFTER
// the output buffer has flushed returns **HTTP 200, no X-ClickHouse-Exception-Code
// header, and a 15 MB body whose tail is the exception**. A status-only check —
// and the header check below — both call that success. This is the only signal
// left, so it is checked too.
var exceptionMarkers = []string{"DB::Exception", "__exception__"}

// bodyCarriesException reports whether a 200 body has an exception in its tail.
// Only the tail is inspected: ClickHouse appends the exception after the data,
// and scanning a whole multi-megabyte result for a substring on every successful
// read would be a real cost for no benefit.
func bodyCarriesException(body []byte) bool {
	const tail = 4 << 10
	seg := body
	if len(seg) > tail {
		seg = seg[len(seg)-tail:]
	}
	for _, m := range exceptionMarkers {
		if bytes.Contains(seg, []byte(m)) {
			return true
		}
	}
	return false
}

// Outcome is the COMMIT-STATE axis, which is not the same question as "did we
// get an error". A caller that advances a Kafka offset or a checkpoint must
// branch on this and nothing else.
//
// The three states are not stylistic. A distributed write has three honest
// answers, and collapsing Unknown into either neighbour causes a specific,
// opposite bug: call it Committed and you lose data; call it Rejected and a
// blind retry duplicates rows that are already there.
type Outcome uint8

const (
	// OutcomeCommitted — ClickHouse positively accepted the statement.
	OutcomeCommitted Outcome = iota
	// OutcomeRejected — positively did NOT commit. Either the server said so,
	// or the request never reached it (connection refused). Safe to retry from
	// scratch; safe to quarantine.
	OutcomeRejected
	// OutcomeUnknown — the request may or may not have been applied. The body
	// was (or may have been) fully transmitted and the answer was lost. Retry
	// ONLY with byte-identical payload and the same idempotency identity.
	OutcomeUnknown
)

func (o Outcome) String() string {
	switch o {
	case OutcomeCommitted:
		return "committed"
	case OutcomeRejected:
		return "rejected"
	default:
		return "unknown"
	}
}

// Error is a classified ClickHouse failure. Callers branch on Outcome (commit
// state) and Retryable (whether another attempt is worthwhile) — never on
// Status, for the reason in the package doc.
type Error struct {
	Op      string // caller-supplied label, e.g. "insert netops.flows"
	Status  int    // HTTP status; 0 when the failure was at transport level
	Code    int    // ClickHouse DB::Exception code; 0 when absent/unparsed
	Message string
	// QueryID is X-ClickHouse-Query-Id when the server sent one. It is the only
	// handle that ties this failure to a row in system.query_log, which is how
	// an Unknown outcome gets resolved after the fact.
	QueryID string
	// Outcome is the commit state. See the Outcome docs.
	Outcome Outcome
	// Classification is a short stable slug for metrics/logs, e.g.
	// "too_many_parts", "schema", "auth", "transport_refused", "response_lost".
	Classification string
	Retryable      bool
	wrapped        error // transport-level cause, if any
}

// QueryIDOf returns the ClickHouse query id carried by err, or "".
func QueryIDOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.QueryID
	}
	return ""
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
	// NoWaitEndOfQuery disables server-side response buffering. Set ONLY by a
	// caller that must stream a large result (the API proxy). It trades the
	// authoritative error status for constant memory — see the wait_end_of_query
	// measurement in do().
	NoWaitEndOfQuery bool
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
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10)) // best-effort: drain for connection reuse
		_ = resp.Body.Close()                                        // best-effort: nothing actionable on close failure
	}()

	queryID := resp.Header.Get("X-ClickHouse-Query-Id")
	hdrCode := headerExceptionCode(resp)

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if readErr != nil {
		// The request was fully sent and the server began answering; the answer
		// was lost mid-flight. We CANNOT know whether the insert applied, and
		// saying "failed" here is how a retry duplicates committed rows.
		return nil, &Error{Op: req.Op, Status: resp.StatusCode, QueryID: queryID,
			Message: "read response: " + readErr.Error(), Outcome: OutcomeUnknown,
			Classification: "response_lost", Retryable: true, wrapped: readErr}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, classify(req.Op, resp.StatusCode, body, hdrCode, queryID)
	}

	// A 200 can still be a failure, two different ways.
	//
	// (1) The exception header is present. Authoritative when ClickHouse got to
	//     set it, and it costs nothing to check.
	// (2) The header is absent but the body ends in an exception — the measured
	//     wait_end_of_query=0 case. Without this check a 15 MB body whose tail
	//     is a DB::Exception is returned to the caller as a successful read.
	if hdrCode != 0 || bodyCarriesException(body) {
		return nil, classify(req.Op, resp.StatusCode, body, hdrCode, queryID)
	}

	// A 200 whose body hit the cap is a TRUNCATED answer. Returning it would let
	// a partial result read as a complete one — the exact shape of F-67.
	if int64(len(body)) >= maxBytes {
		recordOutcome(OutcomeUnknown, "response_truncated")
		return nil, &Error{Op: req.Op, Status: resp.StatusCode, QueryID: queryID,
			Message:        fmt.Sprintf("response exceeded %d bytes — narrow the query", maxBytes),
			Outcome:        OutcomeUnknown, // the statement may well have applied in full
			Classification: "response_truncated"}
	}
	recordOutcome(OutcomeCommitted, "")
	return body, nil
}

// headerExceptionCode reads X-ClickHouse-Exception-Code. MEASURED present on
// 24.8.14.39 for 403 (516) and 404 (81), and — critically — ABSENT on the
// 200-with-embedded-exception case, which is why it cannot be the only check.
func headerExceptionCode(resp *http.Response) int {
	v := resp.Header.Get("X-ClickHouse-Exception-Code")
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0
	}
	return n
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
		defer func() { _ = resp.Body.Close() }() // best-effort: nothing actionable on close failure
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return nil, classify(req.Op, resp.StatusCode, body, headerExceptionCode(resp), resp.Header.Get("X-ClickHouse-Query-Id"))
	}
	return resp.Body, nil
}

// do performs the request and returns the live response. Shared by Exec and
// ExecStream so URL construction, settings and auth cannot drift between them.
func (c *Client) do(ctx context.Context, req Request) (*http.Response, error) {
	if strings.TrimSpace(c.Base) == "" {
		return nil, &Error{Op: req.Op, Message: ErrNoEndpoint.Error(), Outcome: OutcomeRejected, Classification: "no_endpoint", wrapped: ErrNoEndpoint}
	}
	if req.Scope == "" {
		return nil, &Error{Op: req.Op, Message: ErrScopeRequired.Error(), Outcome: OutcomeRejected, Classification: "no_scope", wrapped: ErrScopeRequired}
	}
	budget := req.Budget
	if budget <= 0 {
		budget = DefaultBudget
	}
	u, err := url.Parse(c.Base)
	if err != nil {
		return nil, &Error{Op: req.Op, Message: "bad endpoint: " + err.Error(), Outcome: OutcomeRejected, Classification: "bad_endpoint", wrapped: err}
	}
	q := u.Query()
	q.Set("tenant_scope", req.Scope)
	secs := int(budget.Seconds())
	if secs < 1 {
		secs = 1
	}
	q.Set("max_execution_time", strconv.Itoa(secs))
	q.Set("cancel_http_readonly_queries_on_client_close", "1")
	// wait_end_of_query=1 makes ClickHouse buffer the response server-side so a
	// failure AFTER the first flush still arrives as a proper status + exception
	// header instead of a 200 with the error buried in the body.
	//
	// MEASURED on 24.8.14.39, same failing query, only this flag differing:
	//   wait_end_of_query=0 → HTTP 200, no exception header, 15,687,190 bytes
	//   wait_end_of_query=1 → HTTP 500, exception header,          300 bytes
	//
	// It is NOT the sole detector — it costs server-side buffering, so the
	// streaming path (ExecStream) cannot use it, and bodyCarriesException
	// backstops both. Callers that must stream set NoWaitEndOfQuery.
	if !req.NoWaitEndOfQuery {
		q.Set("wait_end_of_query", "1")
	}
	if req.LogComment != "" {
		q.Set("log_comment", req.LogComment)
	}
	for k, v := range req.Settings {
		q.Set(k, v)
	}
	// ORDER IS LOAD-BEARING — `profile` must precede every per-query setting.
	//
	// ClickHouse's HTTP handler applies URL parameters in the order they appear
	// in the query string, and `profile=` is not a value, it is an ACTION: it
	// assigns every setting the named profile declares, overwriting whatever was
	// already set. url.Values.Encode() sorts keys alphabetically, so before this
	// fix `max_memory_usage` (m) and `max_execution_time` (m) always landed
	// BEFORE `profile` (p) and were silently thrown away by the profile.
	//
	// MEASURED on the deployed 24.8.14.39, same query, only the order differing:
	//   ?max_memory_usage=536870912&profile=background -> getSetting() = 2147483648
	//   ?profile=background&max_memory_usage=536870912 -> getSetting() =  536870912
	// and in system.query_log, 2,250 `worker:timeintel-backfill` queries ran with
	// the profile's 2 GiB / 60 s while the block/threads/bytes guards — which the
	// `background` profile does NOT declare — arrived intact. That is the whole
	// signature of the bug: only the settings the profile also names were lost.
	//
	// These are plain profile VALUES, not constraints (system.settings_profile_
	// elements reports min/max/writability NULL for all of them), so a per-query
	// setting is entitled to override them — it just has to be sent afterwards.
	// Emitting the profile first restores the intended precedence: profile
	// supplies the lane's defaults, the caller's explicit Settings win.
	u.RawQuery = q.Encode()
	if req.Profile != "" {
		u.RawQuery = "profile=" + url.QueryEscape(req.Profile) + "&" + u.RawQuery
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader([]byte(req.SQL)))
	if err != nil {
		return nil, &Error{Op: req.Op, Message: err.Error(), Outcome: OutcomeRejected, Classification: "bad_request_build", wrapped: err}
	}
	httpReq.SetBasicAuth(c.User, c.Password)
	httpReq.Header.Set("Content-Type", "text/plain")

	cl := c.HTTP
	if cl == nil {
		cl = &http.Client{Timeout: budget + 2*time.Second}
	}
	resp, err := cl.Do(httpReq)
	if err != nil {
		return nil, classifyTransport(req.Op, err)
	}
	return resp, nil
}

// classify turns a non-200 into a typed verdict. Exception code wins over HTTP
// status whenever we recognise it, because ClickHouse reports both transient
// backpressure and permanent schema bugs as 500 (see the package doc).
// classify turns a failed response into a typed verdict. The exception code —
// from the header when present, else parsed from the body — outranks the HTTP
// status, because ClickHouse reports transient backpressure and permanent
// schema faults with the same 500.
//
// Outcome here is always Rejected: the server answered, and its answer was no.
// Unknown is produced only by the transport paths, where the answer was lost.
func classify(op string, status int, body []byte, hdrCode int, queryID string) *Error {
	msg := strings.Join(strings.Fields(string(body)), " ")
	// Bound the message BEFORE it reaches a log. A ClickHouse exception body can
	// quote the offending row, which for this platform is customer telemetry.
	if len(msg) > 512 {
		msg = msg[:512] + "…"
	}
	code := hdrCode
	if code == 0 {
		code = parseCode(msg)
	}
	e := &Error{
		Op: op, Status: status, Code: code, Message: msg,
		QueryID: queryID, Outcome: OutcomeRejected,
		Classification: classificationFor[code],
	}

	switch {
	case retryableCodes[code]:
		e.Retryable = true
	case permanentCodes[code]:
		e.Retryable = false
	case status == http.StatusTooManyRequests, status == http.StatusServiceUnavailable,
		status == http.StatusGatewayTimeout, status == http.StatusBadGateway:
		// Backpressure and proxy-level transients, no exception code present.
		e.Retryable = true
		if e.Classification == "" {
			e.Classification = "infrastructure"
		}
	case status >= 500:
		// An unrecognised server-side failure: retrying is the safer default,
		// and the caller's backoff bounds the cost.
		e.Retryable = true
		if e.Classification == "" {
			e.Classification = "server_error"
		}
	default:
		// 4xx without a known code: the request itself is wrong. Retrying an
		// unchanged bad request is how a poison statement loops forever.
		e.Retryable = false
		if e.Classification == "" {
			e.Classification = "bad_request"
		}
	}
	if e.Classification == "" {
		e.Classification = "clickhouse_error"
	}
	recordOutcome(e.Outcome, e.Classification)
	return e
}

// classifyTransport decides the COMMIT STATE of a failure that happened before
// any response was parsed. This is the hardest judgement in the package and the
// stdlib does not make it easy: net/http does not tell us how much of the
// request body reached the server.
//
// So the rule is asymmetric on purpose. We claim Rejected only for failures
// that provably happened BEFORE the server could have seen the body — a refused
// connection, an unresolvable host. Everything else (deadline exceeded, reset
// mid-flight, EOF) is Unknown, because "we timed out waiting for the answer"
// and "the insert applied and we missed the ack" are the same observation.
//
// Erring toward Unknown is the safe direction: Unknown forbids both silent loss
// and a blind non-idempotent retry, whereas a wrong Rejected causes duplicates.
func classifyTransport(op string, err error) *Error {
	e := &Error{Op: op, Message: err.Error(), Retryable: true, wrapped: err}

	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		// Nothing was listening: the body cannot have been read.
		e.Outcome, e.Classification = OutcomeRejected, "transport_refused"
	case isDNSFailure(err):
		// We never opened a connection.
		e.Outcome, e.Classification = OutcomeRejected, "transport_dns"
	case errors.Is(err, context.Canceled):
		e.Outcome, e.Classification = OutcomeUnknown, "context_canceled"
		e.Retryable = false // the caller went away; do not retry on its behalf
	case errors.Is(err, context.DeadlineExceeded), os.IsTimeout(err):
		e.Outcome, e.Classification = OutcomeUnknown, "timeout"
	default:
		// Connection reset, unexpected EOF, broken pipe: the request may have
		// been delivered in full.
		e.Outcome, e.Classification = OutcomeUnknown, "response_lost"
	}
	recordOutcome(e.Outcome, e.Classification)
	return e
}

func isDNSFailure(err error) bool {
	var d *net.DNSError
	return errors.As(err, &d)
}

// ── metrics (Phase 8) ──────────────────────────────────────────────────────
//
// Package-level counters, because the adapter constructs a Client per call
// (clickhouse_client.go chClientFor) so per-Client state would not aggregate.
// The backend's /metrics handler reads Snapshot() and exposes it, giving the
// operator per-outcome visibility into every ClickHouse write the seam carries —
// the observability F-56/F-38 were invisible for want of.
var (
	mCommitted atomic.Int64
	mRejected  atomic.Int64
	mUnknown   atomic.Int64
	mByClass   sync.Map // classification string -> *atomic.Int64
)

func recordOutcome(o Outcome, classification string) {
	switch o {
	case OutcomeCommitted:
		mCommitted.Add(1)
	case OutcomeRejected:
		mRejected.Add(1)
	default:
		mUnknown.Add(1)
	}
	if classification == "" {
		return
	}
	v, _ := mByClass.LoadOrStore(classification, new(atomic.Int64))
	v.(*atomic.Int64).Add(1)
}

// MetricsSnapshot is a point-in-time read of the seam's outcome counters.
type MetricsSnapshot struct {
	Committed int64
	Rejected  int64
	Unknown   int64
	ByClass   map[string]int64
}

// Snapshot returns the current counters for exposition.
func Snapshot() MetricsSnapshot {
	m := MetricsSnapshot{
		Committed: mCommitted.Load(),
		Rejected:  mRejected.Load(),
		Unknown:   mUnknown.Load(),
		ByClass:   map[string]int64{},
	}
	mByClass.Range(func(k, v any) bool {
		m.ByClass[k.(string)] = v.(*atomic.Int64).Load()
		return true
	})
	return m
}

// ── retry orchestration (Phase 3) ──────────────────────────────────────────

// RetryPolicy bounds an ExecWithRetry loop. Zero values disable retry (one
// attempt), so a caller must opt in explicitly.
type RetryPolicy struct {
	MaxAttempts int           // total attempts including the first; <=1 means no retry
	BaseDelay   time.Duration // first backoff; doubles each attempt
	MaxDelay    time.Duration // backoff ceiling
	// JitterFrac in [0,1): the delay is multiplied by (1 - frac/2 + rand*frac),
	// spreading retries so a fleet does not thunder-herd a recovering server.
	JitterFrac float64
}

// DefaultRetry is a sane bounded policy for an idempotent insert.
var DefaultRetry = RetryPolicy{MaxAttempts: 4, BaseDelay: 200 * time.Millisecond, MaxDelay: 5 * time.Second, JitterFrac: 0.5}

// ExecWithRetry runs Exec and retries ONLY on a classified-retryable failure,
// with bounded exponential backoff + jitter. The payload is byte-identical on
// every attempt (the same Request), which is the idempotency contract this
// relies on:
//
//   - SAFE for tables that dedup a re-insert (ReplacingMergeTree, or a
//     deterministic PK the engine collapses). The correlation writes use
//     deterministic signal/object ids for exactly this reason.
//   - For a NON-idempotent table (plain MergeTree with no dedup), a retry after
//     an UNKNOWN outcome can duplicate rows — which is why Unknown is retried
//     the SAME bytes, never rebuilt into a different batch, and why the caller,
//     not this package, decides whether its table is safe to retry. Pass
//     RetryPolicy{} (no retry) when it is not.
//
// randFn is injectable for deterministic tests; nil uses a time-seeded source.
func (c *Client) ExecWithRetry(ctx context.Context, req Request, p RetryPolicy, randFn func() float64) ([]byte, error) {
	attempts := p.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	if randFn == nil {
		r := rand.New(rand.NewSource(time.Now().UnixNano())) // #nosec G404 -- jitter, not crypto
		randFn = r.Float64
	}
	var body []byte
	var err error
	delay := p.BaseDelay
	for attempt := 1; attempt <= attempts; attempt++ {
		body, err = c.Exec(ctx, req)
		if err == nil || !Retryable(err) || attempt == attempts {
			return body, err
		}
		// jittered sleep, cancellable.
		d := delay
		if p.JitterFrac > 0 {
			f := p.JitterFrac
			d = time.Duration(float64(delay) * (1 - f/2 + randFn()*f))
		}
		select {
		case <-ctx.Done():
			return nil, &Error{Op: req.Op, Message: "retry aborted: " + ctx.Err().Error(),
				Outcome: OutcomeUnknown, Classification: "context_canceled", wrapped: ctx.Err()}
		case <-time.After(d):
		}
		if delay = delay * 2; p.MaxDelay > 0 && delay > p.MaxDelay {
			delay = p.MaxDelay
		}
	}
	return body, err
}

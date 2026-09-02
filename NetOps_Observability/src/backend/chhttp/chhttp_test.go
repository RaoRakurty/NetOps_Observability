package chhttp

// chhttp_test.go — the fault-injection suite for the ClickHouse seam.
//
// This is the test that INVARIANTS.md §1 recorded as missing. Until now the
// ClickHouse invariant ("writes check their status") was enforced by a source
// scan: architecture_guards_test.go grepped each file for the word
// "StatusCode". That proves the check is WRITTEN. It cannot prove the check
// BEHAVES — a `if resp.StatusCode != 200 {}` with an empty body passes a grep
// and drops the write.
//
// Every test below fires a real failure at a real client and asserts what the
// caller is told. The kv, bus, notification, audit and credential seams already
// had this; ClickHouse was the last one without it, and the one with the worst
// measured record (F-38: 19 of 20 insert sites discarded the failure).

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(t *testing.T, h http.HandlerFunc) (*Client, func()) {
	t.Helper()
	srv := httptest.NewServer(h)
	return &Client{Base: srv.URL, User: "netops", Password: "x", HTTP: srv.Client()}, srv.Close
}

func mustExecErr(t *testing.T, c *Client, req Request) *Error {
	t.Helper()
	_, err := c.Exec(context.Background(), req)
	if err == nil {
		t.Fatal("expected an error, got nil — a failed ClickHouse call reported success (F-38)")
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("expected *chhttp.Error, got %T: %v", err, err)
	}
	return e
}

// --- the headline case ------------------------------------------------------

// TestTooManyPartsIsRetryableDespiteHTTP500 is the case that justifies the
// whole package. ClickHouse reports insert backpressure as HTTP 500 with
// exception code 252 — indistinguishable, at the status line, from a permanent
// schema bug that also arrives as 500. A status-only classifier gets exactly
// one of the two wrong no matter which way it guesses.
func TestTooManyPartsIsRetryableDespiteHTTP500(t *testing.T) {
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Code: 252. DB::Exception: Too many parts (300). Merges are processing significantly slower than inserts."))
	})
	defer done()

	e := mustExecErr(t, c, Request{SQL: "INSERT INTO netops.flows VALUES", Op: "insert flows", Scope: "__all__"})
	if e.Code != codeTooManyParts {
		t.Errorf("exception code = %d, want %d (TOO_MANY_PARTS)", e.Code, codeTooManyParts)
	}
	if !e.Retryable {
		t.Error("TOO_MANY_PARTS must be retryable: it is transient insert pressure. " +
			"Treating it as permanent drops data that would have landed on the next attempt.")
	}
}

// TestSchemaBugIsNotRetryable is the other half of the same 500. If this and
// the test above ever agree, the classifier has stopped classifying.
func TestSchemaBugIsNotRetryable(t *testing.T) {
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Code: 16. DB::Exception: No such column tenant_id in table netops.flows"))
	})
	defer done()

	e := mustExecErr(t, c, Request{SQL: "INSERT INTO netops.flows VALUES", Op: "insert flows", Scope: "__all__"})
	if e.Retryable {
		t.Error("NO_SUCH_COLUMN must NOT be retryable — the statement is wrong and " +
			"will be wrong on every attempt. Retrying turns a schema bug into a hot loop.")
	}
}

// TestUnknownSettingIsReportedNotSwallowed is F-56 exactly: an insert-tolerance
// setting this server does not know 400s the WHOLE batch.
func TestUnknownSettingIsReportedNotSwallowed(t *testing.T) {
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Code: 115. DB::Exception: Unknown setting input_format_skip_unknown_fields"))
	})
	defer done()

	e := mustExecErr(t, c, Request{
		SQL: "INSERT INTO netops.tunnels VALUES", Op: "insert tunnels", Scope: "__all__",
		Settings: map[string]string{"input_format_skip_unknown_fields": "1"},
	})
	if e.Code != codeUnknownSetting {
		t.Errorf("code = %d, want %d (UNKNOWN_SETTING)", e.Code, codeUnknownSetting)
	}
	if e.Retryable {
		t.Error("an unknown setting is a config error, not a transient")
	}
	if !strings.Contains(e.Error(), "115") {
		t.Errorf("error text must name the code so a log identifies the cause: %q", e.Error())
	}
}

// --- the taxonomy -----------------------------------------------------------

func TestFailureTaxonomy(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		body      string
		retryable bool
	}{
		{"auth failure after password rotation", 403, "Code: 516. DB::Exception: Authentication failed", false},
		{"unknown table", 404, "Code: 60. DB::Exception: Table netops.gone does not exist", false},
		{"memory limit under load", 500, "Code: 241. DB::Exception: Memory limit exceeded", true},
		{"too many simultaneous queries", 500, "Code: 202. DB::Exception: Too many simultaneous queries", true},
		{"disk full", 500, "Code: 243. DB::Exception: Not enough space", true},
		{"429 backpressure, no code", 429, "slow down", true},
		{"503 restarting, no code", 503, "", true},
		{"unrecognised 500", 500, "something opaque", true},
		{"plain 400, no code", 400, "malformed", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			defer done()

			e := mustExecErr(t, c, Request{SQL: "SELECT 1", Op: "probe", Scope: "__all__"})
			if e.Retryable != tc.retryable {
				t.Errorf("Retryable = %v, want %v (HTTP %d, body %q)",
					e.Retryable, tc.retryable, tc.status, tc.body)
			}
			if e.Status != tc.status {
				t.Errorf("Status = %d, want %d", e.Status, tc.status)
			}
		})
	}
}

// --- transport-level faults -------------------------------------------------

func TestTransportFailureIsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	c := &Client{Base: srv.URL, HTTP: srv.Client()}
	srv.Close() // the endpoint is now refusing connections

	e := mustExecErr(t, c, Request{SQL: "SELECT 1", Op: "probe", Scope: "__all__"})
	if !e.Retryable {
		t.Error("a refused connection is transient — ClickHouse may simply be restarting")
	}
	if e.Status != 0 {
		t.Errorf("Status = %d, want 0: there was no HTTP response to have a status", e.Status)
	}
}

func TestHangingServerIsBoundedByContext(t *testing.T) {
	release := make(chan struct{})
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		<-release // never answer until the test says so
	})
	defer func() { close(release); done() }()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := c.Exec(ctx, Request{SQL: "SELECT sleep(9)", Op: "probe", Scope: "__all__"})
	if err == nil {
		t.Fatal("a hung ClickHouse must not hang the caller forever")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("took %v — the context deadline was not honoured", elapsed)
	}
}

// TestConnectionResetMidBodyIsNotSilentTruncation: the server promises 200 and
// a long body, then dies. Returning the prefix as a successful read would be a
// partial answer wearing a success — the shape F-67 was.
func TestConnectionResetMidBodyIsNotSilentTruncation(t *testing.T) {
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1048576")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic(http.ErrAbortHandler) // kill the connection mid-body
	})
	defer done()

	_, err := c.Exec(context.Background(), Request{SQL: "SELECT 1", Op: "probe", Scope: "__all__"})
	if err == nil {
		t.Fatal("a body that died mid-read must not be returned as a complete answer")
	}
}

// --- guards on the request itself -------------------------------------------

// TestOversizeResponseIsRefusedNotTruncated: a 200 whose body hits the cap.
func TestOversizeResponseIsRefusedNotTruncated(t *testing.T) {
	big := strings.Repeat("x", 4096)
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(big))
	})
	defer done()

	_, err := c.Exec(context.Background(), Request{
		SQL: "SELECT 1", Op: "probe", Scope: "__all__", MaxBytes: 1024,
	})
	if err == nil {
		t.Fatal("a truncated response must be an error, never a short success")
	}
	if !strings.Contains(err.Error(), "narrow the query") {
		t.Errorf("the error should tell the operator what to do: %q", err)
	}
}

// TestScopeIsRequired — CLAUDE.md §3a. Every default is wrong: "__all__"
// silently defeats tenant isolation, "__none__" silently returns nothing.
func TestScopeIsRequired(t *testing.T) {
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("the request should never have been sent — Scope was empty")
	})
	defer done()

	_, err := c.Exec(context.Background(), Request{SQL: "SELECT 1", Op: "probe"})
	if !errors.Is(err, ErrScopeRequired) {
		t.Fatalf("an unscoped request must be refused before it is sent, got %v", err)
	}
}

func TestMissingEndpointIsAnErrorNotANoOp(t *testing.T) {
	c := &Client{}
	_, err := c.Exec(context.Background(), Request{SQL: "SELECT 1", Op: "probe", Scope: "__all__"})
	if !errors.Is(err, ErrNoEndpoint) {
		t.Fatalf("an unconfigured endpoint must be reported, not silently skipped: %v", err)
	}
}

// --- the settings actually reach the wire -----------------------------------

// TestRequestSettingsReachTheWire proves the tolerance/scope/attribution params
// are really sent. F-56 was "no site sets insert tolerance"; a settings map
// that never reached ClickHouse would reproduce it with extra steps.
func TestRequestSettingsReachTheWire(t *testing.T) {
	var got atomic.Value
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.URL.Query())
		user, pass, _ := r.BasicAuth()
		if user != "netops" || pass != "x" {
			t.Errorf("basic auth not sent: %q/%q", user, pass)
		}
	})
	defer done()

	_, err := c.Exec(context.Background(), Request{
		SQL: "INSERT INTO netops.flows VALUES", Op: "insert flows",
		Scope: "tenant-a", LogComment: "worker:flows", Profile: "hot_ui",
		Settings: map[string]string{"input_format_skip_unknown_fields": "1"},
		Budget:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	q, _ := got.Load().(url.Values)
	want := map[string]string{
		"tenant_scope":                     "tenant-a",
		"log_comment":                      "worker:flows",
		"profile":                          "hot_ui",
		"input_format_skip_unknown_fields": "1",
		"max_execution_time":               "5",
		"cancel_http_readonly_queries_on_client_close": "1",
	}
	for k, v := range want {
		if len(q[k]) == 0 || q[k][0] != v {
			t.Errorf("query param %s = %v, want %q", k, q[k], v)
		}
	}
}

// TestProfileIsSentBeforePerQuerySettings pins the ORDER, which url.Values.Get
// cannot see and which is the entire bug behind tracker 186 fix-3.
//
// ClickHouse applies HTTP query parameters left to right, and `profile=` assigns
// every setting its profile declares — so a per-query setting emitted before it
// is discarded. Encode() sorts alphabetically, which put max_memory_usage (m)
// and max_execution_time (m) ahead of profile (p) every single time: the
// timeintel backfill asked for 512 MiB and 2,250 consecutive queries ran at the
// background lane's 2 GiB. Asserting the presence of a param is not enough;
// this asserts where it sits.
func TestProfileIsSentBeforePerQuerySettings(t *testing.T) {
	var raw atomic.Value
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		raw.Store(r.URL.RawQuery)
	})
	defer done()

	_, err := c.Exec(context.Background(), Request{
		SQL: "SELECT 1", Op: "order probe", Scope: "tenant-a",
		LogComment: "worker:timeintel-backfill", Profile: "background",
		Settings: map[string]string{"max_memory_usage": "536870912"},
		Budget:   7 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	q, _ := raw.Load().(string)
	prof := strings.Index(q, "profile=")
	if prof != 0 {
		t.Fatalf("profile= must be the FIRST parameter so the lane defaults are applied before the caller's settings; RawQuery = %q", q)
	}
	// Every setting the profile could also declare has to land after it. The two
	// the `background` profile actually declares are called out by name because
	// they are the ones that were silently lost.
	for _, k := range []string{"max_memory_usage=", "max_execution_time="} {
		at := strings.Index(q, k)
		if at < 0 {
			t.Fatalf("%s missing from %q", k, q)
		}
		if at < prof {
			t.Errorf("%s at %d precedes profile= at %d — the profile would overwrite it", k, at, prof)
		}
	}
	// And the profile is still parsed as a normal parameter, exactly once.
	vals, err := url.ParseQuery(q)
	if err != nil {
		t.Fatalf("RawQuery %q is not parseable: %v", q, err)
	}
	if got := vals["profile"]; len(got) != 1 || got[0] != "background" {
		t.Errorf("profile param = %v, want exactly one \"background\"", got)
	}
}

// TestSuccessReturnsTheBody — the happy path still has to work.
func TestSuccessReturnsTheBody(t *testing.T) {
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("1\n2\n3\n"))
	})
	defer done()

	body, err := c.Exec(context.Background(), Request{SQL: "SELECT 1", Op: "probe", Scope: "__all__"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(body) != "1\n2\n3\n" {
		t.Errorf("body = %q", body)
	}
}

// TestRetryableOnForeignErrorIsFalse — an error from outside this package must
// never be assumed retryable. Guessing "yes" on an unknown failure is how a
// poison statement becomes an infinite loop.
func TestRetryableOnForeignErrorIsFalse(t *testing.T) {
	if Retryable(errors.New("something else entirely")) {
		t.Error("a non-chhttp error must not be classified as retryable")
	}
	if Retryable(nil) {
		t.Error("nil is not a retryable failure")
	}
}

// TestMetricsRecordOutcomes proves the Phase 8 counters move on real calls —
// committed on success, rejected with a class on a server refusal.
func TestMetricsRecordOutcomes(t *testing.T) {
	before := Snapshot()

	okSrv, done1 := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("1\n"))
	})
	defer done1()
	if _, err := okSrv.Exec(context.Background(), Request{SQL: "SELECT 1", Op: "probe", Scope: "__all__"}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}

	badSrv, done2 := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Code: 252. DB::Exception: Too many parts"))
	})
	defer done2()
	_, _ = badSrv.Exec(context.Background(), Request{SQL: "INSERT INTO netops.x VALUES", Op: "ins", Scope: "__all__"})

	after := Snapshot()
	if after.Committed <= before.Committed {
		t.Errorf("committed counter did not advance (%d → %d)", before.Committed, after.Committed)
	}
	if after.Rejected <= before.Rejected {
		t.Errorf("rejected counter did not advance (%d → %d)", before.Rejected, after.Rejected)
	}
	if after.ByClass["too_many_parts"] <= before.ByClass["too_many_parts"] {
		t.Errorf("too_many_parts class counter did not advance")
	}
}

// TestExecWithRetryRecoversTransient: a server that fails N times with a
// retryable code then succeeds must be recovered within budget, sending the
// SAME payload each time.
func TestExecWithRetryRecoversTransient(t *testing.T) {
	var calls atomic.Int32
	var payloads sync.Map
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		payloads.Store(string(b), true)
		if calls.Add(1) <= 2 { // fail twice (TOO_MANY_PARTS), then succeed
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Code: 252. DB::Exception: Too many parts"))
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	defer done()

	p := RetryPolicy{MaxAttempts: 4, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond, JitterFrac: 0.5}
	_, err := c.ExecWithRetry(context.Background(), Request{SQL: "INSERT INTO netops.x VALUES(1)", Op: "ins", Scope: "__all__"},
		p, func() float64 { return 0.5 })
	if err != nil {
		t.Fatalf("should have recovered within budget: %v", err)
	}
	if calls.Load() != 3 {
		t.Errorf("expected 3 attempts (2 fail + 1 ok), got %d", calls.Load())
	}
	// exactly one distinct payload was ever sent — byte-identical retries.
	n := 0
	payloads.Range(func(_, _ any) bool { n++; return true })
	if n != 1 {
		t.Errorf("retry sent %d distinct payloads, want 1 (byte-identical)", n)
	}
}

// TestExecWithRetryDoesNotRetryPermanent: a schema fault must fail on the first
// attempt — retrying an unchanged bad statement loops forever.
func TestExecWithRetryDoesNotRetryPermanent(t *testing.T) {
	var calls atomic.Int32
	c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Code: 16. DB::Exception: No such column"))
	})
	defer done()

	_, err := c.ExecWithRetry(context.Background(), Request{SQL: "INSERT INTO netops.x VALUES", Op: "ins", Scope: "__all__"},
		DefaultRetry, func() float64 { return 0.5 })
	if err == nil {
		t.Fatal("expected permanent failure")
	}
	if calls.Load() != 1 {
		t.Errorf("permanent failure retried %d times — must be exactly 1", calls.Load())
	}
}

// TestAnalysisTypeFaultsAreNotRetryable pins the deterministic ANALYSIS-time
// faults on the permanent side of the 500 that transient backpressure also
// arrives on. These are produced by the query's TYPES, before a row is read:
// the same statement fails identically forever, on an empty table as readily as
// a full one, so a retry only multiplies the failure and the operator's error
// string says "(retryable)" about something that can never heal.
//
// The three bodies are the ones this platform actually measured:
// 386 from the alias-shadowing undetermined-frequency read, 43 from the
// timeintel pick's cursor tuple (tracker 186 hotfix), and 184 from an aggregate
// output alias resolved into a WHERE (the cloud seam-telemetry read).
func TestAnalysisTypeFaultsAreNotRetryable(t *testing.T) {
	cases := []struct {
		name           string
		body           string
		code           int
		classification string
	}{
		{
			"no supertype (alias-shadowed window predicate)",
			"Code: 386. DB::Exception: There is no supertype for types String, DateTime because some of them are String/FixedString/Enum and some of them are not. (NO_COMMON_TYPE)",
			codeNoCommonType, "schema_no_common_type",
		},
		{
			"illegal type of argument (cursor tuple across a String alias)",
			"Code: 43. DB::Exception: No operation greater between String and DateTime64(3, 'UTC'). (ILLEGAL_TYPE_OF_ARGUMENT)",
			codeIllegalTypeOfArgument, "schema_illegal_type",
		},
		{
			"aggregate resolved into WHERE",
			"Code: 184. DB::Exception: Aggregate function argMax(kind, ts) AS kind is found in WHERE in query. (ILLEGAL_AGGREGATION)",
			codeIllegalAggregation, "schema_illegal_aggregation",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError) // the same 500 TOO_MANY_PARTS arrives on
				_, _ = w.Write([]byte(tc.body))
			})
			defer done()

			e := mustExecErr(t, c, Request{SQL: "SELECT 1", Op: "probe", Scope: "__all__"})
			if e.Code != tc.code {
				t.Fatalf("code = %d, want %d", e.Code, tc.code)
			}
			if e.Retryable {
				t.Error("a deterministic type fault must NOT be retryable — it cannot heal, " +
					"and retrying it burns the caller's budget on a statement that is simply wrong")
			}
			if e.Classification != tc.classification {
				t.Errorf("classification = %q, want %q — an alert must say the types are wrong, not %q",
					e.Classification, tc.classification, "server_error")
			}
			if Retryable(e) {
				t.Error("the package-level Retryable() must agree with the classification")
			}
		})
	}
}

// TestReadBudgetFaultIsPermanentButUnknown5xxStillRetries pins BOTH halves of
// tracker 207 in one table, because fixing one half by breaking the other is
// the easy mistake here.
//
// Half one: code 307 TOO_MANY_BYTES is a `max_bytes_to_read` breach. It arrives
// on the same HTTP 500 that TOO_MANY_PARTS backpressure arrives on, and before
// this row it was in neither code map — so it fell through the "status >= 500 →
// retry the unknown" default and the caller was told "(retryable)" about a
// statement that reads the same bytes and breaches the same ceiling forever.
//
// Half two: that default MUST still stand for a genuinely unrecognised 5xx.
// Naming 307 is a one-code addition, not a narrowing of the fallback: an
// unlisted server-side code we know nothing about is still safer to retry, and
// the caller's backoff bounds the cost. If this case ever goes red, the
// classifier has stopped retrying things it should.
func TestReadBudgetFaultIsPermanentButUnknown5xxStillRetries(t *testing.T) {
	cases := []struct {
		name           string
		body           string
		code           int
		classification string
		retryable      bool
	}{
		{
			name:           "too many bytes (max_bytes_to_read breach)",
			body:           "Code: 307. DB::Exception: Limit for rows or bytes to read exceeded, max bytes: 1.00 GiB, current bytes: 1.34 GiB. (TOO_MANY_BYTES)",
			code:           codeTooManyBytes,
			classification: "too_many_bytes",
			retryable:      false,
		},
		{
			name:           "an unlisted server-side code still retries (the default is not narrowed)",
			body:           "Code: 999. DB::Exception: Some future ClickHouse failure this build has never seen.",
			code:           999,
			classification: "server_error",
			retryable:      true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, done := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError) // the same 500 TOO_MANY_PARTS arrives on
				_, _ = w.Write([]byte(tc.body))
			})
			defer done()

			e := mustExecErr(t, c, Request{SQL: "SELECT count() FROM netops.flows", Op: "probe", Scope: "__all__"})
			if e.Code != tc.code {
				t.Fatalf("code = %d, want %d", e.Code, tc.code)
			}
			if e.Retryable != tc.retryable {
				t.Errorf("Retryable = %v, want %v — a read-budget breach is deterministic and must not "+
					"be retried, while an unrecognised 5xx must still be", e.Retryable, tc.retryable)
			}
			if e.Classification != tc.classification {
				t.Errorf("classification = %q, want %q", e.Classification, tc.classification)
			}
			if Retryable(e) != tc.retryable {
				t.Errorf("package-level Retryable() = %v, want %v — it must agree with the classification",
					Retryable(e), tc.retryable)
			}
		})
	}
}

// TestTooManyBytesIsNotAlsoRetryable guards the maps themselves: a code in both
// tables would resolve by switch order, silently, and the behavioural test above
// would still pass for the wrong reason.
func TestTooManyBytesIsNotAlsoRetryable(t *testing.T) {
	if retryableCodes[codeTooManyBytes] {
		t.Error("307 TOO_MANY_BYTES must not appear in retryableCodes")
	}
	if !permanentCodes[codeTooManyBytes] {
		t.Error("307 TOO_MANY_BYTES must appear in permanentCodes")
	}
	if classificationFor[codeTooManyBytes] != "too_many_bytes" {
		t.Errorf("classification slug = %q, want \"too_many_bytes\"", classificationFor[codeTooManyBytes])
	}
	for code := range permanentCodes {
		if retryableCodes[code] {
			t.Errorf("code %d is in BOTH retryableCodes and permanentCodes — the classification is ambiguous", code)
		}
	}
}

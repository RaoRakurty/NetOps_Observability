// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// auth_store_pressure_test.go — tracker 322.
//
// THE DEFECT. On 2026-09-15 the lab box sat at 94 % disk with IO PSI ~64 %.
// `POST /api/auth/login` took 26 s and answered 500, while audit persistence
// logged `timeout: context deadline exceeded` in the same second. The same
// credentials returned 200 in 3 s a few minutes later. Nothing was broken: the
// store was saturated. A 500 tells the operator the server is defective and
// gives them nothing to do; the honest answer to "I could not complete this
// write in time" is 503 + Retry-After.
//
// These tests inject the saturation. The session and refresh stores both take
// an injectable KV (SetKVForTest), so a write that never lands is reproducible
// without a full disk.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"netops/backend/alerts"
	"netops/backend/internal/session"
)

// pressureKV is a session/refresh KV whose durable write always fails with a
// caller-supplied error — a stand-in for a pool that cannot hand out a
// connection inside the deadline, or a disk that will not answer.
type pressureKV struct{ err error }

func (p pressureKV) Load(string) ([]byte, error) { return nil, os.ErrNotExist }
func (p pressureKV) Save(string, []byte) error   { return p.err }

// pressureTimeoutErr is a net.Error that reports a timeout, which is how a
// driver's own dial/read deadline surfaces.
type pressureTimeoutErr struct{}

func (pressureTimeoutErr) Error() string   { return "read tcp 10.0.0.2:5432: operation timed out" }
func (pressureTimeoutErr) Timeout() bool   { return true }
func (pressureTimeoutErr) Temporary() bool { return true }

// loginRecorder drives handleLogin directly so the RESPONSE HEADERS (Retry-After)
// are assertable, not just the body.
func loginRecorder(t *testing.T, s *server, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"username":"` + user + `","password":"` + pass + `"}`
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.handleLogin(w, r)
	return w
}

func loginErrorBody(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("response body is not JSON (%q): %v", w.Body.String(), err)
	}
	msg, _ := out["error"].(string)
	return msg
}

// ── the classifier ──────────────────────────────────────────────────────────

// TestStoreUnderPressureClassifiesOnlyTransientFailures pins the WHOLE
// taxonomy in one place. The rule that matters is the negative one: a
// programming error and a corrupt row must stay 500, or the 503 stops meaning
// "retry" and starts meaning "something went wrong, who knows what".
func TestStoreUnderPressureClassifiesOnlyTransientFailures(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		// Transient: the store could not answer IN TIME or AT ALL right now.
		{"nil is not a failure at all", nil, false},
		{"context deadline", context.DeadlineExceeded, true},
		{"wrapped context deadline", fmt.Errorf("session create: %w", context.DeadlineExceeded), true},
		{"context cancelled", context.Canceled, true},
		{"os deadline", os.ErrDeadlineExceeded, true},
		{"net timeout", pressureTimeoutErr{}, true},
		{"pgx pool timeout text", errors.New("timeout: context deadline exceeded"), true},
		{"connection refused", errors.New("dial tcp 127.0.0.1:5432: connect: connection refused"), true},
		{"connection reset", errors.New("write tcp 10.0.0.1:5432: connection reset by peer"), true},
		{"io timeout", errors.New("read tcp 10.0.0.1:5432: i/o timeout"), true},
		{"pool exhausted", errors.New("acquire: pool exhausted"), true},
		{"too many clients", errors.New("FATAL: sorry, too many clients already (SQLSTATE 53300)"), true},
		{"database starting up", errors.New("FATAL: the database system is starting up"), true},
		{"statement timeout", errors.New("ERROR: canceling statement due to statement timeout"), true},
		// NOT transient: a defect, a corruption, or a condition no retry fixes.
		{"programming error", errors.New("session store is not initialised"), false},
		{"corrupt row", errors.New("corrupt session record: invalid character 'q' looking for beginning of value"), false},
		{"schema fault", errors.New("ERROR: relation \"sessions\" does not exist (SQLSTATE 42P01)"), false},
		{"permission denied", errors.New("open /data/sessions.json: permission denied"), false},
		// A full disk is NOT transient on purpose: retrying in five seconds
		// cannot help, and "the system is busy, try again shortly" would be a
		// lie. It stays a 500 and the operator gets the cause from the log.
		{"disk full", errors.New("write /data/sessions.json: no space left on device"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := storeUnderPressure(c.err); got != c.want {
				t.Errorf("storeUnderPressure(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// A wrapper that keeps a SAFE public sentence while carrying the driver's text
// underneath must still classify on the cause. This is the shape
// enforceConcurrentLoginDeny returns: the caller must never see the store's
// own words, and the classifier must never lose them.
func TestStoreUnderPressureSeesThroughASafePublicWrapper(t *testing.T) {
	wrapped := &loginStoreError{
		public: "sign-in could not be completed; prior sessions could not be closed",
		cause:  context.DeadlineExceeded,
	}
	if !storeUnderPressure(wrapped) {
		t.Fatal("a public-sentence wrapper hid a context deadline from the classifier — " +
			"the 503 path would never fire for the concurrent-login revoke")
	}
	if strings.Contains(wrapped.Error(), "deadline") {
		t.Errorf("the PUBLIC sentence leaked the cause: %q", wrapped.Error())
	}
}

// ── the handler ─────────────────────────────────────────────────────────────

// The headline defect: correct credentials + a saturated session store = 503,
// not 500, and the client is told when to come back.
func TestLoginUnderStorePressureAnswers503WithRetryAfter(t *testing.T) {
	_, s := newTestServerState(t)

	// Healthy first, so the assertion below is about the pressure and not about
	// a broken fixture.
	if w := loginRecorder(t, s, seedUser, seedPass); w.Code != http.StatusOK {
		t.Fatalf("healthy login = %d, want 200 (body %s)", w.Code, w.Body.String())
	}

	s.sessions.SetKVForTest(pressureKV{err: fmt.Errorf("timeout: %w", context.DeadlineExceeded)})

	w := loginRecorder(t, s, seedUser, seedPass)
	if w.Code == http.StatusInternalServerError {
		t.Fatalf("a saturated session store still answers 500 — tracker 322 (body %s)", w.Body.String())
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("login under store pressure = %d, want 503", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After on the 503 — the client cannot know when to retry")
	}
}

// §8/§10: the detail goes to the log, the caller gets a sentence. A 503 body
// that names the store, the deadline or a path is an infrastructure disclosure
// to an endpoint reachable before authentication is complete.
func TestBusyLoginRefusalLeaksNothingInternal(t *testing.T) {
	_, s := newTestServerState(t)
	s.sessions.SetKVForTest(pressureKV{err: errors.New("dial tcp 172.18.0.9:5432: connect: connection refused")})

	w := loginRecorder(t, s, seedUser, seedPass)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	msg := strings.ToLower(loginErrorBody(t, w))
	if !strings.Contains(msg, "busy") {
		t.Errorf("the 503 must say, in plain language, that the system is busy — got %q", msg)
	}
	for _, leak := range []string{
		"deadline", "timeout", "context", "store", "session", "postgres", "sql",
		"tcp", "dial", "refused", "/data", ".json", "kv", "172.18",
	} {
		if strings.Contains(msg, leak) {
			t.Errorf("the 503 body leaks %q: %q", leak, msg)
		}
	}
}

// The refresh-token persist is the OTHER durable write on the session path, and
// it fails the same way under the same pressure.
func TestLoginAnswers503WhenTheRefreshTokenCannotPersist(t *testing.T) {
	_, s := newTestServerState(t)
	s.refresh.SetKVForTest(pressureKV{err: context.DeadlineExceeded})

	w := loginRecorder(t, s, seedUser, seedPass)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("refresh-token persist under pressure = %d, want 503 (body %s)", w.Code, w.Body.String())
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After on the refresh-persist 503")
	}
}

// A genuine authentication failure is NOT store pressure, even while the store
// IS under pressure. The password is checked before any session write, so this
// must stay 401 — a 503 here would tell an attacker that guessing is pointless
// right now, and would tell an operator with a typo to "try again shortly".
func TestWrongPasswordUnderStorePressureIsStill401(t *testing.T) {
	_, s := newTestServerState(t)
	s.sessions.SetKVForTest(pressureKV{err: context.DeadlineExceeded})

	w := loginRecorder(t, s, seedUser, "not-the-password")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password under store pressure = %d, want 401", w.Code)
	}
}

// A corrupt row is a defect, not pressure: it must keep its 500, because a 503
// invites a retry that will fail identically forever.
func TestCorruptStoreStateStays500(t *testing.T) {
	_, s := newTestServerState(t)
	s.sessions.SetKVForTest(pressureKV{
		err: errors.New("corrupt session record: invalid character 'q' looking for beginning of value"),
	})

	w := loginRecorder(t, s, seedUser, seedPass)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("a corrupt-state failure = %d, want 500 — only TRANSIENT pressure earns a 503", w.Code)
	}
	// And the 500 must not hand the caller the store's own words either.
	msg := strings.ToLower(loginErrorBody(t, w))
	for _, leak := range []string{"invalid character", "corrupt session record", ".json"} {
		if strings.Contains(msg, leak) {
			t.Errorf("the 500 body leaks %q: %q", leak, msg)
		}
	}
}

// ── lock-out interaction ────────────────────────────────────────────────────

// A 503 is the SERVER's failure, not a failed sign-in attempt by the operator.
// If it counted towards the lockout, an outage would lock out every operator
// trying to reach the console during the incident — the exact moment they need
// it. Proven the only way that counts: refuse many times, then heal, and the
// account must still sign in.
func TestBusyRefusalDoesNotCountTowardsLockout(t *testing.T) {
	_, s := newTestServerState(t)
	s.sessions.SetKVForTest(pressureKV{err: context.DeadlineExceeded})

	for i := 0; i < 8; i++ { // comfortably past any default lockout threshold
		w := loginRecorder(t, s, seedUser, seedPass)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("attempt %d = %d, want 503", i+1, w.Code)
		}
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d was locked out — a busy server counted as a failed sign-in", i+1)
		}
	}

	s.sessions.SetKVForTest(platformKV{}) // the store recovers
	w := loginRecorder(t, s, seedUser, seedPass)
	if w.Code == http.StatusTooManyRequests {
		t.Fatal("LOCKED OUT BY AN OUTAGE: 8 server-side 503s locked the account — " +
			"refuseWhileLocked must never see a busy refusal")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("login after the store recovered = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
}

// ── audit ───────────────────────────────────────────────────────────────────

// From the operator's point of view a refused sign-in is a failed sign-in, and
// a trail that shows nothing for it cannot answer "why could nobody log in at
// 14:20". The row must also NAME the reason, so it is distinguishable from a
// bad password at a glance.
func TestBusyRefusalIsAudited(t *testing.T) {
	_, s := newTestServerState(t)
	s.sessions.SetKVForTest(pressureKV{err: context.DeadlineExceeded})

	if w := loginRecorder(t, s, seedUser, seedPass); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}

	events, err := s.audit.List("", true, auditQuery{Limit: 50})
	if err != nil {
		t.Fatalf("read the trail: %v", err)
	}
	for _, e := range events {
		if e.Method != "LOGIN" || e.Detail == nil {
			continue
		}
		if e.Detail["reason"] == loginRefusalStorePressure {
			if e.Decision != "deny" {
				t.Errorf("the busy refusal is recorded as %q, want deny", e.Decision)
			}
			return
		}
	}
	t.Fatalf("no LOGIN row with reason=%q in the trail — a sign-in refused by a busy "+
		"server is invisible to whoever investigates the outage (%d rows)",
		loginRefusalStorePressure, len(events))
}

// ── observability (§10) ─────────────────────────────────────────────────────

// An un-scraped counter is not observability. The refusals must be countable
// from outside, or "logins were failing for an hour" stays anecdotal.
func TestBusyRefusalIsCounted(t *testing.T) {
	_, s := newTestServerState(t)
	s.alerts = alerts.NewEngine("", nil)
	s.sessions.SetKVForTest(pressureKV{err: context.DeadlineExceeded})

	if w := loginRecorder(t, s, seedUser, seedPass); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}

	w := httptest.NewRecorder()
	s.handlePromMetrics(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	out := w.Body.String()
	const metric = "netops_login_store_pressure_refusals_total"
	if !strings.Contains(out, metric) {
		t.Fatalf("/metrics does not expose %s — tracker 322's failure mode stays invisible", metric)
	}
	if strings.Contains(out, metric+" 0\n") {
		t.Errorf("%s is still 0 after a refusal", metric)
	}
}

// Compile-time proof that the fault injector really is the store's KV seam.
var _ session.KV = pressureKV{}

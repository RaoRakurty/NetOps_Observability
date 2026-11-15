// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisaction

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- fixtures ---------------------------------------------------------------

type fakeITSM struct {
	calls atomic.Int32
	fail  error
}

func (f *fakeITSM) Describe(p ITSMNote) (string, string) {
	return "Add a note to " + p.System + " " + p.TicketRef, p.Title + "\n\n" + p.Note
}
func (f *fakeITSM) DryRun(_ context.Context, _ string, p ITSMNote) DryRun {
	return DryRun{Performed: true, OK: true, Description: "ticket " + p.TicketRef + " is open"}
}
func (f *fakeITSM) Execute(_ context.Context, _ string, p ITSMNote, key string) (Result, error) {
	f.calls.Add(1)
	if f.fail != nil {
		return Result{}, f.fail
	}
	return Result{ExternalRef: p.TicketRef, Message: "note added (" + key[:8] + ")"}, nil
}

type fakeMemory struct{ calls atomic.Int32 }

func (f *fakeMemory) Describe(p InvestigationNote) (string, string) {
	return "Save the finding for " + p.CorrelationID, p.Verdict
}
func (f *fakeMemory) DryRun(context.Context, string, InvestigationNote) DryRun {
	return DryRun{Description: "would save one finding"}
}
func (f *fakeMemory) Execute(context.Context, string, InvestigationNote, string) (Result, error) {
	f.calls.Add(1)
	return Result{Message: "saved"}, nil
}

var t0 = time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)

func onEnv() Env {
	return Env{Platform: true, Settings: Settings{Enabled: true, Kinds: []Kind{KindITSMNote, KindInvestigationNote}}}
}

func itsm() ITSMNote {
	return ITSMNote{System: SystemServiceNow, TicketRef: "INC0012345", CorrelationID: "corr-1",
		Title: "BGP peer down on edge-1", Note: "Iris finding: the peer went Idle after the WAN link flapped [ev-1]."}
}

func newSvc(t *testing.T) (*Service, *fakeITSM, *fakeMemory) {
	t.Helper()
	s := NewService(NewMemStore())
	now := t0
	s.Now = func() time.Time { return now }
	it, mem := &fakeITSM{}, &fakeMemory{}
	if err := Register[ITSMNote](s, KindITSMNote, it); err != nil {
		t.Fatal(err)
	}
	if err := Register[InvestigationNote](s, KindInvestigationNote, mem); err != nil {
		t.Fatal(err)
	}
	return s, it, mem
}

func propose(t *testing.T, s *Service, tenant string, p Payload) Request {
	t.Helper()
	out, err := s.Propose(context.Background(), tenant, onEnv(), Proposal{Payload: p, ProposedBy: "alice", Citations: []string{"ev-1"}})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	return out.Request
}

// ---- gate 2: the policy table ---------------------------------------------

func TestPolicyTable(t *testing.T) {
	cases := []struct {
		name string
		k    Kind
		env  Env
		want Decision
	}{
		{"unknown kind", Kind("device_config"), onEnv(), Deny},
		{"kill switch off", KindITSMNote, Env{Platform: false, Settings: onEnv().Settings}, Deny},
		{"workspace off", KindITSMNote, Env{Platform: true, Settings: Settings{Kinds: []Kind{KindITSMNote}}}, Deny},
		{"kind not allowed", KindITSMNote, Env{Platform: true, Settings: Settings{Enabled: true, Kinds: []Kind{KindInvestigationNote}}}, Deny},
		{"default allowlist is empty", KindInvestigationNote, Env{Platform: true, Settings: Settings{Enabled: true}}, Deny},
		{"dry run only", KindITSMNote, Env{Platform: true, Settings: Settings{Enabled: true, DryRunOnly: true, Kinds: []Kind{KindITSMNote}}}, DryRunOnly},
		{"approval", KindITSMNote, onEnv(), RequireApproval},
	}
	for _, c := range cases {
		if got, why := Evaluate(c.k, c.env); got != c.want || why == "" {
			t.Errorf("%s: got %s (%q), want %s", c.name, got, why, c.want)
		}
	}
}

// ALLOW (run without a person) is never the decision for a write, whatever
// the input.
func TestPolicyNeverAllowsAWrite(t *testing.T) {
	kinds := append(append([]Kind(nil), Kinds...), "", "device_config")
	for _, k := range kinds {
		for _, platform := range []bool{false, true} {
			for _, enabled := range []bool{false, true} {
				for _, dry := range []bool{false, true} {
					for _, allowed := range [][]Kind{nil, Kinds, {k}} {
						env := Env{Platform: platform, Settings: Settings{Enabled: enabled, DryRunOnly: dry, Kinds: allowed}}
						if d, _ := Evaluate(k, env); d == Allow {
							t.Fatalf("Evaluate(%q, %+v) = allow", k, env)
						}
					}
				}
			}
		}
	}
}

// ---- gate 1 / sealing: a device write cannot be expressed -------------------

func TestDevicePayloadsCannotDecode(t *testing.T) {
	hostile := []string{
		`{"system":"servicenow","ticket_ref":"INC0012345","correlation_id":"c","title":"t","note":"n","device_id":"core-1"}`,
		`{"system":"servicenow","ticket_ref":"INC0012345","correlation_id":"c","title":"t","note":"n","command":"reload"}`,
		`{"system":"servicenow","ticket_ref":"INC0012345","correlation_id":"c","title":"t","note":"n","host":"10.0.0.1"}`,
		`{"correlation_id":"c","verdict":"v","device":"edge-1"}`,
		`{"correlation_id":"c","verdict":"v","config":"interface Gi0/0 shutdown"}`,
	}
	for i, raw := range hostile {
		k := KindITSMNote
		if strings.Contains(raw, "verdict") {
			k = KindInvestigationNote
		}
		if _, err := DecodePayload(k, []byte(raw)); err == nil {
			t.Errorf("hostile payload %d decoded", i)
		}
	}
	if _, err := DecodePayload("device_config", []byte(`{}`)); err == nil {
		t.Error("an unknown kind decoded")
	}
	// The closed vocabulary is exactly the two product writes.
	if len(Kinds) != 2 || !ValidKind(KindITSMNote) || !ValidKind(KindInvestigationNote) || ValidKind("device_config") {
		t.Fatalf("the kind vocabulary changed: %v", Kinds)
	}
}

func TestRegisterRefusesMismatchedExecutor(t *testing.T) {
	s := NewService(NewMemStore())
	if err := Register[ITSMNote](s, KindInvestigationNote, &fakeITSM{}); err == nil {
		t.Error("an ITSM executor registered under investigation_note")
	}
	if err := Register[ITSMNote](s, Kind("device_config"), &fakeITSM{}); err == nil {
		t.Error("an executor registered under an unknown kind")
	}
	if s.Registered(KindInvestigationNote) || s.Registered("device_config") {
		t.Fatal("a refused registration took effect")
	}
}

func TestPayloadValidation(t *testing.T) {
	bad := []Payload{
		ITSMNote{System: "remedy", CorrelationID: "c", Title: "t", Note: "n"},
		ITSMNote{System: SystemServiceNow, TicketRef: "INC1/../x", CorrelationID: "c", Title: "t", Note: "n"},
		ITSMNote{System: SystemJira, TicketRef: "net-1", CorrelationID: "c", Title: "t", Note: "n"},
		ITSMNote{System: SystemServiceNow, CorrelationID: "c", Title: "t", Note: strings.Repeat("a", MaxNoteChars+1)},
		ITSMNote{System: SystemServiceNow, CorrelationID: "", Title: "t", Note: "n"},
		InvestigationNote{CorrelationID: "c", Verdict: ""},
		InvestigationNote{CorrelationID: "c", Verdict: "v", Citations: []string{"bad citation with spaces"}},
		nil,
	}
	for i, p := range bad {
		if err := Validate(p); !errors.Is(err, ErrInvalid) {
			t.Errorf("payload %d: want ErrInvalid, got %v", i, err)
		}
	}
	if err := Validate(itsm()); err != nil {
		t.Fatal(err)
	}
}

// ---- propose ---------------------------------------------------------------

func TestProposeDeniedStoresNothing(t *testing.T) {
	s, it, _ := newSvc(t)
	for _, env := range []Env{{}, {Platform: true}, {Platform: true, Settings: Settings{Enabled: true}}} {
		out, err := s.Propose(context.Background(), "acme", env, Proposal{Payload: itsm(), ProposedBy: "alice"})
		if !errors.Is(err, ErrDenied) || out.Decision != Deny {
			t.Fatalf("env %+v: want deny, got %v %s", env, err, out.Decision)
		}
	}
	if rs, _ := s.List(context.Background(), "acme", Filter{}); len(rs) != 0 || it.calls.Load() != 0 {
		t.Fatalf("a denied proposal left %d requests, %d sends", len(rs), it.calls.Load())
	}
}

func TestProposeStoresTheExactPayloadAndDedupes(t *testing.T) {
	s, it, _ := newSvc(t)
	r := propose(t, s, "acme", itsm())
	if r.Status != StatusProposed || r.Policy != RequireApproval || r.ProposedVia != "iris" || r.ProposedBy != "alice" {
		t.Fatalf("unexpected request %+v", r)
	}
	if !r.DryRun.Performed || !strings.Contains(r.Preview, "Iris finding") || !r.ExpiresAt.Equal(t0.Add(DefaultTTL)) {
		t.Fatalf("dry run / preview / expiry not recorded: %+v", r)
	}
	var back ITSMNote
	if err := json.Unmarshal(r.Payload, &back); err != nil || back != itsm() {
		t.Fatalf("payload did not round-trip: %v %+v", err, back)
	}
	out, err := s.Propose(context.Background(), "acme", onEnv(), Proposal{Payload: itsm(), ProposedBy: "bob"})
	if err != nil || !out.Existing || out.Request.ID != r.ID {
		t.Fatalf("second proposal for the same case should return the waiting one: %v %+v", err, out)
	}
	if it.calls.Load() != 0 {
		t.Fatal("proposing sent something")
	}
}

// ---- gates 3–5 -------------------------------------------------------------

func TestSelfApprovalIsRefused(t *testing.T) {
	s, it, _ := newSvc(t)
	r := propose(t, s, "acme", itsm())
	if _, err := s.Approve(context.Background(), "acme", "alice", onEnv(), r.ID, ""); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("want ErrSelfApproval, got %v", err)
	}
	if _, err := s.Approve(context.Background(), "acme", "", onEnv(), r.ID, ""); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("an anonymous approver: %v", err)
	}
	if it.calls.Load() != 0 {
		t.Fatal("a self-approval sent the note")
	}
}

func TestApprovalByAnotherPersonRunsOnceAndReplays(t *testing.T) {
	s, it, _ := newSvc(t)
	r := propose(t, s, "acme", itsm())
	got, err := s.Approve(context.Background(), "acme", "bob", onEnv(), r.ID, "matches the ticket")
	if err != nil || got.Status != StatusExecuted || got.DecidedBy != "bob" || got.Result == nil || got.ExecutedAt == nil {
		t.Fatalf("approve: %v %+v", err, got)
	}
	// Idempotent replay: approving again returns the stored result, sends nothing.
	again, err := s.Approve(context.Background(), "acme", "carol", onEnv(), r.ID, "")
	if !errors.Is(err, ErrNotPending) || again.Status != StatusExecuted || again.DecidedBy != "bob" {
		t.Fatalf("replay: %v %+v", err, again)
	}
	if it.calls.Load() != 1 {
		t.Fatalf("the note was sent %d times", it.calls.Load())
	}
}

func TestConcurrentApprovalsSendOnce(t *testing.T) {
	s, it, _ := newSvc(t)
	r := propose(t, s, "acme", itsm())
	var wg sync.WaitGroup
	var won atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := s.Approve(context.Background(), "acme", "approver-"+string(rune('a'+i)), onEnv(), r.ID, ""); err == nil {
				won.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if it.calls.Load() != 1 || won.Load() != 1 {
		t.Fatalf("sent %d times, %d approvals succeeded", it.calls.Load(), won.Load())
	}
}

func TestExpiredRequestCannotRun(t *testing.T) {
	s, it, _ := newSvc(t)
	r := propose(t, s, "acme", itsm())
	later := t0.Add(DefaultTTL + time.Minute)
	s.Now = func() time.Time { return later }
	got, err := s.Approve(context.Background(), "acme", "bob", onEnv(), r.ID, "")
	if !errors.Is(err, ErrExpired) || got.Status != StatusExpired {
		t.Fatalf("want expired, got %v %+v", err, got)
	}
	if it.calls.Load() != 0 {
		t.Fatal("an expired request ran")
	}
	if _, err := s.Reject(context.Background(), "acme", "bob", r.ID, "late"); !errors.Is(err, ErrExpired) {
		t.Fatalf("reject after expiry: %v", err)
	}
}

func TestKillSwitchOffAtApprovalStopsIt(t *testing.T) {
	s, it, _ := newSvc(t)
	r := propose(t, s, "acme", itsm())
	off := onEnv()
	off.Platform = false
	if _, err := s.Approve(context.Background(), "acme", "bob", off, r.ID, ""); !errors.Is(err, ErrDenied) {
		t.Fatalf("kill switch off: want ErrDenied, got %v", err)
	}
	ws := onEnv()
	ws.Settings.Enabled = false
	if _, err := s.Approve(context.Background(), "acme", "bob", ws, r.ID, ""); !errors.Is(err, ErrDenied) {
		t.Fatalf("workspace off: want ErrDenied, got %v", err)
	}
	if it.calls.Load() != 0 {
		t.Fatal("the switch was off and the note went out")
	}
	if got, _ := s.Get(context.Background(), "acme", r.ID); got.Status != StatusProposed {
		t.Fatalf("a refused approval changed the request: %s", got.Status)
	}
}

func TestDryRunOnlyNeverExecutes(t *testing.T) {
	s, it, _ := newSvc(t)
	env := onEnv()
	env.Settings.DryRunOnly = true
	out, err := s.Propose(context.Background(), "acme", env, Proposal{Payload: itsm(), ProposedBy: "alice"})
	if err != nil || out.Request.Status != StatusDryRun || out.Decision != DryRunOnly {
		t.Fatalf("dry-run proposal: %v %+v", err, out)
	}
	if _, err := s.Approve(context.Background(), "acme", "bob", onEnv(), out.Request.ID, ""); !errors.Is(err, ErrNotPending) {
		t.Fatalf("a dry-run request must never run: %v", err)
	}
	// And a waiting request approved while the workspace is dry-run-only stays put.
	r := propose(t, s, "acme", InvestigationNote{CorrelationID: "corr-2", Verdict: "BGP peer idle after WAN flap."})
	if _, err := s.Approve(context.Background(), "acme", "bob", env, r.ID, ""); !errors.Is(err, ErrDryRunOnly) {
		t.Fatalf("approve under dry-run-only: %v", err)
	}
	if it.calls.Load() != 0 {
		t.Fatal("dry run sent something")
	}
}

func TestFailedSendIsRecordedAndNotRetried(t *testing.T) {
	s, it, _ := newSvc(t)
	it.fail = errors.New("servicenow work note returned 503")
	r := propose(t, s, "acme", itsm())
	got, err := s.Approve(context.Background(), "acme", "bob", onEnv(), r.ID, "")
	if err == nil || got.Status != StatusFailed || got.Result == nil || !strings.Contains(got.Result.Message, "503") {
		t.Fatalf("failed send: %v %+v", err, got)
	}
	if _, err := s.Approve(context.Background(), "acme", "carol", onEnv(), r.ID, ""); !errors.Is(err, ErrNotPending) {
		t.Fatalf("a failed request must not be re-run by another approval: %v", err)
	}
	if it.calls.Load() != 1 {
		t.Fatalf("sent %d times", it.calls.Load())
	}
}

func TestRejectNeedsAReasonAndTheProposerMayWithdraw(t *testing.T) {
	s, _, _ := newSvc(t)
	r := propose(t, s, "acme", itsm())
	if _, err := s.Reject(context.Background(), "acme", "alice", r.ID, "  "); !errors.Is(err, ErrReasonMissing) {
		t.Fatalf("blank reason: %v", err)
	}
	got, err := s.Reject(context.Background(), "acme", "alice", r.ID, "already noted by hand")
	if err != nil || got.Status != StatusRejected || got.Reason == "" {
		t.Fatalf("withdraw: %v %+v", err, got)
	}
}

// §3a: another tenant's request is the same not-found as a missing one.
func TestRequestsAreTenantScoped(t *testing.T) {
	s, it, _ := newSvc(t)
	r := propose(t, s, "acme", itsm())
	if _, err := s.Get(context.Background(), "globex", r.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if _, err := s.Approve(context.Background(), "globex", "mallory", onEnv(), r.ID, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant approve: %v", err)
	}
	if _, err := s.Reject(context.Background(), "globex", "mallory", r.ID, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant reject: %v", err)
	}
	if rs, _ := s.List(context.Background(), "globex", Filter{}); len(rs) != 0 {
		t.Fatalf("globex lists %d acme requests", len(rs))
	}
	if it.calls.Load() != 0 {
		t.Fatal("a cross-tenant call sent something")
	}
}

func TestOpenCapHolds(t *testing.T) {
	s, _, _ := newSvc(t)
	for i := 0; i < MaxOpenPerTenant; i++ {
		p := itsm()
		p.CorrelationID = "corr-" + string(rune('A'+i%26)) + string(rune('a'+i/26))
		propose(t, s, "acme", p)
	}
	p := itsm()
	p.CorrelationID = "corr-over"
	if _, err := s.Propose(context.Background(), "acme", onEnv(), Proposal{Payload: p, ProposedBy: "alice"}); !errors.Is(err, ErrTooManyOpen) {
		t.Fatalf("want ErrTooManyOpen, got %v", err)
	}
}

// The Go vocabularies and the migration's CHECKs name exactly the same values.
func TestVocabulariesMatchTheMigration(t *testing.T) {
	b, err := os.ReadFile("../platformdb/migrations/0076_iris_action_requests.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(b)
	check := func(col string, vals []string) {
		t.Helper()
		want := "'" + strings.Join(vals, "','") + "'"
		if !strings.Contains(sql, col+" IN ("+want+")") {
			t.Errorf("migration CHECK for %s does not name exactly %s", col, want)
		}
	}
	ks := []string{}
	for _, k := range Kinds {
		ks = append(ks, string(k))
	}
	ss := []string{}
	for _, s := range Statuses {
		ss = append(ss, string(s))
	}
	ds := []string{}
	for _, d := range Decisions {
		ds = append(ds, string(d))
	}
	check("kind", ks)
	check("status", ss)
	check("policy", ds)
}

// ---- HTTP ------------------------------------------------------------------

type httpRig struct {
	svc      *Service
	settings Settings
	env      Env
	audits   []string
	ledgers  int
}

func (h *httpRig) deps(c Caller) Deps {
	return Deps{
		Service: h.svc,
		Authorize: func(_ http.ResponseWriter, _ *http.Request, _ Level) (Caller, bool) {
			return c, true
		},
		Env:      func(*http.Request, string) Env { return h.env },
		Settings: func(string) Settings { return h.settings },
		SaveSettings: func(_ *http.Request, _ Caller, s Settings) error {
			h.settings = s
			return nil
		},
		Audit: func(_ *http.Request, _ Caller, action, decision string, _ *Request, _ map[string]any) {
			h.audits = append(h.audits, action+":"+decision)
		},
		Ledger: func(*http.Request, Caller, Request) { h.ledgers++ },
	}
}

func call(d Deps, method, path, body string) (int, map[string]any) {
	rec := httptest.NewRecorder()
	d.Handler(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		return rec.Code, nil
	}
	return rec.Code, m
}

func TestHTTPApproveRules(t *testing.T) {
	s, it, _ := newSvc(t)
	rig := &httpRig{svc: s, env: onEnv(), settings: onEnv().Settings}
	r := propose(t, s, "acme", itsm())
	alice := Caller{Tenant: "acme", Sub: "alice", Person: true}
	bob := Caller{Tenant: "acme", Sub: "bob", Person: true}
	key := Caller{Tenant: "acme", Sub: "apikey:ci", Person: false}

	if code, m := call(rig.deps(alice), http.MethodGet, apiPrefix, ""); code != 200 || m["open"].(float64) != 1 {
		t.Fatalf("list: %d %v", code, m)
	}
	if code, _ := call(rig.deps(alice), http.MethodPost, apiPrefix+"/"+r.ID+"/approve", `{}`); code != http.StatusForbidden {
		t.Fatalf("self approve over HTTP: %d", code)
	}
	if code, _ := call(rig.deps(key), http.MethodPost, apiPrefix+"/"+r.ID+"/approve", `{}`); code != http.StatusForbidden {
		t.Fatalf("API-key approve: %d", code)
	}
	if code, _ := call(rig.deps(bob), http.MethodPost, apiPrefix+"/"+r.ID+"/approve", `{"extra":1}`); code != http.StatusBadRequest {
		t.Fatalf("unknown body field: %d", code)
	}
	code, m := call(rig.deps(bob), http.MethodPost, apiPrefix+"/"+r.ID+"/approve", `{"reason":"ok"}`)
	if code != 200 || m["status"] != string(StatusExecuted) || rig.ledgers != 1 {
		t.Fatalf("approve: %d %v ledger=%d", code, m, rig.ledgers)
	}
	if code, _ := call(rig.deps(bob), http.MethodPost, apiPrefix+"/"+r.ID+"/approve", `{}`); code != http.StatusConflict {
		t.Fatalf("replay: %d", code)
	}
	if it.calls.Load() != 1 || rig.ledgers != 1 {
		t.Fatalf("sent %d times, %d ledger records", it.calls.Load(), rig.ledgers)
	}
	other := Caller{Tenant: "globex", Sub: "mallory", Person: true}
	if code, _ := call(rig.deps(other), http.MethodGet, apiPrefix+"/"+r.ID, ""); code != http.StatusNotFound {
		t.Fatalf("cross-tenant get: %d", code)
	}
}

func TestHTTPSettingsNeedAcknowledgement(t *testing.T) {
	s, _, _ := newSvc(t)
	rig := &httpRig{svc: s, env: onEnv()}
	admin := Caller{Tenant: "acme", Sub: "admin", Person: true}
	if code, _ := call(rig.deps(admin), http.MethodPut, apiPrefix+"/settings", `{"enabled":true,"kinds":["itsm_note"]}`); code != http.StatusBadRequest {
		t.Fatalf("enable without ack: %d", code)
	}
	if code, _ := call(rig.deps(admin), http.MethodPut, apiPrefix+"/settings", `{"enabled":true,"kinds":["device_config"],"acknowledged":true}`); code != http.StatusBadRequest {
		t.Fatalf("unknown kind: %d", code)
	}
	code, m := call(rig.deps(admin), http.MethodPut, apiPrefix+"/settings", `{"enabled":true,"kinds":["itsm_note","itsm_note"],"acknowledged":true}`)
	if code != 200 || !rig.settings.Enabled || len(rig.settings.Kinds) != 1 {
		t.Fatalf("enable: %d %v %+v", code, m, rig.settings)
	}
	// Turning it off never needs the acknowledgement.
	if code, _ := call(rig.deps(admin), http.MethodPut, apiPrefix+"/settings", `{"enabled":false}`); code != 200 || rig.settings.Enabled {
		t.Fatalf("disable: %d", code)
	}
	key := Caller{Tenant: "acme", Sub: "apikey:ci"}
	if code, _ := call(rig.deps(key), http.MethodPut, apiPrefix+"/settings", `{"enabled":false}`); code != http.StatusForbidden {
		t.Fatalf("API key changed settings: %d", code)
	}
}

func TestHTTPHasNoProposeRoute(t *testing.T) {
	s, _, _ := newSvc(t)
	rig := &httpRig{svc: s, env: onEnv(), settings: onEnv().Settings}
	alice := Caller{Tenant: "acme", Sub: "alice", Person: true}
	for _, path := range []string{apiPrefix, apiPrefix + "/propose", apiPrefix + "/x/execute"} {
		if code, _ := call(rig.deps(alice), http.MethodPost, path, `{"kind":"itsm_note"}`); code == http.StatusOK || code == http.StatusCreated {
			t.Fatalf("POST %s accepted a client proposal: %d", path, code)
		}
	}
	if rs, _ := s.List(context.Background(), "acme", Filter{}); len(rs) != 0 {
		t.Fatal("a client created a request")
	}
}

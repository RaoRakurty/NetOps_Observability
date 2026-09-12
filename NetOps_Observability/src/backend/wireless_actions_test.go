// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// wireless_actions_test.go — the five gates (#128 Phase 8), each proven to
// FAIL CLOSED, plus dormancy, tenancy and audit. The framework ships before
// any executor exists — so the most important assertions here are refusals.

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/wireless"
)

func gateStore() *wirelessActionStore { return newWirelessActionStore() }

const confirmedTier = "confirmed"

var rfKinds = []string{"wireless_channel_util_high", "wireless_retry_rate_high"}

func TestGate1ProposalRequiresParticipatingEvidence(t *testing.T) {
	t.Setenv("WIRELESS_ACTION_ALLOWLIST", wireless.WirelessActionRRMChannel)
	st := gateStore()
	// The incident's evidence is an ONBOARDING failure — an RRM channel change
	// does not interrogate that family; proposing it must be refused.
	_, err := st.Propose("t1", "op", wireless.WirelessActionRRMChannel, "ap-abc", "c1",
		[]string{"wireless_onboarding_dhcp_failure"}, confirmedTier, wirelessActionAllowlist())
	if !errors.Is(err, wireless.ErrActionEvidence) {
		t.Fatalf("want gate-1 refusal, got %v", err)
	}
	if _, err := st.Propose("t1", "op", wireless.WirelessActionRRMChannel, "ap-abc", "c1",
		rfKinds, confirmedTier, wirelessActionAllowlist()); err != nil {
		t.Fatalf("participating RF evidence must pass gate 1: %v", err)
	}
}

func TestGate2AllowlistDefaultsEmpty(t *testing.T) {
	t.Setenv("WIRELESS_ACTION_ALLOWLIST", "")
	st := gateStore()
	_, err := st.Propose("t1", "op", wireless.WirelessActionRRMChannel, "ap-abc", "c1",
		rfKinds, confirmedTier, wirelessActionAllowlist())
	if !errors.Is(err, wireless.ErrActionNotAllowed) {
		t.Fatalf("empty allowlist must refuse EVERY kind, got %v", err)
	}
}

func TestGate2VerdictMustBeConfirmed(t *testing.T) {
	t.Setenv("WIRELESS_ACTION_ALLOWLIST", wireless.WirelessActionRRMChannel)
	st := gateStore()
	for _, tier := range []string{"suspected", "undetermined", ""} {
		if _, err := st.Propose("t1", "op", wireless.WirelessActionRRMChannel, "ap-abc", "c1",
			rfKinds, tier, wirelessActionAllowlist()); !errors.Is(err, wireless.ErrActionNotConfirmed) {
			t.Fatalf("tier %q must refuse, got %v", tier, err)
		}
	}
}

func TestGate2BlastRadiusOneTypedTarget(t *testing.T) {
	t.Setenv("WIRELESS_ACTION_ALLOWLIST", wireless.WirelessActionRRMChannel+","+wireless.WirelessActionClientDeauth)
	st := gateStore()
	cases := []string{"", "sw1:Gi1/0/1", "ap-a,ap-b", "wcl-c1"}
	for _, target := range cases {
		if _, err := st.Propose("t1", "op", wireless.WirelessActionRRMChannel, target, "c1",
			rfKinds, confirmedTier, wirelessActionAllowlist()); !errors.Is(err, wireless.ErrActionBlastRadius) {
			t.Fatalf("target %q must refuse on blast radius, got %v", target, err)
		}
	}
	// The deauth action targets a CLIENT, never an AP.
	if _, err := st.Propose("t1", "op", wireless.WirelessActionClientDeauth, "ap-abc", "c1",
		[]string{"wireless_roam_storm"}, confirmedTier, wirelessActionAllowlist()); !errors.Is(err, wireless.ErrActionBlastRadius) {
		t.Fatalf("client action on an AP target must refuse, got %v", err)
	}
}

func TestGate3And4ApprovalThenFailClosedExecution(t *testing.T) {
	t.Setenv("WIRELESS_ACTION_ALLOWLIST", wireless.WirelessActionRadioReset)
	st := gateStore()
	a, err := st.Propose("t1", "op", wireless.WirelessActionRadioReset, "ap-abc", "c1",
		[]string{"wireless_radio_down"}, confirmedTier, wirelessActionAllowlist())
	if err != nil {
		t.Fatal(err)
	}
	// Executing an unapproved action refuses (gate 3).
	if _, err := st.Execute("t1", a.ID); !errors.Is(err, wireless.ErrActionNotApproved) {
		t.Fatalf("unapproved execute must refuse, got %v", err)
	}
	if _, err := st.Approve("t1", a.ID, "admin", ""); err != nil {
		t.Fatal(err)
	}
	// v1 has NO executor: execution fails CLOSED and records FAILED (gate 4).
	got, err := st.Execute("t1", a.ID)
	if !errors.Is(err, wireless.ErrActionNoExecutor) {
		t.Fatalf("no-executor execute must refuse, got %v", err)
	}
	if got.State != wireless.ActionStateFailed || got.Error == "" {
		t.Fatalf("refused execution must record failed+reason: %+v", got)
	}
	// A rejected proposal can never be approved or executed.
	b, _ := st.Propose("t1", "op", wireless.WirelessActionRadioReset, "ap-def", "c1",
		[]string{"wireless_radio_down"}, confirmedTier, wirelessActionAllowlist())
	if _, err := st.Reject("t1", b.ID, "admin", "channel plan is already being re-run by hand"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Approve("t1", b.ID, "admin", ""); !errors.Is(err, wireless.ErrActionWrongState) {
		t.Fatalf("approving a rejected action must refuse, got %v", err)
	}
}

func TestActionsTenantScoped(t *testing.T) {
	t.Setenv("WIRELESS_ACTION_ALLOWLIST", wireless.WirelessActionRadioReset)
	st := gateStore()
	a, _ := st.Propose("tA", "op", wireless.WirelessActionRadioReset, "ap-abc", "c1",
		[]string{"wireless_radio_down"}, confirmedTier, wirelessActionAllowlist())
	// Another tenant can neither see nor act on it — indistinguishable from
	// nonexistent (§3a).
	if got := st.List("tB", false); len(got) != 0 {
		t.Fatalf("cross-tenant list leaked: %+v", got)
	}
	if _, err := st.Approve("tB", a.ID, "admin", ""); !errors.Is(err, wireless.ErrActionNotFound) {
		t.Fatalf("cross-tenant approve must be notFound, got %v", err)
	}
	if _, err := st.Execute("tB", a.ID); !errors.Is(err, wireless.ErrActionNotFound) {
		t.Fatalf("cross-tenant execute must be notFound, got %v", err)
	}
	if got := st.List("tA", false); len(got) != 1 {
		t.Fatalf("own list must see it")
	}
	if got := st.List("", true); len(got) != 1 {
		t.Fatalf("platform cross list must see it")
	}
}

// Dormancy + the scoped-route contract through the REAL router: with the
// feature off (default) every actions route 404s even authenticated; with it
// on, an unauthenticated caller still gets 401 and a tenant operator's list
// is empty rather than another tenant's rows.
func TestWirelessActionsHTTPDormantAndScoped(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// Default: dormant → 404 even for the platform owner.
	if st, _ := do(t, srv, "GET", "/api/wireless/actions", admin, nil); st != 404 {
		t.Fatalf("dormant actions surface must 404, got %d", st)
	}

	t.Setenv("FEATURE_WIRELESS_ACTIONS", "true")
	if st, _ := do(t, srv, "GET", "/api/wireless/actions", "", nil); st != 401 {
		t.Fatalf("unauthenticated must 401, got %d", st)
	}
	st_, body := do(t, srv, "GET", "/api/wireless/actions", admin, nil)
	if st_ != 200 {
		t.Fatalf("enabled list: %d %s", st_, body)
	}
	var rows []map[string]any
	_ = json.Unmarshal(body, &rows)
	if len(rows) != 0 {
		t.Fatalf("fresh store must list empty, got %s", body)
	}
	// Propose without a reachable evidence store: gate inputs FAIL CLOSED.
	st_, body = do(t, srv, "POST", "/api/wireless/actions", admin, map[string]any{
		"kind": wireless.WirelessActionRRMChannel, "target": "ap-abc",
		"correlation_id": "0f9e8d7c-0000-4000-8000-000000000001",
	})
	if st_ != 400 && st_ != 422 {
		t.Fatalf("proposal without gate inputs must refuse (400/422), got %d %s", st_, body)
	}

	// Item route (§3a): a cross-tenant/unknown action id is 404 — existence
	// hidden. Seed one action for tenant "other" directly in the store; the
	// platform-owner path sees it, but a foreign id through the item verbs
	// resolves exactly like a nonexistent one for a scoped caller.
	t.Setenv("WIRELESS_ACTION_ALLOWLIST", wireless.WirelessActionRadioReset)
	a, err := s.wirelessActions.Propose("other-tenant", "seed", wireless.WirelessActionRadioReset,
		"ap-abc", "c1", []string{"wireless_radio_down"}, "confirmed", wirelessActionAllowlist())
	if err != nil {
		t.Fatal(err)
	}
	opTok := makeTenantOperator(t, srv, admin, "wact-iso")
	if st, b := do(t, srv, "POST", "/api/wireless/actions/"+a.ID+"/approve", opTok, nil); st != 404 {
		t.Fatalf("cross-tenant approve must 404, got %d %s", st, b)
	}
	if st, b := do(t, srv, "GET", "/api/wireless/actions", opTok, nil); st != 200 || string(b) == "" {
		t.Fatalf("operator list: %d %s", st, b)
	} else {
		var rows2 []map[string]any
		_ = json.Unmarshal(b, &rows2)
		if len(rows2) != 0 {
			t.Fatalf("operator must not see other-tenant actions: %s", b)
		}
	}
}

// makeTenantOperator creates an org+tenant+operator and returns its token.
func makeTenantOperator(t *testing.T, srv *httptest.Server, adminTok, name string) string {
	t.Helper()
	st, b := do(t, srv, "POST", "/api/orgs", adminTok, map[string]any{"name": "Org " + name})
	if st != 201 {
		t.Fatalf("org: %d %s", st, b)
	}
	orgID := idOf(t, b)
	st, b = do(t, srv, "POST", "/api/tenants", adminTok, map[string]any{"name": "T " + name, "org_id": orgID})
	if st != 201 {
		t.Fatalf("tenant: %d %s", st, b)
	}
	tid := idOf(t, b)
	user := "u-" + name
	if st, b := do(t, srv, "POST", "/api/users", adminTok, map[string]any{
		"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tid,
	}); st != 201 {
		t.Fatalf("user: %d %s", st, b)
	}
	return login(t, srv, user, "Passw0rd!2345").Token
}

// A rejection with no reason is refused: the audit trail's whole value is the
// record of WHY an evidence-backed proposal was not carried out (gate 3).
func TestRejectRequiresAReason(t *testing.T) {
	t.Setenv("WIRELESS_ACTION_ALLOWLIST", wireless.WirelessActionRadioReset)
	st := gateStore()
	a, err := st.Propose("t1", "op", wireless.WirelessActionRadioReset, "ap-abc", "c1",
		[]string{"wireless_radio_down"}, confirmedTier, wirelessActionAllowlist())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Reject("t1", a.ID, "admin", "   "); !errors.Is(err, wireless.ErrActionNoReason) {
		t.Fatalf("blank reason must refuse, got %v", err)
	}
	// The proposal is untouched by the refused rejection.
	if got := st.List("t1", false); len(got) != 1 || got[0].State != wireless.ActionStateProposed {
		t.Fatalf("refused rejection must not move the action: %+v", got)
	}
	// An over-long reason is refused at the boundary rather than stored.
	long := strings.Repeat("x", wireless.MaxActionReason+1)
	if _, err := st.Reject("t1", a.ID, "admin", long); err == nil {
		t.Fatal("over-long reason must be refused")
	}
	rejected, err := st.Reject("t1", a.ID, "admin", "  radio reset is scheduled in tonight's window  ")
	if err != nil {
		t.Fatal(err)
	}
	if rejected.State != wireless.ActionStateRejected {
		t.Fatalf("state = %q", rejected.State)
	}
	if rejected.Reason != "radio reset is scheduled in tonight's window" {
		t.Fatalf("reason not trimmed/recorded: %q", rejected.Reason)
	}
	// An approval records its optional note the same way.
	b, _ := st.Propose("t1", "op", wireless.WirelessActionRadioReset, "ap-def", "c1",
		[]string{"wireless_radio_down"}, confirmedTier, wirelessActionAllowlist())
	approved, err := st.Approve("t1", b.ID, "admin", "agreed with the seam owner")
	if err != nil {
		t.Fatal(err)
	}
	if approved.Reason != "agreed with the seam owner" {
		t.Fatalf("approval note not recorded: %q", approved.Reason)
	}
}

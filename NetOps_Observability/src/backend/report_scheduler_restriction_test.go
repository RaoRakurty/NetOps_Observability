// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// report_scheduler_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test
// for the operator-visibility restriction (Tenant.OperatorRestricted) on the
// SCHEDULED REPORT path.
//
// This is the sharpest of the alert readers, and it is the one with no operator
// in front of it. A scheduled report is rendered by a timer and then DELIVERED —
// to platform notify channels (Slack/PagerDuty/webhook/email) and to contact
// points chosen when the schedule was created, possibly months earlier. Every
// other surface in this family leaks to a human who asked a question; this one
// leaks a restricted tenant's live incidents, by name, off the box, on a clock,
// to a destination nobody is looking at in the moment.
//
// So the assertions below are on what the DELIVERED MESSAGE CONTAINS — the bytes
// the recording channel received — not on an internal filter call.
//
// Whose visibility a scheduled run carries is decided in
// reportScheduler.alertVisibility: the report's OWN tenant, which is the scope
// its recipients were chosen under. A tenant-owned report is the tenant's own
// view and nothing is hidden from it; a PLATFORM-owned report is the operator's
// Global view and the restriction applies to it.

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/alerts"
	"netops/backend/internal/discovery"
	"netops/backend/internal/saved"
	"netops/backend/models"
	"netops/backend/notify"
	"netops/backend/reports"
)

// The values that must not leave the box on a timer.
const (
	schedAcmeAlertID   = "alert-acme-edge-bfd"
	schedAcmeSummary   = "BFD session to 203.0.113.44 is down on acme-edge"
	schedAcmeExpTarget = "billing.acme.example"
	schedGlobexSummary = "BFD session is down on globex-edge"
	schedStackSummary  = "engine consumer lag is climbing"
)

type restrictedReportFixture struct {
	t      *testing.T
	s      *server
	rs     *reportScheduler
	ch     *recordingChannel
	acme   string
	globex string
}

func (f *restrictedReportFixture) restrictAcme() {
	f.t.Helper()
	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		f.t.Fatalf("restrict acme: %v", err)
	}
}

// savedReport reads one stored schedule back the way the timer does.
func (f *restrictedReportFixture) savedReport(id string) (saved.Object, reportSpec) {
	f.t.Helper()
	o, ok := f.rs.saved.Get(id)
	if !ok {
		f.t.Fatalf("saved report %q not found", id)
	}
	spec, err := parseReportSpec(o.Body)
	if err != nil {
		f.t.Fatalf("parse spec for %q: %v", id, err)
	}
	return o, spec
}

// deliverReport runs the REAL delivery path (render → dispatch) for a
// PLATFORM-owned schedule and returns what the notify channel actually received,
// flattened to the text a recipient reads. Dispatch is asynchronous, so this
// waits for the message rather than racing it.
func (f *restrictedReportFixture) deliverReport(id string) string {
	f.t.Helper()
	o, spec := f.savedReport(id)
	f.rs.deliver(o, spec, time.Now().UTC())

	deadline := time.Now().Add(5 * time.Second)
	var sent []models.Alert
	for {
		if sent = f.ch.drain(); len(sent) > 0 {
			break
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("report %q was never delivered to the notify channel — the test would assert on nothing", o.Name)
		}
		time.Sleep(5 * time.Millisecond)
	}
	return alertText(sent...)
}

// renderReport is the same content for a TENANT-owned schedule, which by design
// never reaches a platform notify channel (deliver() skips named channels for a
// tenant-owned report) and is emailed to that tenant's own contact points
// instead. This is the message body those recipients receive.
func (f *restrictedReportFixture) renderReport(id string) string {
	f.t.Helper()
	o, spec := f.savedReport(id)
	return alertText(f.rs.render(o, spec, time.Now().UTC()))
}

// alertText flattens delivered report messages to the text a recipient reads.
func alertText(msgs ...models.Alert) string {
	var b strings.Builder
	for _, m := range msgs {
		b.WriteString(m.Summary)
		b.WriteString("\n")
		b.WriteString(m.Description)
		b.WriteString("\n")
	}
	return b.String()
}

// newRestrictedReportFixture seeds two tenants plus the platform, one active
// alert each (plus acme's device-less experience alert and an unowned stack
// alert), and a platform notify channel that records what it is handed.
func newRestrictedReportFixture(t *testing.T) *restrictedReportFixture {
	t.Helper()
	dir := t.TempDir()
	ts, err := newTenantStore(filepath.Join(dir, "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	acme, err := ts.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	globex, err := ts.Create("Globex", "globex", "", "", "")
	if err != nil {
		t.Fatalf("create globex: %v", err)
	}
	roles, err := newRoleStore(filepath.Join(dir, "roles.json"))
	if err != nil {
		t.Fatalf("newRoleStore: %v", err)
	}
	sv, err := newSavedStore(filepath.Join(dir, "saved.json"))
	if err != nil {
		t.Fatalf("newSavedStore: %v", err)
	}

	d := discovery.NewDiscoveryAggregator()
	for _, dev := range []models.Device{
		{ID: "acme-edge", Name: "acme-edge", Address: "10.1.0.2", TenantID: acme.ID},
		{ID: "globex-edge", Name: "globex-edge", Address: "10.2.0.2", TenantID: globex.ID},
		{ID: "stack-jump", Name: "stack-jump", Address: "10.9.0.1"},
	} {
		if err := d.Upsert(dev); err != nil {
			t.Fatalf("upsert %s: %v", dev.ID, err)
		}
	}

	now := time.Now().UTC()
	eng := alerts.NewEngine("", nil)
	eng.SeedActiveForTest(
		models.Alert{ID: schedAcmeAlertID, Rule: "BFDSessionDown", Severity: "critical",
			DeviceID: "acme-edge", Summary: schedAcmeSummary, FiredAt: now},
		models.Alert{ID: "alert-globex-edge-bfd", Rule: "BFDSessionDown", Severity: "critical",
			DeviceID: "globex-edge", Summary: schedGlobexSummary, FiredAt: now},
		models.Alert{ID: "alert-acme-experience-sched", Rule: "ExperienceLatencyOverBudget", Severity: "critical",
			Summary: "Experience target " + schedAcmeExpTarget + " p95 is 940 ms",
			Labels:  map[string]string{"tenant": acme.ID, "target": schedAcmeExpTarget},
			FiredAt: now},
		models.Alert{ID: "alert-stack-kafka-sched", Rule: "KafkaLagHigh", Severity: "warning",
			Summary: schedStackSummary, FiredAt: now},
	)

	ch := &recordingChannel{name: "ops-slack"}
	dispatcher := notify.NewDispatcher()
	dispatcher.Register(ch)

	s := &server{discovery: d, tenants: ts, roles: roles, saved: sv, alerts: eng, notifier: dispatcher}
	rs := &reportScheduler{
		srv: s, saved: sv, notifier: dispatcher, discovery: d, alerts: eng,
		runs: map[string]reportRun{}, path: filepath.Join(dir, "runs.json"),
	}
	rs.ds = rs.dataSource()
	s.reports = rs
	return &restrictedReportFixture{t: t, s: s, rs: rs, ch: ch, acme: acme.ID, globex: globex.ID}
}

// TestScheduledReportHonoursTheOperatorVisibilityRestriction asserts on the
// DELIVERED report, both halves plus the tenant's own view.
func TestScheduledReportHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedReportFixture(t)

	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	acmeAdmin := jwtClaims{Sub: "admin@acme", Role: RoleSuperAdmin, Tenant: f.acme}
	globexAdmin := jwtClaims{Sub: "admin@globex", Role: RoleSuperAdmin, Tenant: f.globex}

	// A PLATFORM-owned schedule bound to a platform notify channel — the shape
	// that carries a restricted tenant's incidents off the box on a timer.
	fleet := createReport(t, f.s, owner, "fleet alerts",
		`{"kind":"alerts_summary","enabled":true,"interval_minutes":60,"channels":["ops-slack"]}`)
	// The tenants' own schedules. They must be untouched by the switch.
	acmeRpt := createReport(t, f.s, acmeAdmin, "acme alerts",
		`{"kind":"alerts_summary","enabled":true,"interval_minutes":60}`)
	globexRpt := createReport(t, f.s, globexAdmin, "globex alerts",
		`{"kind":"alerts_summary","enabled":true,"interval_minutes":60}`)

	// ── baseline: the platform report DOES carry acme's incidents today. Without
	//    this the assertions below could pass on a report that renders nothing. ──
	base := f.deliverReport(fleet)
	for _, want := range []string{schedAcmeSummary, schedAcmeExpTarget, schedGlobexSummary, schedStackSummary} {
		if !strings.Contains(base, want) {
			t.Fatalf("baseline: the delivered platform report does not contain %q — the fixture does not reach the channel:\n%s", want, base)
		}
	}
	if !strings.Contains(base, "4 active alert(s)") {
		t.Fatalf("baseline: the delivered platform report should summarise 4 active alerts:\n%s", base)
	}
	// acme's OWN delivered report, captured BEFORE the switch.
	acmeBefore := f.rs.tenantAlerts(f.acme)
	acmeBeforeIDs := alertIDSet(acmeBefore)
	if !acmeBeforeIDs[schedAcmeAlertID] || len(acmeBefore) != 3 {
		t.Fatalf("baseline: acme's own report set = %v, want its device alert, its experience alert and the platform's stack alert",
			sortedKeys(acmeBeforeIDs))
	}

	f.restrictAcme()

	// ── half 1: the platform (cross-tenant) report drops the restricted tenant. ──
	after := f.deliverReport(fleet)
	for _, leak := range []string{schedAcmeAlertID, schedAcmeSummary, "acme-edge", schedAcmeExpTarget, "203.0.113.44"} {
		if strings.Contains(after, leak) {
			t.Errorf("RESTRICTION LEAK: the DELIVERED platform report carries acme's %q off the box on a timer:\n%s", leak, after)
		}
	}
	// ── an unrestricted tenant is unmoved and a platform-owned alert survives. ──
	for _, want := range []string{schedGlobexSummary, schedStackSummary} {
		if !strings.Contains(after, want) {
			t.Errorf("restricting acme also removed %q from the platform report:\n%s", want, after)
		}
	}
	if !strings.Contains(after, "2 active alert(s)") {
		t.Errorf("the delivered platform report's COUNT still discloses acme: want \"2 active alert(s)\":\n%s", after)
	}

	// ── half 2: the restricted tenant's OWN scheduled report is unchanged. The
	//    switch hides a tenant from the PLATFORM, never from itself, and a
	//    restricted tenant that stopped receiving its own reports would be a
	//    self-inflicted outage dressed up as a privacy control. ──
	acmeDelivered := f.renderReport(acmeRpt)
	if !strings.Contains(acmeDelivered, schedAcmeSummary) || !strings.Contains(acmeDelivered, schedAcmeExpTarget) {
		t.Errorf("the restriction damaged acme's OWN scheduled report — it lost its own incidents:\n%s", acmeDelivered)
	}
	if strings.Contains(acmeDelivered, schedGlobexSummary) {
		t.Errorf("CROSS-TENANT LEAK: acme's own report carries globex's %q:\n%s", schedGlobexSummary, acmeDelivered)
	}
	acmeAfter := alertIDSet(f.rs.tenantAlerts(f.acme))
	if !sameSet(acmeBeforeIDs, acmeAfter) {
		t.Errorf("the restriction changed acme's own report set: %v before, %v after",
			sortedKeys(acmeBeforeIDs), sortedKeys(acmeAfter))
	}

	// ── the unrestricted tenant's own report is unmoved too. ──
	globexDelivered := f.renderReport(globexRpt)
	if !strings.Contains(globexDelivered, schedGlobexSummary) {
		t.Errorf("restricting acme damaged globex's own report:\n%s", globexDelivered)
	}
	if strings.Contains(globexDelivered, schedAcmeSummary) {
		t.Errorf("CROSS-TENANT LEAK: globex's own report carries acme's %q:\n%s", schedAcmeSummary, globexDelivered)
	}
}

// TestScheduledReportDoesNotInheritBreakGlass pins the second half of the
// scheduled-run decision. Break-glass is a live, time-boxed session an operator
// opens for ITSELF; a timer holds none. A schedule that inherited one would keep
// delivering a restricted tenant's incidents to a channel long after the session
// that authorised the look had expired.
func TestScheduledReportDoesNotInheritBreakGlass(t *testing.T) {
	f := newRestrictedReportFixture(t)
	bs, err := newBindingStore(filepath.Join(t.TempDir(), "role_bindings.json"))
	if err != nil {
		t.Fatalf("newBindingStore: %v", err)
	}
	f.s.bindings = bs
	f.restrictAcme()

	// An operator opens a live session into acme. Its own REST view un-hides.
	exp := time.Now().UTC().Add(30 * time.Minute)
	if _, err := bs.Add(RoleBinding{
		PrincipalID: "root", RoleID: RoleSuperAdmin, ScopeID: scopeTenant(f.acme),
		Effect: EffectAllow, Condition: map[string]any{conditionBreakGlass: true}, ExpiresAt: &exp,
	}); err != nil {
		t.Fatalf("open break-glass: %v", err)
	}
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	if vis := f.s.alertVisibilityFor(owner); len(vis.hiddenTenants) != 0 {
		t.Fatalf("premise broken: the operator's own view is still hiding %v despite a live session", vis.hiddenTenants)
	}

	// The SCHEDULED platform run is not that operator and does not inherit it.
	fleet := createReport(t, f.s, owner, "fleet alerts",
		`{"kind":"alerts_summary","enabled":true,"interval_minutes":60,"channels":["ops-slack"]}`)
	delivered := f.deliverReport(fleet)
	for _, leak := range []string{schedAcmeAlertID, schedAcmeSummary, schedAcmeExpTarget} {
		if strings.Contains(delivered, leak) {
			t.Errorf("RESTRICTION LEAK: the scheduled platform report inherited an operator's break-glass session and delivered acme's %q:\n%s",
				leak, delivered)
		}
	}
	if !strings.Contains(delivered, schedGlobexSummary) {
		t.Errorf("the scheduled platform report lost globex's alert too:\n%s", delivered)
	}
}

// TestScheduledReportDatasetHonoursTheRestriction covers the OTHER renderer the
// same dataset feeds: buildViewModel (the structured HTML/Excel/PDF pipeline),
// so the fix cannot hold for the notify body and miss the attachment.
func TestScheduledReportDatasetHonoursTheRestriction(t *testing.T) {
	f := newRestrictedReportFixture(t)
	o := saved.Object{ID: "fleet", Name: "fleet alerts", Type: "report"} // platform-owned: blank TenantID

	base := renderedViewModelText(f.rs.buildViewModel(o, reportSpec{Kind: "alerts_summary"}, time.Now().UTC()))
	if !strings.Contains(base, schedAcmeSummary) {
		t.Fatalf("baseline: the platform ViewModel does not contain acme's alert — the fixture does not reach the dataset:\n%s", base)
	}

	f.restrictAcme()

	after := renderedViewModelText(f.rs.buildViewModel(o, reportSpec{Kind: "alerts_summary"}, time.Now().UTC()))
	for _, leak := range []string{schedAcmeSummary, "acme-edge", schedAcmeExpTarget} {
		if strings.Contains(after, leak) {
			t.Errorf("RESTRICTION LEAK: the platform report's ViewModel (HTML/Excel/PDF attachment) carries acme's %q:\n%s", leak, after)
		}
	}
	if !strings.Contains(after, schedGlobexSummary) {
		t.Errorf("the platform ViewModel lost globex's alert:\n%s", after)
	}
}

// drain takes and clears everything the channel has been handed, so each
// delivery in a test is read in isolation.
func (c *recordingChannel) drain() []models.Alert {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.sent
	c.sent = nil
	return out
}

// renderedViewModelText flattens the structured ViewModel the HTML/Excel/PDF
// renderers consume down to the text a recipient would read out of it.
func renderedViewModelText(vm reports.ViewModel) string {
	var b strings.Builder
	b.WriteString(vm.Summary)
	b.WriteString("\n")
	for _, s := range vm.Sections {
		b.WriteString(s.Title)
		b.WriteString("\n")
		b.WriteString(s.Note)
		b.WriteString("\n")
		for _, row := range s.Rows {
			b.WriteString(strings.Join(row, " | "))
			b.WriteString("\n")
		}
	}
	return b.String()
}

// alertIDSet keys an alert slice by id.
func alertIDSet(as []models.Alert) map[string]bool {
	out := map[string]bool{}
	for _, a := range as {
		out[a.ID] = true
	}
	return out
}

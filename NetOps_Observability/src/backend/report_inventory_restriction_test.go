// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// report_inventory_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test
// for the operator-visibility restriction (Tenant.OperatorRestricted) on the
// DEVICE and TELEMETRY half of a scheduled report (tracker 303).
//
// report_scheduler_restriction_test.go closed the ALERT half of this same
// delivery path. This file closes the rest of it, and the rest of it is most of
// the report: the inventory table (device name, management address, vendor,
// last-seen), the fleet-health counts derived from it, the WAN/overlay links,
// the security findings and the CPU/memory ranking. Those do not come from the
// alert engine — they come from the device registry, ClickHouse and
// VictoriaMetrics, and a PLATFORM-owned report read all three unscoped.
//
// The assertions are on the DELIVERED artifact for the same reason: a scheduled
// report is rendered by a timer, with no operator in front of it, and handed to
// Slack/PagerDuty/webhook/SMTP. What matters is the bytes the recipient gets —
// the notify body and the ViewModel the HTML/Excel/PDF attachment is rendered
// from — not whether some internal filter was called.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/saved"
)

// The values that must not leave the box on a timer. acme-edge is the restricted
// tenant's device; the address is where it is reachable.
const (
	invAcmeDevice = "acme-edge"
	invAcmeAddr   = "10.1.0.2"
	invAcmeTunnel = "acme-branch"
	invAcmeFind   = "credential stuffing against acme-edge mgmt"
	invGlobexDev  = "globex-edge"
	invGlobexAddr = "10.2.0.2"
	invStackDev   = "stack-jump"
)

// ── a ClickHouse that actually applies the narrowing clause ──────────────────
//
// The point of this test is the DELIVERED report, so the fake cannot just return
// a fixed row set: it has to answer the query the renderer actually sent. It
// parses the IN / NOT IN lists out of the SQL and applies them the way
// ClickHouse would — a row whose device appears in a NOT IN list is dropped, and
// when the SQL carries an allow-list a row must appear in one of them to
// survive. That is exactly the semantics the report's scoping depends on, so a
// clause that is missing, or aimed at the wrong column set, shows up as leaked
// TEXT in the delivered body rather than as a passing assertion about SQL.

var sqlInListPattern = regexp.MustCompile(`(?i)(NOT\s+IN|IN)\s*\(([^)]*)\)`)

// sqlAdmits reports whether a row naming these devices survives the narrowing
// clauses in sql.
func sqlAdmits(sql string, names ...string) bool {
	named := func(list string, want []string) bool {
		for _, w := range want {
			if strings.Contains(list, "'"+w+"'") {
				return true
			}
		}
		return false
	}
	allowLists := 0
	allowed := false
	for _, m := range sqlInListPattern.FindAllStringSubmatch(sql, -1) {
		op, list := strings.ToUpper(strings.Fields(m[1])[0]), m[2]
		if op == "NOT" {
			if named(list, names) {
				return false // excluded by a deny-list
			}
			continue
		}
		allowLists++
		if named(list, names) {
			allowed = true
		}
	}
	return allowLists == 0 || allowed
}

// invLink and invFinding are the fake tables, one row per tenant. Each row is
// rendered into whichever column layout the SELECT asked for, so the fake
// answers the four tunnel shapes and three findings shapes the report renderers
// actually issue rather than one shape that happens to parse.
type invLink struct {
	local, remote, typ, status string
	latency, jitter, loss, qoe string
}

type invFinding struct {
	severity, device, summary string
}

var invLinks = []invLink{
	{invAcmeDevice, invAcmeTunnel, "ipsec", "up", "12.5", "1.2", "0.10", "91.0"},
	{invGlobexDev, "globex-branch", "ipsec", "up", "9.5", "0.8", "0.05", "95.0"},
}

var invFindings = []invFinding{
	{"critical", invAcmeDevice, invAcmeFind},
	{"warning", invGlobexDev, "port scan against globex-edge"},
}

func invTunnelRows(sql string) []string {
	var out []string
	for _, l := range invLinks {
		if !sqlAdmits(sql, l.local, l.remote) {
			continue
		}
		var cols []string
		switch {
		case strings.Contains(sql, "round(qoe,1)"): // DatasetWAN
			cols = []string{l.local, l.remote, l.typ, l.status, l.latency, l.jitter, l.loss, l.qoe}
		case strings.Contains(sql, "round(qoe,2)"): // RenderWANUtilization
			cols = []string{l.local, l.remote, l.typ, l.status, l.loss, l.qoe}
		default: // DatasetLatency / RenderLatencyJitterSLA
			cols = []string{l.local, l.remote, l.status, l.latency, l.jitter, l.loss}
		}
		out = append(out, strings.Join(cols, "\t"))
	}
	return out
}

func invFindingRows(sql string) []string {
	var out []string
	for _, fnd := range invFindings {
		if !sqlAdmits(sql, fnd.device) {
			continue
		}
		var cols []string
		switch {
		case strings.Contains(sql, "SELECT severity, count()"):
			cols = []string{fnd.severity, "1"}
		case strings.Contains(sql, "SELECT device, count()"):
			cols = []string{fnd.device, "1"}
		default: // SELECT severity, device, summary
			cols = []string{fnd.severity, fnd.device, fnd.summary}
		}
		out = append(out, strings.Join(cols, "\t"))
	}
	return out
}

// invFakeClickHouse answers the tunnels and findings reads a report issues.
func invFakeClickHouse(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("fake clickhouse: read body: %v", err)
			http.Error(w, "read", http.StatusInternalServerError)
			return
		}
		sql := string(body)
		var rows []string
		switch {
		case strings.Contains(sql, "netops.tunnels"):
			rows = invTunnelRows(sql)
		case strings.Contains(sql, "netops.findings"):
			rows = invFindingRows(sql)
		}
		if _, err := io.WriteString(w, strings.Join(rows, "\n")); err != nil {
			t.Errorf("fake clickhouse: write: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
}

// invFakeVictoria answers device_cpu_percent / device_mem_percent with one
// series per tenant device, keyed on the `device` label the reports read.
func invFakeVictoria(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		payload := map[string]any{"data": map[string]any{"result": []map[string]any{
			{"metric": map[string]string{"device": invAcmeDevice}, "value": []any{0, "97"}},
			{"metric": map[string]string{"device": invGlobexDev}, "value": []any{0, "41"}},
			{"metric": map[string]string{"device": invStackDev}, "value": []any{0, "12"}},
		}}}
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			t.Errorf("fake victoria: encode: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("VICTORIA_URL", srv.URL)
}

// invReportText is the DELIVERED text of a platform-owned schedule of one kind:
// the notify body a channel receives AND the ViewModel the HTML/Excel/PDF
// attachment is rendered from, concatenated, so a fix that holds for one and
// misses the other cannot pass.
func (f *restrictedReportFixture) invReportText(t *testing.T, id, kind string) string {
	t.Helper()
	body := f.deliverReport(id)
	o, spec := f.savedReport(id)
	attachment := renderedViewModelText(f.rs.buildViewModel(o, spec, time.Now().UTC()))
	if spec.Kind != kind {
		t.Fatalf("report %q has kind %q, want %q", id, spec.Kind, kind)
	}
	return body + "\n" + attachment
}

// TestScheduledReportInventoryAndTelemetryHonourTheRestriction is the
// two-halves §3a rule-5 test over every non-alert dataset a schedule delivers.
func TestScheduledReportInventoryAndTelemetryHonourTheRestriction(t *testing.T) {
	invFakeClickHouse(t)
	invFakeVictoria(t)
	f := newRestrictedReportFixture(t)

	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	acmeAdmin := jwtClaims{Sub: "admin@acme", Role: RoleSuperAdmin, Tenant: f.acme}

	// One PLATFORM-owned schedule per dataset, each bound to the platform notify
	// channel — the shape that carries a restricted tenant off the box on a timer.
	kinds := []string{"device_inventory", "health_summary", "wan_utilization", "security_threats", "device_utilization", "latency_jitter_sla"}
	ids := map[string]string{}
	for _, k := range kinds {
		ids[k] = createReport(t, f.s, owner, "fleet "+k,
			`{"kind":"`+k+`","enabled":true,"interval_minutes":60,"channels":["ops-slack"]}`)
	}
	// acme's OWN inventory schedule — it must be untouched by the switch.
	acmeRpt := createReport(t, f.s, acmeAdmin, "acme inventory",
		`{"kind":"device_inventory","enabled":true,"interval_minutes":60}`)

	// ── baseline: the delivered platform reports DO carry acme today. Named
	//    values, so a failure says WHAT leaked. ──
	baseline := map[string][]string{
		"device_inventory":   {invAcmeDevice, invAcmeAddr, "3 device(s)"},
		"health_summary":     {"3 devices"},
		"wan_utilization":    {invAcmeDevice, invAcmeTunnel, "2 WAN/overlay link(s)"},
		"security_threats":   {invAcmeDevice, invAcmeFind},
		"device_utilization": {invAcmeDevice, "97%"},
		"latency_jitter_sla": {invAcmeDevice, invAcmeTunnel},
	}
	base := map[string]string{}
	for _, k := range kinds {
		base[k] = f.invReportText(t, ids[k], k)
		for _, want := range baseline[k] {
			if !strings.Contains(base[k], want) {
				t.Fatalf("baseline: the delivered %s report does not contain %q — the fixture does not reach the dataset:\n%s", k, want, base[k])
			}
		}
	}
	// acme's own delivered inventory, captured BEFORE the switch.
	acmeBefore := f.renderReport(acmeRpt)
	if !strings.Contains(acmeBefore, invAcmeDevice) || !strings.Contains(acmeBefore, invAcmeAddr) {
		t.Fatalf("baseline: acme's own inventory report does not list its own device:\n%s", acmeBefore)
	}

	f.restrictAcme()

	// ── half 1: the platform (cross-tenant) reports drop the restricted tenant,
	//    and keep everything else. ──
	leaks := map[string][]string{
		"device_inventory":   {invAcmeDevice, invAcmeAddr},
		"health_summary":     {},
		"wan_utilization":    {invAcmeDevice, invAcmeTunnel},
		"security_threats":   {invAcmeDevice, invAcmeFind},
		"device_utilization": {invAcmeDevice},
		"latency_jitter_sla": {invAcmeDevice, invAcmeTunnel},
	}
	survives := map[string][]string{
		"device_inventory":   {invGlobexDev, invGlobexAddr, invStackDev, "2 device(s)"},
		"health_summary":     {"2 devices"},
		"wan_utilization":    {invGlobexDev, "1 WAN/overlay link(s)"},
		"security_threats":   {invGlobexDev, "port scan against globex-edge"},
		"device_utilization": {invGlobexDev, invStackDev},
		"latency_jitter_sla": {invGlobexDev},
	}
	for _, k := range kinds {
		after := f.invReportText(t, ids[k], k)
		for _, leak := range leaks[k] {
			if strings.Contains(after, leak) {
				t.Errorf("RESTRICTION LEAK: the DELIVERED %s report carries acme's %q off the box on a timer:\n%s", k, leak, after)
			}
		}
		for _, want := range survives[k] {
			if !strings.Contains(after, want) {
				t.Errorf("restricting acme also removed %q from the delivered %s report — an unrestricted tenant and the platform's own devices must be unmoved:\n%s", want, k, after)
			}
		}
	}

	// ── half 2: the restricted tenant's OWN scheduled report is unchanged. The
	//    switch hides a tenant from the PLATFORM, never from itself. ──
	acmeAfter := f.renderReport(acmeRpt)
	if acmeAfter != acmeBefore {
		t.Errorf("the restriction changed acme's OWN inventory report.\nbefore:\n%s\nafter:\n%s", acmeBefore, acmeAfter)
	}
	if !strings.Contains(acmeAfter, invAcmeDevice) || !strings.Contains(acmeAfter, invAcmeAddr) {
		t.Errorf("the restriction took acme's own device out of acme's own report:\n%s", acmeAfter)
	}
	for _, foreign := range []string{invGlobexDev, invGlobexAddr} {
		if strings.Contains(acmeAfter, foreign) {
			t.Errorf("CROSS-TENANT LEAK: acme's own inventory report names globex's %q:\n%s", foreign, acmeAfter)
		}
	}
}

// TestScheduledReportDeviceScopeDoesNotInheritBreakGlass is the device twin of
// TestScheduledReportDoesNotInheritBreakGlass. Break-glass is a live, time-boxed
// session an operator opens for itself; a timer holds none, and a schedule that
// inherited one would keep printing a restricted tenant's inventory into every
// delivery after the session expired.
func TestScheduledReportDeviceScopeDoesNotInheritBreakGlass(t *testing.T) {
	f := newRestrictedReportFixture(t)
	bs, err := newBindingStore(t.TempDir() + "/role_bindings.json")
	if err != nil {
		t.Fatalf("newBindingStore: %v", err)
	}
	f.s.bindings = bs
	f.restrictAcme()

	exp := time.Now().UTC().Add(30 * time.Minute)
	if _, err := bs.Add(RoleBinding{
		PrincipalID: "root", RoleID: RoleSuperAdmin, ScopeID: scopeTenant(f.acme),
		Effect: EffectAllow, Condition: map[string]any{conditionBreakGlass: true}, ExpiresAt: &exp,
	}); err != nil {
		t.Fatalf("open break-glass: %v", err)
	}
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	if vis := f.s.deviceVisibilityFor(owner); vis.hides(f.acme) {
		t.Fatalf("premise broken: the operator's own device view is still hiding acme despite a live session")
	}

	o := saved.Object{ID: "fleet", Name: "fleet inventory", Type: "report"} // platform-owned
	got := renderedViewModelText(f.rs.buildViewModel(o, reportSpec{Kind: "device_inventory"}, time.Now().UTC()))
	for _, leak := range []string{invAcmeDevice, invAcmeAddr} {
		if strings.Contains(got, leak) {
			t.Errorf("RESTRICTION LEAK: the scheduled platform report inherited an operator's break-glass session and printed acme's %q:\n%s", leak, got)
		}
	}
	if !strings.Contains(got, invGlobexDev) || !strings.Contains(got, invStackDev) {
		t.Errorf("the scheduled platform report lost globex's and the platform's own devices too:\n%s", got)
	}
}

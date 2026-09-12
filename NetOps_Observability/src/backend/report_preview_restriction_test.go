// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// report_preview_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test
// for POST /api/reports/preview (tracker 302).
//
// The preview renders a report's dataset on demand, without enqueuing a job or
// delivering anything, by stamping the CALLER's tenant onto a synthetic
// saved.Object and handing it to the scheduler's dataset builder. That builder
// resolves a run's visibility from the REPORT'S OWN tenant, which is right for a
// schedule — a tenant-owned report is that tenant's own view, and the
// operator-visibility switch hides a tenant from the PLATFORM, never from
// itself. It is wrong for the preview: an operator asking with
// ?as_tenant=<restricted> arrives wearing the tenant's own clothes, and the
// route answered 200 with the tenant's alerts, devices, WAN links, findings and
// CPU in the body.
//
// So the gate is at the handler, where the CALLER's scope is still known, and
// this test drives the real route: the HTTP handler, both output formats, the
// operator's Global view, the operator scoped into the restricted tenant, the
// operator scoped into an UNRESTRICTED one, and the restricted tenant's own
// admin — whose preview must be untouched.

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

// previewBody drives POST /api/reports/preview and returns status + body.
//
// The ?as_tenant= query parameter is how the switcher reaches this route in
// production; the middleware validates it and stamps ActingTenant on the claims
// (withActingTenant), and principalTenant reads it from there. A direct handler
// test has no middleware, so the claims carry it AND the URL says it — the URL
// because that is the request being described, the claims because that is what
// the handler actually reads.
func previewBody(t *testing.T, s *server, claims jwtClaims, format, body string) (int, string) {
	t.Helper()
	path := "/api/reports/preview"
	if act := strings.TrimSpace(claims.ActingTenant); act != "" {
		path += "?as_tenant=" + act
	}
	if format != "" {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		path += sep + "format=" + format
	}
	w := httptest.NewRecorder()
	s.handleReportPreview(w, req("POST", path, body, claims))
	return w.Code, w.Body.String()
}

// previewKinds is the dataset set this route exposes — every one of them is
// gathered by the same builder, so the gate either closes all of them or none.
var previewKinds = []string{"alerts_summary", "device_inventory", "health_summary", "wan_utilization", "security_threats", "device_utilization", "latency_jitter_sla"}

func previewSpec(kind string) string {
	return `{"name":"preview","body":{"kind":"` + kind + `"}}`
}

// TestReportPreviewHonoursTheOperatorVisibilityRestriction is the two-halves
// §3a rule-5 test for the route.
func TestReportPreviewHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	invFakeClickHouse(t)
	invFakeVictoria(t)
	f := newRestrictedReportFixture(t)

	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	ownerIntoAcme := ownerActing(owner, f.acme)
	ownerIntoGlobex := ownerActing(owner, f.globex)
	acmeAdmin := jwtClaims{Sub: "admin@acme", Role: RoleSuperAdmin, Tenant: f.acme}

	// Every value the restricted tenant owns that this route can render.
	acmeValues := []string{schedAcmeSummary, schedAcmeExpTarget, invAcmeDevice, invAcmeAddr, invAcmeTunnel, invAcmeFind}

	// ── baseline: the operator's ?as_tenant=acme preview DOES serve acme today.
	//    Without this the assertions below could pass on a route that renders
	//    nothing for everybody. ──
	before := map[string]string{}
	for _, kind := range previewKinds {
		code, body := previewBody(t, f.s, ownerIntoAcme, "", previewSpec(kind))
		if code != 200 {
			t.Fatalf("baseline: preview %s = %d, want 200:\n%s", kind, code, body)
		}
		before[kind] = body
	}
	seen := 0
	for _, v := range acmeValues {
		for _, kind := range previewKinds {
			if strings.Contains(before[kind], v) {
				seen++
				break
			}
		}
	}
	if seen != len(acmeValues) {
		t.Fatalf("baseline: only %d of acme's %d values reach the preview — the fixture does not exercise the route", seen, len(acmeValues))
	}
	// The restricted tenant's OWN preview, captured BEFORE the switch.
	acmeOwn := map[string]string{}
	for _, kind := range previewKinds {
		_, body := previewBody(t, f.s, acmeAdmin, "", previewSpec(kind))
		acmeOwn[kind] = body
	}
	if !strings.Contains(acmeOwn["alerts_summary"], schedAcmeSummary) || !strings.Contains(acmeOwn["device_inventory"], invAcmeDevice) {
		t.Fatalf("baseline: acme's own preview does not show acme's own data:\n%s\n%s", acmeOwn["alerts_summary"], acmeOwn["device_inventory"])
	}

	f.restrictAcme()

	// ── half 1: ?as_tenant into the restricted tenant is served nothing — 200
	//    with an empty report, never a 403 that would confirm what it refuses. ──
	for _, kind := range previewKinds {
		for _, format := range []string{"", "xlsx"} {
			code, raw := previewBody(t, f.s, ownerIntoAcme, format, previewSpec(kind))
			if code != 200 {
				t.Errorf("preview %s (format %q) = %d, want 200 with an empty report — a status of its own discloses that the tenant is there to refuse:\n%s", kind, format, code, raw)
			}
			// An .xlsx is a ZIP: its cell text is DEFLATEd, so searching the
			// response bytes for a device name would find nothing whether or not
			// the workbook contains it. Read the sheets out.
			body := raw
			if format == "xlsx" {
				body = xlsxText(t, raw)
			}
			for _, leak := range acmeValues {
				if strings.Contains(body, leak) {
					t.Errorf("RESTRICTION LEAK: /api/reports/preview?as_tenant=acme (%s, format %q) answered %d with acme's %q:\n%s", kind, format, code, leak, body)
				}
			}
		}
		if body := mustPreview(t, f.s, ownerIntoAcme, previewSpec(kind)); !strings.Contains(body, "No data") {
			t.Errorf("the denied %s preview should render the ordinary no-data report, got:\n%s", kind, body)
		}
	}

	// ── an UNRESTRICTED tenant is unmoved under the same switcher. ──
	for _, kind := range []string{"alerts_summary", "device_inventory"} {
		body := mustPreview(t, f.s, ownerIntoGlobex, previewSpec(kind))
		want := schedGlobexSummary
		if kind == "device_inventory" {
			want = invGlobexDev
		}
		if !strings.Contains(body, want) {
			t.Errorf("restricting acme also emptied the owner→globex %s preview (want %q):\n%s", kind, want, body)
		}
	}

	// ── the operator's GLOBAL preview keeps the platform's own data and drops
	//    the restricted tenant (the platform-scope half, resolved by the report
	//    scheduler rather than by this gate). ──
	global := mustPreview(t, f.s, owner, previewSpec("device_inventory"))
	for _, leak := range []string{invAcmeDevice, invAcmeAddr} {
		if strings.Contains(global, leak) {
			t.Errorf("RESTRICTION LEAK: the owner's GLOBAL preview carries acme's %q:\n%s", leak, global)
		}
	}
	for _, want := range []string{invGlobexDev, invStackDev} {
		if !strings.Contains(global, want) {
			t.Errorf("the owner's Global preview lost %q — an unrestricted tenant and the platform's own devices must survive:\n%s", want, global)
		}
	}

	// ── half 2: the restricted tenant's OWN preview is unchanged. The switch
	//    hides a tenant from the platform, never from itself. ──
	//
	// Compared by MARKER SET rather than byte-for-byte: every report stamps its
	// own generation time and renders ages ("just now", "2m ago"), so two
	// renders a second apart are never identical bytes and an equality check
	// would be a clock test wearing an isolation test's name. The markers are
	// what the rule is about — whose data is in the report, and how much of it.
	for _, kind := range previewKinds {
		_, body := previewBody(t, f.s, acmeAdmin, "", previewSpec(kind))
		gotBefore, gotAfter := previewMarkers(acmeOwn[kind]), previewMarkers(body)
		if strings.Join(gotBefore, "|") != strings.Join(gotAfter, "|") {
			t.Errorf("the restriction changed acme's OWN %s preview: %v before, %v after\nafter:\n%s",
				kind, gotBefore, gotAfter, body)
		}
		for _, foreign := range []string{schedGlobexSummary, invGlobexDev, invGlobexAddr} {
			if strings.Contains(body, foreign) {
				t.Errorf("CROSS-TENANT LEAK: acme's own %s preview names globex's %q:\n%s", kind, foreign, body)
			}
		}
	}
	if got := previewMarkers(acmeOwn["alerts_summary"]); !strings.Contains(strings.Join(got, "|"), schedAcmeSummary) {
		t.Errorf("acme's own preview lost acme's own alert: %v", got)
	}
}

// previewMarkers is the fingerprint the "own view is unmoved" check compares:
// which of the fixture's named values — each tenant's alerts, devices,
// addresses, links and findings, and the COUNTS derived from them — the report
// contains, in a fixed order. A restriction that took anything away from the
// tenant's own report, or added anything to it, moves this list.
func previewMarkers(body string) []string {
	var out []string
	for _, m := range []string{
		schedAcmeSummary, schedAcmeExpTarget, invAcmeDevice, invAcmeAddr, invAcmeTunnel, invAcmeFind,
		schedGlobexSummary, invGlobexDev, invGlobexAddr,
		schedStackSummary, invStackDev,
		"1 device(s)", "2 device(s)", "3 device(s)",
		"1 active alert(s)", "2 active alert(s)", "3 active alert(s)", "4 active alert(s)",
		"1 devices", "2 devices", "3 devices",
		"1 link(s)", "2 link(s)",
	} {
		if strings.Contains(body, m) {
			out = append(out, m)
		}
	}
	return out
}

// mustPreview is previewBody with the 200 asserted, for the reads whose status
// is not itself under test.
func mustPreview(t *testing.T, s *server, claims jwtClaims, body string) string {
	t.Helper()
	code, out := previewBody(t, s, claims, "", body)
	if code != 200 {
		t.Fatalf("preview = %d, want 200:\n%s", code, out)
	}
	return out
}

// xlsxText returns the readable text of an .xlsx response: every entry in the
// workbook ZIP concatenated, which is where the sheet XML and the shared-string
// table carry the cell values. Fails the test if the bytes are not a workbook —
// a silently unreadable attachment would make every assertion below vacuous.
func xlsxText(t *testing.T, raw string) string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader([]byte(raw)), int64(len(raw)))
	if err != nil {
		t.Fatalf("xlsx preview is not a workbook (%v) — the leak assertions would read nothing", err)
	}
	var b strings.Builder
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s in xlsx preview: %v", f.Name, err)
		}
		if _, err := io.Copy(&b, rc); err != nil {
			rc.Close()
			t.Fatalf("read %s in xlsx preview: %v", f.Name, err)
		}
		if err := rc.Close(); err != nil {
			t.Fatalf("close %s in xlsx preview: %v", f.Name, err)
		}
	}
	if b.Len() == 0 {
		t.Fatal("xlsx preview workbook is empty — the leak assertions would read nothing")
	}
	return b.String()
}

package rca

// rca_inferred_service_test.go — the Azure optional-tags QA deliverable, rendered
// in-worktree. Proves the built-in service inference reaches the RCA report the
// same way a tag would: the engine attributes an untagged cloud resource to its
// INFERRED BusinessService, that name lands in the correlation object's
// affected.apps, and the report NAMES it as the affected subject — no report code
// change, no tag jargon, and the consistency/quality gate stays green.
//
// BEFORE (untagged, un-inferable): the subject is a generic descriptor, never a
// forced name, and the report NEVER mentions tags/untagged policy.
// AFTER (inferred → affected.apps): the subject is the inferred service name.
//
// This is the mechanism behind the live P-E22C5E fix: the untagged Azure fleet
// stops reading as "Untagged" because attribution (cloud/resolve.go) now names it
// by inference, and affected.apps carries that name into exactly this path.

import (
	"encoding/json"
	"strings"
	"testing"
)

// a cloud-family incident, open + fault-confirmed, mirroring the shape the merged
// P-E22C5E case carries. Reused for both the BEFORE and AFTER variants.
func inferredServiceMeta(affected string) map[string]any {
	m := testMeta("open", "confirmed", "sig.ent.cloud.status-check-failed",
		testHyp("sig.ent.cloud.status-check-failed", 0.9, "confirmed",
			[]string{"cloud_status_check_failed", "probe_loss"}, nil, nil, "netops", false))
	m["affected"] = affected
	return m
}

func inferredServiceSigs() []map[string]any {
	return []map[string]any{
		testSig("cloud_status_check_failed", "device_telemetry", "cloud_provider", "device",
			"/subscriptions/s/resourceGroups/rg-payments-prod/providers/Microsoft.Compute/virtualMachines/web01",
			"crit", "2026-07-12 18:12:00", true, nil),
		testSig("probe_loss", "active_probe", "prober", "path", "prober->10.1.0.11", "crit",
			"2026-07-12 18:12:30", true, map[string]any{"probe_scope": "customer_path"}),
	}
}

// tag jargon a NOC report must NEVER contain (mission requirement #4).
var tagJargon = []string{"untagged", "missing tag", "tag policy", "please tag", "add a tag", "tag enforcement"}

func assertNoTagJargon(t *testing.T, rep Report) {
	t.Helper()
	blob, _ := json.Marshal(rep)
	low := strings.ToLower(string(blob))
	for _, j := range tagJargon {
		if strings.Contains(low, j) {
			t.Fatalf("RCA report leaked tag jargon %q — reports must not mention tag policy", j)
		}
	}
}

func TestRcaInferredService_BeforeAfter(t *testing.T) {
	// BEFORE: no service attributed (untagged + un-inferable) → generic subject.
	before := buildTestReport(t, inferredServiceMeta("{}"), inferredServiceSigs())
	if !before.Quality.Passed {
		t.Fatalf("BEFORE quality gate failed: %+v", before.Quality.Errors)
	}
	if strings.Contains(before.Summary.Management, "payments") {
		t.Fatalf("BEFORE must NOT name a service it cannot attribute: %q", before.Summary.Management)
	}
	// Generic descriptor, never a forced name or a raw ARM id in the prose.
	if strings.Contains(before.Summary.Management, "resourceGroups") {
		t.Fatalf("BEFORE subject leaked a raw resource id: %q", before.Summary.Management)
	}
	assertNoTagJargon(t, before)

	// AFTER: the engine attributed the untagged VM to its inferred service; the
	// name rides affected.apps into the report subject.
	after := buildTestReport(t, inferredServiceMeta(`{"apps":["payments"]}`), inferredServiceSigs())
	if !after.Quality.Passed {
		t.Fatalf("AFTER quality gate failed: %+v", after.Quality.Errors)
	}
	if !strings.Contains(after.Summary.Management, "payments") {
		t.Fatalf("AFTER must name the inferred service 'payments' as the subject: %q", after.Summary.Management)
	}
	assertNoTagJargon(t, after)

	// No "Closed" contradiction: an open, still-observed incident must not claim
	// recovery/closure (the merged-incident lifecycle hardening must not regress).
	if after.States.Recovery == "explicitly_confirmed" {
		t.Fatalf("AFTER falsely claims confirmed recovery with no recovery evidence: %+v", after.States)
	}
	if strings.Contains(strings.ToLower(after.Summary.Management), "closed") {
		t.Fatalf("AFTER management summary claims 'closed' on an open incident: %q", after.Summary.Management)
	}
}

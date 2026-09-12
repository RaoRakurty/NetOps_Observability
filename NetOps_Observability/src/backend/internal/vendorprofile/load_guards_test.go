// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package vendorprofile

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

// loadDocs builds a registry from SEVERAL synthetic vendor documents. The load
// order is the sorted file name, exactly as Load sees a real profile directory,
// so a "whichever document loads second wins" defect is reproducible here.
func loadDocs(t *testing.T, docs ...map[string]any) (*Registry, error) {
	t.Helper()
	fsys := fstest.MapFS{}
	for _, doc := range docs {
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		fsys["p/"+doc["vendor"].(string)+".json"] = &fstest.MapFile{Data: b}
	}
	return Load(fsys, "p")
}

// ── 3.5-17: os_version_pattern must carry a capture group ────────────────────

// TestLoaderRejectsGrouplessOSVersionPattern — the pattern is read as
// "capture group 1 is the version" by ResolveOS. A pattern with NO group
// compiles cleanly, loads cleanly, and then indexes m[1] out of range on the
// first sysDescr that matches it — a panic on an SNMP-fed request path. The
// loader must refuse it, naming the field.
func TestLoaderRejectsGrouplessOSVersionPattern(t *testing.T) {
	doc := goodDoc()
	doc["detection"].(map[string]any)["os_version_pattern"] = `(?i)\bAcmeOS[ :]+[0-9.]+`
	_, err := loadDoc(t, doc)
	if err == nil {
		t.Fatal("a groupless os_version_pattern was accepted; ResolveOS would panic on m[1]")
	}
	if !strings.Contains(err.Error(), "os_version_pattern") {
		t.Fatalf("error does not name the offending field: %v", err)
	}
	if !strings.Contains(err.Error(), "capture group") {
		t.Fatalf("error does not say what is wrong (a missing capture group): %v", err)
	}
}

// TestLoaderAcceptsAGroupedOSVersionPattern pins that the new guard rejects
// ONLY the groupless shape — the shipped documents' patterns stay legal.
func TestLoaderAcceptsAGroupedOSVersionPattern(t *testing.T) {
	if _, err := loadDoc(t, goodDoc()); err != nil {
		t.Fatalf("a valid grouped os_version_pattern was rejected: %v", err)
	}
}

// TestResolveOSDoesNotPanicOnAGrouplessPattern is the DEFENSIVE half. The
// loader now refuses to build this state, so the registry is constructed
// directly (same package) — a future data or code change must not be able to
// turn a matching sysDescr into a process-killing panic on a request path.
func TestResolveOSDoesNotPanicOnAGrouplessPattern(t *testing.T) {
	r := &Registry{
		osParse: map[string]vendorOSParse{
			"acme": {
				versionRe: regexp.MustCompile(`(?i)acmeos [0-9.]+`),
				products:  []productRule{{rank: 1, product: "acmeos"}},
			},
		},
	}
	id, ok := r.ResolveOS("acme", "Acme Networks AcmeOS 15.2, build 7")
	if !ok {
		t.Fatal("ResolveOS refused a vendor it has an os_parse table for")
	}
	if id.Product != "acmeos" {
		t.Fatalf("product = %q, want %q", id.Product, "acmeos")
	}
	if id.Version != "" {
		t.Fatalf("version = %q, want empty (the pattern captures nothing)", id.Version)
	}
}

// TestBuildDoesNotPanicOnAGrouplessPatternRoundTrip covers the SECOND m[1] on
// this regexp: the os_version_probe round-trip check in build(). build is fed
// documents directly here because the decoder now refuses this shape upstream.
func TestBuildDoesNotPanicOnAGrouplessPatternRoundTrip(t *testing.T) {
	doc := vendorDoc{
		SchemaVersion: SchemaVersion,
		Vendor:        "acme",
		DisplayName:   "Acme",
		Detection:     Detection{OSVersionPattern: `(?i)acmeos [0-9.]+`},
		Profiles: []Profile{{
			Platform:    "acmeos",
			DisplayName: "Acme AcmeOS",
			OSVersionProbe: OSVersionProbe{
				CLIVersionPattern: `AcmeOS ([0-9.]+)`,
				VersionRender:     "AcmeOS " + OSVersionProbeVersionToken,
			},
		}},
	}
	_, err := build([]vendorDoc{doc})
	if err == nil {
		t.Fatal("build accepted an os_version_pattern that captures nothing")
	}
	if !strings.Contains(err.Error(), "os_version_pattern") {
		t.Fatalf("error does not name the offending field: %v", err)
	}
}

// ── 3.5-18: a capture family id is claimed exactly once ──────────────────────

// captureDoc is a minimal valid vendor document that PARTICIPATES in config
// capture, so the capture-family index is exercised.
func captureDoc(vendor string, rank int, enterprise, cmd string, dialects []any) map[string]any {
	doc := goodDoc()
	doc["vendor"] = vendor
	doc["display_name"] = strings.ToUpper(vendor)
	det := doc["detection"].(map[string]any)
	det["sysobjectid_prefixes"] = []string{"1.3.6.1.4.1." + enterprise}
	det["sysdescr_contains"] = []string{vendor + "os"}
	det["sysdescr_rank"] = rank
	det["os_version_pattern"] = `(?i)\b` + vendor + `OS[ :]+([0-9.]+)`
	doc["dialect"] = map[string]any{"vrf_term": "VRF", "vrf_term_keys": []string{vendor}}
	prof := doc["profiles"].([]any)[0].(map[string]any)
	prof["platform"] = vendor + "os"
	prof["display_name"] = vendor + " os"
	prof["detection"] = map[string]any{"os_parse": map[string]any{
		"product": vendor + "os", "sysdescr_contains_any": []string{}, "rank": 1,
	}}
	prof["advisory"] = map[string]any{"provider": "offline-feed", "product_ids": []string{vendor + "os"}}
	cc := map[string]any{
		"platform_contains":  []string{vendor},
		"platform_rank":      rank,
		"running_config_cmd": cmd,
		"volatile_rules": []any{map[string]any{
			"name": vendor + "-clock", "pattern": `^! time: `,
		}},
	}
	if len(dialects) > 0 {
		cc["platform_dialects"] = dialects
	}
	doc["config_capture"] = cc
	return doc
}

// TestCaptureFamilyIDMayBeClaimedOnlyOnce — a vendor id and a sibling dialect
// id share ONE namespace (both are keys of the capture-family index). The
// collision check used to run in one direction only: a dialect was checked
// against the families already registered, but a VENDOR id was written
// unconditionally. So a vendor document whose id equalled an earlier document's
// dialect id silently overwrote that family's running-config command and
// unioned both families' volatile rules — whichever loaded second won, with no
// error. The load must be REFUSED, naming both claimants.
func TestCaptureFamilyIDMayBeClaimedOnlyOnce(t *testing.T) {
	acme := captureDoc("acme", 1, "99991", "show running-config", []any{map[string]any{
		"id":                 "brand",
		"platform_contains":  []string{"brandos"},
		"platform_rank":      7,
		"running_config_cmd": "info from running flat",
		"volatile_rules": []any{map[string]any{
			"name": "brand-uptime", "pattern": `^# uptime `,
		}},
	}})
	brand := captureDoc("brand", 2, "99992", "display current-configuration", nil)

	reg, err := loadDocs(t, acme, brand)
	if err == nil {
		// Pre-fix behaviour: the load succeeds and the "brand" capture family
		// silently belongs to whichever document loaded second. Show it.
		cmd, _ := reg.ConfigCaptureCommand("brand")
		t.Fatalf("two documents both claimed the capture family %q and the load succeeded; "+
			"ConfigCaptureCommand(%q) = %q (the dialect declared %q), volatile rules = %v",
			"brand", "brand", cmd, "info from running flat", reg.ConfigVolatileRuleNames("brand"))
	}
	msg := err.Error()
	for _, want := range []string{"brand", "acme"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("collision error does not name claimant %q: %v", want, err)
		}
	}
}

// TestCaptureFamilySelfClaimIsStillLegal — the fix must not break the ordinary
// case where one vendor document claims its OWN id once and ships a sibling
// dialect beside it.
func TestCaptureFamilySelfClaimIsStillLegal(t *testing.T) {
	acme := captureDoc("acme", 1, "99991", "show running-config", []any{map[string]any{
		"id":                 "acmelinux",
		"platform_contains":  []string{"acmelinux"},
		"platform_rank":      7,
		"running_config_cmd": "info from running flat",
	}})
	reg, err := loadDocs(t, acme)
	if err != nil {
		t.Fatalf("a vendor and its own sibling dialect were rejected: %v", err)
	}
	if cmd, ok := reg.ConfigCaptureCommand("acme"); !ok || cmd != "show running-config" {
		t.Fatalf("vendor family command = %q (ok=%v)", cmd, ok)
	}
	if cmd, ok := reg.ConfigCaptureCommand("acmelinux"); !ok || cmd != "info from running flat" {
		t.Fatalf("dialect family command = %q (ok=%v)", cmd, ok)
	}
}

// TestCaptureDialectMayNotClaimItsOwnVendorID — the same namespace rule in the
// other direction, for a vendor that does NOT otherwise participate in config
// capture (the one shape the pre-existing dialect-side check could miss).
func TestCaptureDialectMayNotClaimItsOwnVendorID(t *testing.T) {
	doc := goodDoc()
	doc["config_capture"] = map[string]any{
		"platform_dialects": []any{map[string]any{
			"id":                 "acme",
			"platform_contains":  []string{"acme"},
			"platform_rank":      7,
			"running_config_cmd": "info from running flat",
		}},
	}
	if _, err := loadDocs(t, doc); err == nil {
		t.Fatal("a dialect claimed its own vendor id and the load succeeded")
	}
}

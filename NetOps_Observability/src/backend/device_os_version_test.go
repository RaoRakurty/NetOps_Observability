// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// device_os_version_test.go — tracker 231, at the HTTP boundary.
//
// The reference lab's two Nokia SR Linux spines are hand-authored device rows:
// the platform's ACL refuses the collector host, so there is no sysDescr to
// parse, and the row carries `os: "SR Linux"` — a product label with no
// version. `/api/vulns` therefore reported both devices UNASSESSED forever.
// That was the honest answer (§5g: never "not vulnerable" without a version),
// but it was permanent: no reachable transport could ever supply the version.
//
// The device row now carries the version leaf itself, whatever learned it. What
// is proven here: a row with the leaf is ASSESSED and its CVEs are reported; a
// row without one is still honestly unassessed and SAYS which field is missing;
// and the leaf does not become a way around tenant scope.

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"netops/backend/internal/vuln"
	"netops/backend/models"
)

// srlVersionLeaf is what lab spine1/spine2 actually report — read over gNMI
// /system/information on 2026-09-03, byte-identical on both, and the same
// string SR Linux answers sysDescr.0 with.
const srlVersionLeaf = "SRLinux-v26.3.2-426-g2b38957bbca 7220 IXR-D3L Copyright (c) 2000-2026 Nokia."

// seedSRLinuxAdvisory wires a feed with one SR Linux CVE covering 26.3.2.
func seedSRLinuxAdvisory(t *testing.T, s *server) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "advisories.csv")
	csvData := `vendor,product,cve,severity,cvss,ver_start_incl,ver_start_excl,ver_end_incl,ver_end_excl,ver_exact,kev,published,summary
nokia,srlinux,CVE-2026-9001,high,8.1,26.0.0,,26.4.0,,,0,2026-08-01,SR Linux range advisory
`
	if err := os.WriteFile(path, []byte(csvData), 0o600); err != nil {
		t.Fatal(err)
	}
	s.vulns = vuln.NewFeed(path, nil, nil)
}

// srlVulnsBody extends the shared vulnsBody shape with the `assessed` counter,
// which is the number this row is about: how many devices had a version to
// compare at all.
type srlVulnsBody struct {
	Summary struct {
		Assessed int `json:"assessed"`
	} `json:"summary"`
	Findings []struct {
		DeviceID string `json:"device_id"`
		CVE      string `json:"cve"`
	} `json:"findings"`
	Unassessed []struct {
		DeviceID string `json:"device_id"`
		Reason   string `json:"reason"`
	} `json:"unassessed"`
}

func vulnsPage(t *testing.T, srv *httptest.Server, token, path string) srlVulnsBody {
	t.Helper()
	st, b := do(t, srv, "GET", path, token, nil)
	if st != 200 {
		t.Fatalf("%s: status %d: %s", path, st, truncBody(b))
	}
	var body srlVulnsBody
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatalf("%s: decode: %v (%s)", path, err, truncBody(b))
	}
	return body
}

// TestVulnsAssessesADeviceWhoseVersionCameFromTheRowNotSysDescr is the row's
// regression test: the spine as it exists in the lab, plus the version leaf.
func TestVulnsAssessesADeviceWhoseVersionCameFromTheRowNotSysDescr(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	seedSRLinuxAdvisory(t, s)

	// spine1 as the lab has it, plus the leaf. spine2 as the lab has it today.
	if err := s.discovery.Upsert(models.Device{
		ID: "spine1", Name: "spine1", Address: "172.40.40.11", Source: "test",
		Vendor: "nokia", OS: "SR Linux", OSVersion: srlVersionLeaf,
	}); err != nil {
		t.Fatalf("upsert spine1: %v", err)
	}
	if err := s.discovery.Upsert(models.Device{
		ID: "spine2", Name: "spine2", Address: "172.40.40.12", Source: "test",
		Vendor: "nokia", OS: "SR Linux",
	}); err != nil {
		t.Fatalf("upsert spine2: %v", err)
	}

	body := vulnsPage(t, srv, admin, "/api/vulns?limit=500")
	if body.Summary.Assessed != 1 {
		t.Fatalf("assessed = %d, want 1 — the row's version leaf is not reaching the assessment", body.Summary.Assessed)
	}
	if len(body.Findings) != 1 || body.Findings[0].DeviceID != "spine1" || body.Findings[0].CVE != "CVE-2026-9001" {
		t.Fatalf("findings = %+v, want one CVE-2026-9001 on spine1", body.Findings)
	}

	// spine2 is still UNASSESSED, and the reason names the field that is
	// missing — an operator has to be able to tell "no version" from "clear".
	if len(body.Unassessed) != 1 || body.Unassessed[0].DeviceID != "spine2" {
		t.Fatalf("unassessed = %+v, want exactly spine2", body.Unassessed)
	}
	if want := "OS version not present in sysDescr or os_version"; body.Unassessed[0].Reason != want {
		t.Errorf("unassessed reason = %q, want %q", body.Unassessed[0].Reason, want)
	}
}

// TestVulnsVersionLeafIsNotAWayAroundTenantScope — §3a: the new leaf changes
// what is assessed, never WHOSE devices are visible.
func TestVulnsVersionLeafIsNotAWayAroundTenantScope(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	seedSRLinuxAdvisory(t, s)

	orgA := idOf(t, mustDo(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org Alpha"}, 201))
	orgB := idOf(t, mustDo(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org Bravo"}, 201))
	tenantA := idOf(t, mustDo(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant Alpha", "org_id": orgA}, 201))
	tenantB := idOf(t, mustDo(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant Bravo", "org_id": orgB}, 201))
	mustDo(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "srl-a", "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantA}, 201)
	tokA := login(t, srv, "srl-a", "Passw0rd!2345").Token

	for i, tenant := range []string{tenantA, tenantB} {
		if err := s.discovery.Upsert(models.Device{
			ID: fmt.Sprintf("srl-%d", i), Name: fmt.Sprintf("srl-%d", i),
			Address: fmt.Sprintf("172.40.40.%d", 11+i), Source: "test",
			Vendor: "nokia", OS: "SR Linux", OSVersion: srlVersionLeaf, TenantID: tenant,
		}); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}

	for _, path := range []string{
		"/api/vulns?limit=500",
		"/api/vulns?limit=500&as_tenant=" + tenantB, // narrowing must never widen
	} {
		body := vulnsPage(t, srv, tokA, path)
		if body.Summary.Assessed != 1 || len(body.Findings) != 1 {
			t.Fatalf("%s: tenant A sees assessed=%d findings=%d, want 1/1", path, body.Summary.Assessed, len(body.Findings))
		}
		if body.Findings[0].DeviceID != "srl-0" {
			t.Fatalf("%s: CROSS-TENANT LEAK — %s", path, body.Findings[0].DeviceID)
		}
		for _, u := range body.Unassessed {
			if u.DeviceID == "srl-1" {
				t.Fatalf("%s: another tenant's device appeared in unassessed", path)
			}
		}
	}
}

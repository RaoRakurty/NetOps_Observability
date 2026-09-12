// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package advisory

import (
	"context"
	"errors"
	"testing"
)

func TestMockProviderMatching(t *testing.T) {
	epss := 0.4212
	eol := true
	m := NewMockProvider("psirt-mock").
		Add("cisco", "IOS-XE", Advisory{
			CVE: "CVE-2024-20356", Severity: "critical", CVSS: 9.8, KEV: true,
			EPSS: &epss, EoLRelevant: &eol,
			AffectedVersion: VersionConstraint{EndExcl: "17.9.5"},
			Summary:         "CISCO CMD web UI RCE",
		}).
		Add("cisco", "IOS-XE", Advisory{
			CVE: "CVE-2023-20198", Severity: "high", CVSS: 8.1,
			AffectedVersion: VersionConstraint{Exact: "16.12.1"},
		}).
		Add("juniper", "junos", Advisory{
			CVE: "CVE-2024-0001", Severity: "medium",
			AffectedVersion: VersionConstraint{EndExcl: "22.0"},
		})

	got, err := m.AdvisoriesFor(context.Background(), Query{Vendor: "Cisco", Platform: "ios_xe", Version: "17.9.4a"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != 1 || got[0].CVE != "CVE-2024-20356" {
		t.Fatalf("got %+v, want single CVE-2024-20356 (range hit; exact 16.12.1 miss)", got)
	}
	if got[0].Source != "psirt-mock" {
		t.Errorf("Source = %q, want stamped provider name", got[0].Source)
	}

	// Different vendor is isolated.
	jn, err := m.AdvisoriesFor(context.Background(), Query{Vendor: "juniper", Platform: "junos", Version: "21.4"})
	if err != nil || len(jn) != 1 || jn[0].CVE != "CVE-2024-0001" {
		t.Fatalf("juniper query = %+v, err %v", jn, err)
	}

	// Assessed-but-none-apply is (nil, nil), not an error.
	none, err := m.AdvisoriesFor(context.Background(), Query{Vendor: "cisco", Platform: "ios-xe", Version: "18.0.0"})
	if err != nil || none != nil {
		t.Fatalf("expected (nil,nil) for no matches, got %+v err %v", none, err)
	}
}

func TestMockProviderFail(t *testing.T) {
	m := NewMockProvider("mock")
	m.Fail = ErrNotProvisioned
	_, err := m.AdvisoriesFor(context.Background(), Query{Vendor: "cisco", Platform: "ios-xe", Version: "1"})
	if !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("err = %v, want ErrNotProvisioned", err)
	}
}

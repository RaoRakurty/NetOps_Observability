// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package advisory

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/secfindings"
)

func TestFindingsForOffline(t *testing.T) {
	rows := "cisco,IOS-XE,CVE-2024-20356,critical,9.8,,,,17.9.5,,1,2024-01-01,web UI RCE\n"
	p := NewOfflineProvider(writeFeed(t, rows))
	dev := Device{
		Vendor: "cisco", Product: "IOS-XE", Version: "17.9.4",
		Resource: secfindings.Resource{DeviceID: "d1", DeviceName: "core-rtr-1"},
	}
	when := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	fs, err := FindingsFor(context.Background(), p, dev, EmitOptions{TenantID: "acme", ScanID: "scan-7", Now: when})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	f := fs[0]
	if f.EvidenceClass != secfindings.EvidenceExposure {
		t.Errorf("EvidenceClass = %q, want exposure", f.EvidenceClass)
	}
	if f.StatusID != secfindings.StatusFail || f.Status != "Fail" {
		t.Errorf("status = %v/%q, want Fail", f.StatusID, f.Status)
	}
	if f.Source != SourceOfflineFeed {
		t.Errorf("Source = %q, want offline-feed", f.Source)
	}
	if f.ControlID != "CVE-2024-20356" || f.RawRuleID != "CVE-2024-20356" {
		t.Errorf("CVE not on control/rule ids: %+v", f)
	}
	if f.Severity != secfindings.SeverityCritical {
		t.Errorf("Severity = %q", f.Severity)
	}
	if f.Resource.DeviceID != "d1" || f.Resource.Kind != secfindings.KindNetworkDevice {
		t.Errorf("resource wrong: %+v", f.Resource)
	}
	if f.TenantID != "acme" {
		t.Errorf("TenantID = %q, want stamped from opts (§3a)", f.TenantID)
	}
	if !containsStd(f.Standards, "CVE-2024-20356") || !containsStd(f.Standards, "CISA-KEV") {
		t.Errorf("standards missing CVE/KEV tag: %v", f.Standards)
	}
	if f.EvidenceRef == nil || f.EvidenceRef.Locator != "CVE-2024-20356" {
		t.Errorf("evidence ref not by-reference to CVE: %+v", f.EvidenceRef)
	}
	if !f.Time.Equal(when) {
		t.Errorf("Time = %v, want %v", f.Time, when)
	}
}

func TestFindingsForEnrichmentThreading(t *testing.T) {
	epss := 0.4212
	eol := true
	m := NewMockProvider("vendor-x").Add("cisco", "IOS-XE", Advisory{
		CVE: "CVE-2024-20356", Severity: "critical", CVSS: 9.8, KEV: true,
		EPSS: &epss, EoLRelevant: &eol,
		AffectedVersion: VersionConstraint{EndExcl: "17.9.5"},
		Summary:         "RCE",
	})
	dev := Device{Vendor: "cisco", Product: "IOS-XE", Version: "17.9.4"}
	fs, err := FindingsFor(context.Background(), m, dev, EmitOptions{})
	if err != nil || len(fs) != 1 {
		t.Fatalf("got %d findings, err %v", len(fs), err)
	}
	f := fs[0]
	// Non-offline provider maps to the vendor-api source category.
	if f.Source != secfindings.SourceVendorAPI {
		t.Errorf("Source = %q, want vendor-api", f.Source)
	}
	if !containsStd(f.Standards, "EPSS=0.4212") || !containsStd(f.Standards, "EoL") {
		t.Errorf("EPSS/EoL not threaded into standards: %v", f.Standards)
	}
	if !strings.Contains(f.Detail, "EPSS 42.1%") || !strings.Contains(f.Detail, "end-of-life") {
		t.Errorf("EPSS/EoL not threaded into detail: %q", f.Detail)
	}
	if f.Time.IsZero() {
		t.Error("zero Now should default to time.Now()")
	}
}

func TestFindingsForUnassessedPropagates(t *testing.T) {
	m := NewMockProvider("mock")
	m.Fail = ErrNotProvisioned
	fs, err := FindingsFor(context.Background(), m, Device{Vendor: "cisco", Product: "ios-xe", Version: "1"}, EmitOptions{})
	if fs != nil {
		t.Fatalf("findings should be nil on provider error, got %v", fs)
	}
	if !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("err = %v, want wrapped ErrNotProvisioned (unassessed, not false-clear)", err)
	}
}

func containsStd(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

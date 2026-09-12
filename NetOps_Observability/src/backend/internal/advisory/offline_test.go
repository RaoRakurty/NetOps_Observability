// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package advisory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"netops/backend/internal/vuln"
)

const feedHeader = "vendor,product,cve,severity,cvss,ver_start_incl,ver_start_excl,ver_end_incl,ver_end_excl,ver_exact,kev,published,summary\n"

func writeFeed(t *testing.T, rows string) *vuln.Feed {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "advisories.csv")
	if err := os.WriteFile(path, []byte(feedHeader+rows), 0o600); err != nil {
		t.Fatalf("write feed: %v", err)
	}
	return vuln.NewFeed(path, nil, nil)
}

func TestOfflineProviderNotProvisioned(t *testing.T) {
	// A feed pointing at a nonexistent file is "not provisioned" — unassessed,
	// never a false clear.
	p := NewOfflineProvider(vuln.NewFeed(filepath.Join(t.TempDir(), "missing.csv"), nil, nil))
	_, err := p.AdvisoriesFor(context.Background(), Query{Vendor: "cisco", Platform: "ios-xe", Version: "17.9.4"})
	if !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("err = %v, want ErrNotProvisioned", err)
	}
	// A nil feed is also not provisioned (defensive).
	if _, err := NewOfflineProvider(nil).AdvisoriesFor(context.Background(), Query{}); !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("nil feed err = %v, want ErrNotProvisioned", err)
	}
}

func TestOfflineProviderMatches(t *testing.T) {
	rows := "" +
		"cisco,IOS-XE,CVE-2024-20356,critical,9.8,,,,17.9.5,,1,2024-01-01,web UI RCE\n" +
		"cisco,IOS-XE,CVE-2023-99999,high,7.5,,,,,16.12.1,0,2023-01-01,exact only\n" +
		"juniper,junos,CVE-2024-0001,medium,5.0,,,,22.0,,0,2024-02-01,junos issue\n"
	p := NewOfflineProvider(writeFeed(t, rows))

	got, err := p.AdvisoriesFor(context.Background(), Query{Vendor: "Cisco", Platform: "ios_xe", Version: "17.9.4"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(got) != 1 || got[0].CVE != "CVE-2024-20356" {
		t.Fatalf("got %+v, want single CVE-2024-20356", got)
	}
	a := got[0]
	if a.Severity != "critical" || a.CVSS != 9.8 || !a.KEV {
		t.Errorf("advisory facts wrong: %+v", a)
	}
	if a.Source != SourceOfflineFeed {
		t.Errorf("Source = %q, want %q", a.Source, SourceOfflineFeed)
	}
	if a.EPSS != nil || a.EoLRelevant != nil {
		t.Errorf("offline feed must leave EPSS/EoL nil, got EPSS=%v EoL=%v", a.EPSS, a.EoLRelevant)
	}
	if a.AffectedVersion.EndExcl != "17.9.5" {
		t.Errorf("AffectedVersion not threaded: %+v", a.AffectedVersion)
	}

	// Assessed, none apply → (nil, nil).
	none, err := p.AdvisoriesFor(context.Background(), Query{Vendor: "cisco", Platform: "ios-xe", Version: "18.0.0"})
	if err != nil || none != nil {
		t.Fatalf("expected (nil,nil), got %+v err %v", none, err)
	}
}

// TestFabricPlatformsAreAssessableOnceTheFeedIsProvisioned closes the honest
// loop for the lab fabric (Arista EOS, Nokia SR Linux).
//
// Neither platform is "advisory-unassessed" because of anything MISSING in this
// repository's data: the profiles bind the offline-feed provider and declare
// the product ids NVD uses, and vuln.NormProduct folds NVD's `sr_linux` onto
// the `srlinux` id the profile declares. They report unassessed today for one
// reason and one reason only — the CSV feed is OPERATOR-PROVISIONED and
// air-gapped by design (VULN_FEED_PATH, prepared by scripts/vuln-feed-prepare.py),
// so no feed ships in the repository and every platform is unassessed until one
// is installed. This test proves the wiring by installing one.
func TestFabricPlatformsAreAssessableOnceTheFeedIsProvisioned(t *testing.T) {
	rows := "" +
		"arista,eos,CVE-2026-11111,high,7.8,,,4.36.1,,,0,2026-05-01,EOS issue\n" +
		"nokia,sr_linux,CVE-2026-22222,medium,5.4,,,26.4.0,,,0,2026-06-01,SR Linux issue\n"
	p := NewOfflineProvider(writeFeed(t, rows))

	for _, c := range []struct {
		vendor, platform, version, cve string
	}{
		// The version strings are the ones the devices report: cEOSLab
		// 4.36.0.1F on leaf1, SR Linux v26.3.2 on spine1.
		{"arista", "eos", "4.36.0.1F", "CVE-2026-11111"},
		{"nokia", "srlinux", "26.3.2", "CVE-2026-22222"},
	} {
		got, err := p.AdvisoriesFor(context.Background(), Query{Vendor: c.vendor, Platform: c.platform, Version: c.version})
		if err != nil {
			t.Errorf("%s/%s: %v", c.vendor, c.platform, err)
			continue
		}
		if len(got) != 1 || got[0].CVE != c.cve {
			t.Errorf("%s/%s %s = %+v, want %s", c.vendor, c.platform, c.version, got, c.cve)
		}
	}
}

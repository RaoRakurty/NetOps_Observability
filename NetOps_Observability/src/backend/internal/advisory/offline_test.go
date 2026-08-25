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

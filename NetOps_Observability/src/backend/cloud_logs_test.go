package main

import (
	"testing"

	"netops/backend/internal/oslog"
)

// The unified Cloud Logs experience indexes tagged raw cloud logs into
// netops-cloudlogs-{tenant}-{date}. These tests pin the read-path plumbing so a
// cloud-log search resolves to the right per-tenant index pattern and can NEVER
// name another tenant's cloud index (§3a — cloud logs are tenant-scoped, no
// cross-tenant leak). The doc-level clause (osTenantFilter) is the same one the
// generic log search uses and is covered by logs_tenant_test.go; here we guard
// the cloud-specific index routing that feeds it.

func TestIndexBaseCloud(t *testing.T) {
	for _, sig := range []string{"cloud", "cloudlogs", "cloudlog"} {
		if got := oslog.IndexBase(sig); got != "netops-cloudlogs" {
			t.Errorf("oslog.IndexBase(%q) = %q, want netops-cloudlogs", sig, got)
		}
	}
}

// TestTenantIndexPatternCloud: the platform owner reads every tenant's cloud
// index; a scoped tenant reads ONLY its own + the shared untagged cloud index,
// and NEVER another tenant's — even before the per-doc filter runs.
func TestTenantIndexPatternCloud(t *testing.T) {
	if got := oslog.TenantIndexPattern("cloud", "acme", true); got != "netops-cloudlogs-*" {
		t.Errorf("platform cloud = %q, want netops-cloudlogs-*", got)
	}
	scoped := oslog.TenantIndexPattern("cloud", "acme", false)
	if scoped != "netops-cloudlogs-acme-*,netops-cloudlogs-untagged-*" {
		t.Errorf("scoped cloud = %q", scoped)
	}
	// Isolation: a scoped tenant's cloud pattern must not name another tenant.
	if containsSub(scoped, "globex") {
		t.Errorf("acme cloud pattern leaked another tenant: %q", scoped)
	}
	// Cloud logs are their OWN plane — never folded into the "all" search
	// (like flows), so a bare all-signals search can't drown in cloud volume.
	for _, sig := range []string{"", "all"} {
		if pat := oslog.TenantIndexPattern(sig, "acme", false); containsSub(pat, "cloudlogs") {
			t.Errorf("oslog.TenantIndexPattern(%q) must NOT include cloud logs in 'all': %q", sig, pat)
		}
	}
}

// TestTenantCatPatternCloud: a scoped tenant can enumerate its OWN cloud indices
// (own + untagged) but not another tenant's.
func TestTenantCatPatternCloud(t *testing.T) {
	got := oslog.TenantCatPattern("acme", false)
	for _, want := range []string{"netops-cloudlogs-acme-*", "netops-cloudlogs-untagged-*"} {
		if !containsSub(got, want) {
			t.Errorf("scoped cat %q missing cloud pattern %q", got, want)
		}
	}
	if containsSub(got, "globex") {
		t.Errorf("scoped cloud cat leaked another tenant: %q", got)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// configstore_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test for
// the per-tenant OPERATOR-VISIBILITY restriction (Tenant.OperatorRestricted) on
// the configuration-backup subtree (internal/configstore).
//
// A device configuration is the most sensitive per-device artefact the product
// holds: the box's whole operational blueprint, its addressing, its neighbours
// and — even redacted — the shape of its security posture. The diff is the same
// thing again, line by line. Logs, flows, metrics, igpmon and the BMP feed all
// hide a restricted tenant from the platform owner; this subtree must too, on
// every route it registers.
//
// Run through the REAL wiring: buildConfigBackup(), the production s.configAuthz
// gate mapping, the production s.configLookupDevice owner resolution and a REAL
// tenant store, so the switch under test is the production one
// (Tenant.OperatorRestricted → effectiveRestrictedIDs →
// operatorTelemetryRestriction).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/configdrift"
	"netops/backend/internal/configstore"
	"netops/backend/internal/discovery"
	"netops/backend/models"
)

const (
	cfgAcmeSHA2   = "3333333333333333333333333333333333333333333333333333333333333333"
	cfgAcmeText   = "hostname acme-core\ninterface Gi0/1\n ip address 10.1.0.1 255.255.255.0\n"
	cfgAcmeText2  = "hostname acme-core\ninterface Gi0/1\n ip address 10.1.0.9 255.255.255.0\n"
	cfgGlobexText = "hostname globex-core\ninterface Gi0/1\n ip address 10.2.0.1 255.255.255.0\n"
)

type restrictedCfgFixture struct {
	t      *testing.T
	s      *server
	acme   string
	globex string
}

func newRestrictedCfgFixture(t *testing.T) *restrictedCfgFixture {
	t.Helper()
	dir := t.TempDir()
	roles, err := newRoleStore(dir + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	tenants, err := newTenantStore(dir + "/tenants.json")
	if err != nil {
		t.Fatalf("tenantStore: %v", err)
	}
	acme, err := tenants.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	globex, err := tenants.Create("Globex", "globex", "", "", "")
	if err != nil {
		t.Fatalf("create globex: %v", err)
	}
	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1",
		Vendor: "cisco", OS: "IOS-XE", TenantID: acme.ID})
	d.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1",
		Vendor: "cisco", OS: "IOS-XE", TenantID: globex.ID})

	s := &server{
		roles:     roles,
		tenants:   tenants,
		discovery: d,
		vault:     newTestVault(t),
		sshHosts:  newSSHHostStore(dir + "/known_hosts.json"),
	}
	t.Setenv(configstore.EnvFeatureFlag, "true")
	t.Setenv("CONFIG_BACKUP_VERSIONS_FILE", dir+"/versions.json")
	t.Setenv("CONFIG_DRIFT_STATE_FILE", dir+"/drift.json")
	t.Setenv(configstore.EnvDir, dir+"/blobs")

	sealer := configSealer{v: s.vault}
	blobs, err := configstore.NewFileBlobStore(dir+"/blobs", sealer.Marker())
	if err != nil {
		t.Fatalf("blob store: %v", err)
	}
	vs := configstore.NewFileStore(dir + "/versions.json")
	ds := configdrift.NewFileStore(dir + "/drift.json")
	ctx := context.Background()
	at := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for _, seed := range []struct {
		tenant, device, sha, text string
	}{
		{acme.ID, "acme-core", cfgAcmeSHA, cfgAcmeText},
		{acme.ID, "acme-core", cfgAcmeSHA2, cfgAcmeText2},
		{globex.ID, "globex-core", cfgGlobexSHA, cfgGlobexText},
	} {
		sealed, serr := sealer.Seal(seed.tenant, configstore.BlobField(seed.device, seed.sha), seed.text)
		if serr != nil {
			t.Fatalf("seal: %v", serr)
		}
		ref, perr := blobs.Put(seed.tenant, seed.device, seed.sha, sealed)
		if perr != nil {
			t.Fatalf("blob put: %v", perr)
		}
		if err := vs.Put(ctx, seed.tenant, false, configstore.Version{
			TenantID: seed.tenant, DeviceID: seed.device, SHA: seed.sha,
			CapturedAt: at, SizeBytes: int64(len(seed.text)), BlobRef: ref,
			Vendor: "cisco_iosxe", Status: configstore.StatusOK, Drift: configstore.DriftInSync,
		}); err != nil {
			t.Fatalf("version put: %v", err)
		}
		if err := ds.Put(ctx, seed.tenant, false, configdrift.State{
			TenantID: seed.tenant, DeviceID: seed.device, State: configdrift.StateInSync,
			LastSHA: seed.sha, LastCapture: at, UpdatedAt: at,
		}); err != nil {
			t.Fatalf("state put: %v", err)
		}
	}
	if err := s.buildConfigBackup(); err != nil {
		t.Fatalf("buildConfigBackup: %v", err)
	}
	return &restrictedCfgFixture{t: t, s: s, acme: acme.ID, globex: globex.ID}
}

func (f *restrictedCfgFixture) do(method, path string, claims jwtClaims) *httptest.ResponseRecorder {
	f.t.Helper()
	w := httptest.NewRecorder()
	if !f.s.configAPI.ServeDeviceSubroute(w, req(method, path, "", claims)) {
		f.t.Fatalf("the config subtree did not claim %s %s", method, path)
	}
	return w
}

// every route the subtree registers for acme's device.
func cfgRestrictionRoutes() []struct{ method, path string } {
	return []struct{ method, path string }{
		{http.MethodGet, "/api/devices/acme-core/config/versions"},
		{http.MethodGet, "/api/devices/acme-core/config/versions/" + cfgAcmeSHA},
		{http.MethodGet, "/api/devices/acme-core/config/diff?from=" + cfgAcmeSHA + "&to=" + cfgAcmeSHA2},
		{http.MethodGet, "/api/devices/acme-core/config/status"},
		{http.MethodPost, "/api/devices/acme-core/config/backup"},
		{http.MethodPost, "/api/devices/acme-core/config/golden"},
	}
}

// TestConfigBackupHonoursTheOperatorVisibilityRestriction is the §3a rule-5 test
// for the compliance switch on this subtree. It asserts BOTH halves: the
// restricted tenant's versions, text and diffs are absent from the platform
// owner's Global read, and an as_tenant read into that tenant is refused.
func TestConfigBackupHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedCfgFixture(t)
	owner := platformOwner()

	// Before anything is restricted the platform owner reads acme's config, so
	// the test cannot pass by serving nothing.
	pre := f.do(http.MethodGet, "/api/devices/acme-core/config/versions/"+cfgAcmeSHA, owner)
	if pre.Code != http.StatusOK || !strings.Contains(pre.Body.String(), "hostname acme-core") {
		t.Fatalf("owner (nothing restricted) could not read acme's config: %d %s", pre.Code, pre.Body.String())
	}

	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	hidden := []string{cfgAcmeSHA, cfgAcmeSHA2, "hostname acme-core", "10.1.0.1"}

	// Global view, then the as_tenant half: both answer the same 404 a foreign
	// device gets, on every route.
	for _, claims := range []jwtClaims{owner, ownerActing(owner, f.acme)} {
		for _, rt := range cfgRestrictionRoutes() {
			w := f.do(rt.method, rt.path, claims)
			if w.Code != http.StatusNotFound {
				t.Errorf("RESTRICTION LEAK: %s %s (acting=%q) = %d, want 404: %s",
					rt.method, rt.path, claims.ActingTenant, w.Code, w.Body.String())
			}
			for _, leak := range hidden {
				if strings.Contains(w.Body.String(), leak) {
					t.Errorf("RESTRICTION LEAK on %s %s (acting=%q) — the platform owner saw %q: %s",
						rt.method, rt.path, claims.ActingTenant, leak, w.Body.String())
				}
			}
		}
	}

	// globex is untouched.
	w := f.do(http.MethodGet, "/api/devices/globex-core/config/versions/"+cfgGlobexSHA, owner)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "hostname globex-core") {
		t.Errorf("the unrestricted tenant's config read broke: %d %s", w.Code, w.Body.String())
	}

	// And acme's OWN operator is never restricted from acme's own configs.
	acmeOwn := jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme}
	own := f.do(http.MethodGet, "/api/devices/acme-core/config/versions", acmeOwn)
	if own.Code != http.StatusOK || !strings.Contains(own.Body.String(), cfgAcmeSHA) {
		t.Fatalf("acme's own operator lost its own versions: %d %s", own.Code, own.Body.String())
	}
	text := f.do(http.MethodGet, "/api/devices/acme-core/config/versions/"+cfgAcmeSHA, acmeOwn)
	if text.Code != http.StatusOK || !strings.Contains(text.Body.String(), "hostname acme-core") {
		t.Fatalf("acme's own operator lost its own configuration text: %d %s", text.Code, text.Body.String())
	}
}

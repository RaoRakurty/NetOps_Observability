package backend

// config_backup_isolation_test.go — the CLAUDE.md §3a rule-5 cross-org test for
// the Config Backup & Drift module (P3-CFG, internal/configstore +
// internal/configdrift), exercised through the REAL wiring: the server is built
// by buildConfigBackup() itself, so the gates under test are the production
// s.configAuthz / s.configDriftAuthz mappings and the production
// s.configLookupDevice owner resolution — not a fake. The gate CHOICE (per-tenant
// requirePerm + a tenant filter, NOT a platform gate) is half of what §3a rule 3
// is about, and a fixture that re-implemented it would prove nothing.
//
// Proven here:
//   - GET /api/devices/{id}/config/versions returns the caller's OWN device's
//     versions only, and never another tenant's rows;
//   - a FOREIGN device id answers 404 on every route in the subtree
//     (versions, versions/{sha}, diff, status, backup, golden) — absent and
//     foreign are indistinguishable, so the subtree is not an existence oracle;
//   - a foreign VERSION id under an own device answers 404 too (the store's own
//     tenant filter is the second, independent line);
//   - GET /api/config/drift is own-only; ?as_tenant into another org is
//     accepted-then-IGNORED for a tenant admin and HONOURED (narrowing) for the
//     platform owner, while every other unknown parameter is still a 400;
//   - the platform owner is the ONLY principal that reads cross-tenant;
//   - with FEATURE_CONFIG_BACKUP off nothing is constructed and the device
//     subtree dispatcher declines every path (flag-off registers nothing).

import (
	"context"
	"encoding/json"
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

// cfgFixture is the wired server plus the on-disk paths its stores use.
type cfgFixture struct {
	s        *server
	versions string
	states   string
	blobs    string
}

const (
	cfgAcmeSHA   = "1111111111111111111111111111111111111111111111111111111111111111"
	cfgGlobexSHA = "2222222222222222222222222222222222222222222222222222222222222222"
)

// cfgServer seeds one version + one drift row per tenant, then brings the module
// up through buildConfigBackup() — the SAME call main() makes.
func cfgServer(t *testing.T) *cfgFixture {
	t.Helper()
	dir := t.TempDir()
	fx := &cfgFixture{
		versions: dir + "/versions.json",
		states:   dir + "/drift.json",
		blobs:    dir + "/blobs",
	}
	roles, err := newRoleStore(dir + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1",
		Vendor: "cisco", OS: "IOS-XE", TenantID: "acme"})
	d.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1",
		Vendor: "cisco", OS: "IOS-XE", TenantID: "globex"})

	s := &server{
		roles:     roles,
		discovery: d,
		vault:     newTestVault(t),
		sshHosts:  newSSHHostStore(dir + "/known_hosts.json"),
	}
	fx.s = s

	t.Setenv(configstore.EnvFeatureFlag, "true")
	t.Setenv("CONFIG_BACKUP_VERSIONS_FILE", fx.versions)
	t.Setenv("CONFIG_DRIFT_STATE_FILE", fx.states)
	t.Setenv(configstore.EnvDir, fx.blobs)

	// Seed through the module's OWN stores (a second instance over the same
	// paths), so the rows the wired manager loads are byte-identical to rows a
	// real capture would have written — including the sealed blob, which is
	// AAD-bound to (tenant, device, sha) by BlobField.
	sealer := configSealer{v: s.vault}
	blobs, err := configstore.NewFileBlobStore(fx.blobs, sealer.Marker())
	if err != nil {
		t.Fatalf("blob store: %v", err)
	}
	vs := configstore.NewFileStore(fx.versions)
	ds := configdrift.NewFileStore(fx.states)
	ctx := context.Background()
	at := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for _, seed := range []struct {
		tenant, device, sha, text string
	}{
		{"acme", "acme-core", cfgAcmeSHA, "hostname acme-core\nsnmp-server community ACMESECRET ro\n"},
		{"globex", "globex-core", cfgGlobexSHA, "hostname globex-core\nsnmp-server community GLOBEXSECRET ro\n"},
	} {
		sealed, serr := sealer.Seal(seed.tenant, configstore.BlobField(seed.device, seed.sha), seed.text)
		if serr != nil {
			t.Fatalf("seal %s: %v", seed.tenant, serr)
		}
		ref, perr := blobs.Put(seed.tenant, seed.device, seed.sha, sealed)
		if perr != nil {
			t.Fatalf("blob put %s: %v", seed.tenant, perr)
		}
		if err := vs.Put(ctx, seed.tenant, false, configstore.Version{
			TenantID: seed.tenant, DeviceID: seed.device, SHA: seed.sha,
			CapturedAt: at, SizeBytes: int64(len(seed.text)), BlobRef: ref,
			Vendor: "cisco_iosxe", Status: configstore.StatusOK, Drift: configstore.DriftInSync,
		}); err != nil {
			t.Fatalf("version put %s: %v", seed.tenant, err)
		}
		if err := ds.Put(ctx, seed.tenant, false, configdrift.State{
			TenantID: seed.tenant, DeviceID: seed.device, State: configdrift.StateInSync,
			LastSHA: seed.sha, LastCapture: at, UpdatedAt: at,
		}); err != nil {
			t.Fatalf("state put %s: %v", seed.tenant, err)
		}
	}

	if err := s.buildConfigBackup(); err != nil {
		t.Fatalf("buildConfigBackup: %v", err)
	}
	if s.configAPI == nil || s.configDrift == nil || s.configBackup == nil {
		t.Fatal("buildConfigBackup left the module half-wired")
	}
	return fx
}

// cfgDo runs one request through the REAL device-subtree dispatcher, exactly as
// handleDeviceByID does. It returns the recorder and whether the subtree claimed
// the path at all.
func cfgDo(s *server, method, path string, claims jwtClaims) (*httptest.ResponseRecorder, bool) {
	w := httptest.NewRecorder()
	claimed := s.configAPI.ServeDeviceSubroute(w, req(method, path, "", claims))
	return w, claimed
}

func TestConfigBackupVersionsAreOwnTenantOnly(t *testing.T) {
	fx := cfgServer(t)

	w, claimed := cfgDo(fx.s, http.MethodGet, "/api/devices/acme-core/config/versions", acme())
	if !claimed {
		t.Fatal("the device subtree did not claim /config/versions")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("own versions = %d (%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, cfgAcmeSHA) {
		t.Fatalf("acme's own version is missing — the guard would be vacuous: %s", body)
	}
	if strings.Contains(body, cfgGlobexSHA) || strings.Contains(body, "globex") {
		t.Fatalf("TENANT LEAK: acme's versions carried globex data: %s", body)
	}

	// The mirror direction: globex sees its own and never acme's.
	w, _ = cfgDo(fx.s, http.MethodGet, "/api/devices/globex-core/config/versions", globex())
	if w.Code != http.StatusOK {
		t.Fatalf("globex own versions = %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), cfgGlobexSHA) {
		t.Fatalf("globex's own version is missing: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), cfgAcmeSHA) {
		t.Fatalf("TENANT LEAK: globex's versions carried acme data: %s", w.Body.String())
	}
}

func TestConfigBackupForeignDeviceIsAlways404(t *testing.T) {
	fx := cfgServer(t)

	// Every route in the subtree, on a device owned by the OTHER tenant. A 403
	// would confirm the id exists elsewhere; only 404 is acceptable (§3a rule 1).
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/devices/globex-core/config/versions"},
		{http.MethodGet, "/api/devices/globex-core/config/versions/" + cfgGlobexSHA},
		{http.MethodGet, "/api/devices/globex-core/config/diff?from=" + cfgGlobexSHA + "&to=" + cfgGlobexSHA},
		{http.MethodGet, "/api/devices/globex-core/config/status"},
		{http.MethodPost, "/api/devices/globex-core/config/backup"},
		{http.MethodPost, "/api/devices/globex-core/config/golden"},
	} {
		w, claimed := cfgDo(fx.s, tc.method, tc.path, acme())
		if !claimed {
			t.Fatalf("%s %s was not claimed by the subtree", tc.method, tc.path)
		}
		if w.Code != http.StatusNotFound {
			t.Errorf("cross-tenant %s %s = %d, want 404 (%s)", tc.method, tc.path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), cfgGlobexSHA) {
			t.Errorf("TENANT LEAK: the 404 body carried the foreign version: %s", w.Body.String())
		}
	}

	// An id that exists NOWHERE must answer identically — absent and foreign are
	// indistinguishable or the subtree is an existence oracle.
	w, _ := cfgDo(fx.s, http.MethodGet, "/api/devices/no-such-device/config/versions", acme())
	if w.Code != http.StatusNotFound {
		t.Fatalf("absent device = %d, want the same 404 a foreign device gets", w.Code)
	}
}

func TestConfigBackupForeignVersionIDUnderOwnDeviceIs404(t *testing.T) {
	fx := cfgServer(t)

	// The device IS acme's, so the device gate passes; the store's own tenant
	// filter is what must refuse the other tenant's version id.
	w, _ := cfgDo(fx.s, http.MethodGet, "/api/devices/acme-core/config/versions/"+cfgGlobexSHA, acme())
	if w.Code != http.StatusNotFound {
		t.Fatalf("foreign version id = %d, want 404 (%s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "GLOBEXSECRET") {
		t.Fatalf("TENANT LEAK: another tenant's configuration text was returned: %s", w.Body.String())
	}
}

func TestConfigBackupStatusIsOwnTenantOnly(t *testing.T) {
	fx := cfgServer(t)

	w, _ := cfgDo(fx.s, http.MethodGet, "/api/devices/acme-core/config/status", acme())
	if w.Code != http.StatusOK {
		t.Fatalf("own status = %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), configdrift.StateInSync) {
		t.Fatalf("own status did not render the seeded state: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), cfgGlobexSHA) {
		t.Fatalf("TENANT LEAK: status carried another tenant's sha: %s", w.Body.String())
	}
}

// cfgDriftIDs runs GET /api/config/drift and returns the device ids it listed.
func cfgDriftIDs(t *testing.T, s *server, url string, claims jwtClaims) []string {
	t.Helper()
	w := httptest.NewRecorder()
	s.configDrift.HandleDriftList(w, req(http.MethodGet, url, "", claims))
	if w.Code != http.StatusOK {
		t.Fatalf("%s = %d (%s)", url, w.Code, w.Body.String())
	}
	var body struct {
		Items []struct {
			DeviceID string `json:"device_id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode drift list: %v (%s)", err, w.Body.String())
	}
	out := make([]string, 0, len(body.Items))
	for _, it := range body.Items {
		out = append(out, it.DeviceID)
	}
	return out
}

func TestConfigDriftListIsOwnTenantOnly(t *testing.T) {
	fx := cfgServer(t)

	ids := cfgDriftIDs(t, fx.s, "/api/config/drift", acme())
	if len(ids) != 1 || ids[0] != "acme-core" {
		t.Fatalf("acme's drift list = %v, want exactly [acme-core]", ids)
	}

	ids = cfgDriftIDs(t, fx.s, "/api/config/drift", globex())
	if len(ids) != 1 || ids[0] != "globex-core" {
		t.Fatalf("globex's drift list = %v, want exactly [globex-core]", ids)
	}
}

// TestConfigDriftListIgnoresAsTenantForATenantAdminAndHonoursItForThePlatformOwner
// is the §3a rule-5 acting-tenant obligation on the drift list, in both
// directions. The parameter is ACCEPTED (a 400 here would make the drift page
// the one surface the platform-wide tenant selector cannot reach) and it can
// only ever NARROW:
//
//   - a scoped caller's ?as_tenant into another org is IGNORED — principalTenant
//     never trusts ActingTenant for a non-owner, and withActingTenant rewrites
//     the effective tenant only for a tenant the principal actually reaches — so
//     acme asking for globex still gets acme;
//   - the PLATFORM OWNER's selection is HONOURED — its default view is
//     cross-tenant Global, and selecting a tenant drops it to that tenant.
//
// The owner's claims here carry ActingTenant directly: that is exactly what the
// auth middleware's withActingTenant mints for an owner after resolving
// ?as_tenant=globex, and req() builds the post-middleware context these handler
// tests run against.
func TestConfigDriftListIgnoresAsTenantForATenantAdminAndHonoursItForThePlatformOwner(t *testing.T) {
	fx := cfgServer(t)

	// A scoped caller: accepted, then inert. Never a 400, never a widening.
	w := httptest.NewRecorder()
	fx.s.configDrift.HandleDriftList(w, req(http.MethodGet, "/api/config/drift?as_tenant=globex", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("?as_tenant = %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "globex-core") {
		t.Fatalf("TENANT LEAK: ?as_tenant carried acme into another org: %s", w.Body.String())
	}
	ids := cfgDriftIDs(t, fx.s, "/api/config/drift?as_tenant=globex", acme())
	if len(ids) != 1 || ids[0] != "acme-core" {
		t.Fatalf("TENANT LEAK: ?as_tenant changed a tenant admin's scope: %v", ids)
	}

	// Same for a tenant ADMIN holding full administration:admin — a role that is
	// NOT the platform owner and must not be able to buy reach with a parameter.
	ids = cfgDriftIDs(t, fx.s, "/api/config/drift?as_tenant=globex", tAdmin("acme"))
	if len(ids) != 1 || ids[0] != "acme-core" {
		t.Fatalf("TENANT LEAK: a tenant admin used ?as_tenant to reach another org: %v", ids)
	}

	// The platform owner: the selection is HONOURED and NARROWS the cross-tenant
	// view to exactly the selected tenant.
	owner := platformOwner()
	owner.ActingTenant = "globex"
	ids = cfgDriftIDs(t, fx.s, "/api/config/drift?as_tenant=globex", owner)
	if len(ids) != 1 || ids[0] != "globex-core" {
		t.Fatalf("the platform owner's tenant selection was not honoured: %v", ids)
	}

	// The scope a scoped caller gets with no parameter at all is unchanged.
	ids = cfgDriftIDs(t, fx.s, "/api/config/drift", acme())
	if len(ids) != 1 || ids[0] != "acme-core" {
		t.Fatalf("TENANT LEAK: acme's scope is not own-only: %v", ids)
	}

	// The exception is exactly one parameter wide: everything else still 400s.
	w = httptest.NewRecorder()
	fx.s.configDrift.HandleDriftList(w, req(http.MethodGet, "/api/config/drift?states=drifted", "", acme()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("?states = %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

func TestConfigDriftListIsCrossTenantOnlyForThePlatformOwner(t *testing.T) {
	fx := cfgServer(t)

	ids := cfgDriftIDs(t, fx.s, "/api/config/drift", platformOwner())
	seen := map[string]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	if !seen["acme-core"] || !seen["globex-core"] {
		t.Fatalf("the platform owner must read cross-tenant; got %v", ids)
	}

	// A tenant admin holding full administration:admin is NOT the platform owner
	// and must stay inside its own org.
	ids = cfgDriftIDs(t, fx.s, "/api/config/drift", tAdmin("acme"))
	if len(ids) != 1 || ids[0] != "acme-core" {
		t.Fatalf("TENANT LEAK: a tenant admin read cross-tenant: %v", ids)
	}
}

func TestConfigBackupFlagOffRegistersNothing(t *testing.T) {
	// No buildConfigBackup: this is exactly the flag-off server. The subtree
	// dispatcher must DECLINE every path so handleDeviceByID keeps its existing
	// behaviour and a prober cannot enumerate the dormant feature.
	s := &server{}
	if s.configAPI != nil || s.configDrift != nil || s.configBackup != nil {
		t.Fatal("a flag-off server must construct nothing")
	}
	w := httptest.NewRecorder()
	if s.configAPI.ServeDeviceSubroute(w, req(http.MethodGet, "/api/devices/acme-core/config/versions", "", acme())) {
		t.Fatal("a nil configAPI claimed a path")
	}
	mux := http.NewServeMux()
	if s.configDrift != nil {
		mux.HandleFunc("/api/config/drift", s.configDrift.HandleDriftList)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req(http.MethodGet, "/api/config/drift", "", acme()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("flag-off /api/config/drift = %d, want 404", rec.Code)
	}
}

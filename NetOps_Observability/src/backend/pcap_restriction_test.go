// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// pcap_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test for the
// per-tenant OPERATOR-VISIBILITY restriction (Tenant.OperatorRestricted) on the
// packet-capture subtree.
//
// A packet capture is the rawest artefact this product holds: real frames off a
// customer's production interface. Logs, flows, metrics, igpmon and the BMP feed
// all hide a restricted tenant from the platform owner. This subtree must too,
// on EVERY route it registers — and most of all on /download, which streams the
// packets themselves.
//
// Run through the REAL wiring: buildPacketCapture(), the production
// s.pcapAuthz gate mapping, the production s.pcapLookupDevice owner resolution
// and a REAL tenant store, so the switch under test is the production one
// (Tenant.OperatorRestricted → effectiveRestrictedIDs →
// operatorTelemetryRestriction).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/discovery"
	"netops/backend/internal/pcap"
	"netops/backend/models"
)

// restrictedPcapFixture is a two-tenant estate with one stored capture each,
// wired through the module's own build path.
type restrictedPcapFixture struct {
	t      *testing.T
	s      *server
	acme   string // the opaque tenant id the store minted
	globex string
}

func newRestrictedPcapFixture(t *testing.T) *restrictedPcapFixture {
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
		Vendor: "cisco", OS: "NX-OS", TenantID: acme.ID})
	d.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1",
		Vendor: "cisco", OS: "NX-OS", TenantID: globex.ID})

	s := &server{
		roles:     roles,
		tenants:   tenants,
		discovery: d,
		vault:     newTestVault(t),
		sshHosts:  newSSHHostStore(dir + "/known_hosts.json"),
	}
	t.Setenv(pcap.EnvFeatureFlag, "true")
	t.Setenv(pcap.EnvMetaFile, dir+"/captures.json")
	t.Setenv(pcap.EnvDir, dir+"/blobs")

	sealer := pcapSealer{v: s.vault}
	blobs, err := pcap.NewFileBlobStore(dir+"/blobs", sealer.Marker())
	if err != nil {
		t.Fatalf("blob store: %v", err)
	}
	store := pcap.NewFileStore(dir + "/captures.json")
	ctx := context.Background()
	at := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	for _, seed := range []struct{ tenant, device, id, payload string }{
		{acme.ID, "acme-core", pcapAcmeCapture, pcapAcmePayload},
		{globex.ID, "globex-core", pcapGlobexCapture, pcapGlobexPayload},
	} {
		sealed, serr := sealer.Seal(seed.tenant, pcap.BlobField(seed.device, seed.id), seed.payload)
		if serr != nil {
			t.Fatalf("seal: %v", serr)
		}
		ref, perr := blobs.Put(seed.tenant, seed.device, seed.id, sealed)
		if perr != nil {
			t.Fatalf("blob put: %v", perr)
		}
		ended := at
		if err := store.Put(ctx, seed.tenant, false, pcap.Capture{
			TenantID: seed.tenant, DeviceID: seed.device, ID: seed.id,
			Interface: "Ethernet1/1", DurationSec: 30, MaxPackets: 100,
			StartedAt: at.Add(-time.Minute), ExpiresAt: at, EndedAt: &ended,
			Status: pcap.StatusStored, Packets: 2, Bytes: int64(len(seed.payload)),
			BlobRef: ref, Actor: "u@" + seed.tenant,
		}); err != nil {
			t.Fatalf("capture put: %v", err)
		}
	}
	if err := s.buildPacketCapture(); err != nil {
		t.Fatalf("buildPacketCapture: %v", err)
	}
	return &restrictedPcapFixture{t: t, s: s, acme: acme.ID, globex: globex.ID}
}

func (f *restrictedPcapFixture) do(method, path string, claims jwtClaims) *httptest.ResponseRecorder {
	f.t.Helper()
	w := httptest.NewRecorder()
	if !f.s.pcapAPI.ServeDeviceSubroute(w, req(method, path, "", claims)) {
		f.t.Fatalf("the pcap subtree did not claim %s %s", method, path)
	}
	return w
}

// the four read routes the subtree registers, plus the one that streams packets.
func pcapRestrictionRoutes(capture string) []struct{ method, path string } {
	return []struct{ method, path string }{
		{http.MethodGet, "/api/devices/acme-core/pcap"},
		{http.MethodGet, "/api/devices/acme-core/pcap/" + capture},
		{http.MethodGet, "/api/devices/acme-core/pcap/" + capture + "/download"},
	}
}

// TestPcapHonoursTheOperatorVisibilityRestriction is the §3a rule-5 test for the
// compliance switch on this subtree. It asserts BOTH halves: the restricted
// tenant's captures are absent from the platform owner's Global read, and an
// as_tenant read into that tenant is refused — on the list, the status and the
// DOWNLOAD, which is the one that carries the customer's actual packets.
func TestPcapHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedPcapFixture(t)
	owner := platformOwner()

	// Before anything is restricted the platform owner reads acme, so the test
	// cannot pass by serving nothing.
	for _, rt := range pcapRestrictionRoutes(pcapAcmeCapture) {
		w := f.do(rt.method, rt.path, owner)
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s (owner, nothing restricted) = %d (%s)", rt.method, rt.path, w.Code, w.Body.String())
		}
	}

	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// Global view: acme's device, its capture id and its packets are gone.
	for _, rt := range pcapRestrictionRoutes(pcapAcmeCapture) {
		w := f.do(rt.method, rt.path, owner)
		if w.Code != http.StatusNotFound {
			t.Errorf("RESTRICTION LEAK: %s %s (owner, acme restricted) = %d, want 404: %s",
				rt.method, rt.path, w.Code, w.Body.String())
		}
		for _, hidden := range []string{pcapAcmeCapture, pcapAcmePayload, "Ethernet1/1"} {
			if strings.Contains(w.Body.String(), hidden) {
				t.Errorf("RESTRICTION LEAK on %s %s — the platform owner saw %q: %s",
					rt.method, rt.path, hidden, w.Body.String())
			}
		}
	}

	// The as_tenant half: the operator walking into the restricted tenant.
	scoped := ownerActing(owner, f.acme)
	for _, rt := range pcapRestrictionRoutes(pcapAcmeCapture) {
		w := f.do(rt.method, rt.path, scoped)
		if w.Code != http.StatusNotFound {
			t.Errorf("RESTRICTION LEAK: %s %s (owner→acme) = %d, want 404: %s",
				rt.method, rt.path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), pcapAcmePayload) {
			t.Errorf("PACKET LEAK: %s %s (owner→acme) streamed the capture: %s",
				rt.method, rt.path, w.Body.String())
		}
	}

	// A write on the restricted tenant's device is refused the same way, so the
	// operator cannot start a fresh capture on an estate it may not read.
	w := httptest.NewRecorder()
	if !f.s.pcapAPI.ServeDeviceSubroute(w,
		req(http.MethodPost, "/api/devices/acme-core/pcap", `{"interface":"Ethernet1/1"}`, scoped)) {
		t.Fatal("the pcap subtree did not claim the start route")
	}
	if w.Code != http.StatusNotFound {
		t.Errorf("start on a restricted tenant's device = %d, want 404: %s", w.Code, w.Body.String())
	}

	// globex is untouched, in the Global view and scoped into.
	for _, claims := range []jwtClaims{owner, ownerActing(owner, f.globex)} {
		w := f.do(http.MethodGet, "/api/devices/globex-core/pcap/"+pcapGlobexCapture+"/download", claims)
		if w.Code != http.StatusOK || w.Body.String() != pcapGlobexPayload {
			t.Errorf("the unrestricted tenant's download broke: %d %q", w.Code, w.Body.String())
		}
	}

	// And acme's OWN operator is never restricted from acme's own captures: the
	// switch hides a tenant from the PLATFORM, never from itself.
	acmeOwn := jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme}
	own := f.do(http.MethodGet, "/api/devices/acme-core/pcap", acmeOwn)
	if own.Code != http.StatusOK || !strings.Contains(own.Body.String(), pcapAcmeCapture) {
		t.Fatalf("acme's own operator lost its own captures: %d %s", own.Code, own.Body.String())
	}
	dl := f.do(http.MethodGet, "/api/devices/acme-core/pcap/"+pcapAcmeCapture+"/download", acmeOwn)
	if dl.Code != http.StatusOK || dl.Body.String() != pcapAcmePayload {
		t.Fatalf("acme's own operator lost its own packets: %d %q", dl.Code, dl.Body.String())
	}
}

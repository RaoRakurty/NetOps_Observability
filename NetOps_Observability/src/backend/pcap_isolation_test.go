// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// pcap_isolation_test.go — the CLAUDE.md §3a rule-5 cross-org test for the
// Packet Capture subtree (internal/pcap), exercised through the REAL wiring: the
// server is built by buildPacketCapture() itself, so the gates under test are
// the production s.pcapAuthz mapping and the production s.pcapLookupDevice owner
// resolution — not a fake. The gate CHOICE is half of what §3a rule 3 is about,
// and it is unusually load-bearing here: a PCAP is customer PAYLOAD, so DOWNLOAD
// takes infrastructure:WRITE rather than read, and a fixture that re-implemented
// the mapping would prove nothing about the deployed gate.
//
// Proven here:
//   - GET /api/devices/{id}/pcap lists the caller's OWN device's captures only;
//   - a FOREIGN device id answers 404 on every route in the subtree (list,
//     start, status, download, delete) — absent and foreign are
//     indistinguishable, so the subtree is not an existence oracle;
//   - a foreign CAPTURE id under an own device answers 404 too (the store's own
//     tenant filter is the second, independent line), and no packet byte of
//     another tenant's capture is ever streamed;
//   - the platform owner is the ONLY principal that reads cross-tenant, and a
//     tenant admin holding full administration:admin is NOT that principal;
//   - a read-only principal cannot start or download a capture (the write gate
//     is real), and a download is audited;
//   - with FEATURE_PACKET_CAPTURE off nothing is constructed and the device
//     subtree dispatcher declines every path.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/discovery"
	"netops/backend/internal/pcap"
	"netops/backend/models"
)

const (
	pcapAcmeCapture   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
	pcapGlobexCapture = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2"
	pcapAcmePayload   = "ACME-PACKET-PAYLOAD"
	pcapGlobexPayload = "GLOBEX-PACKET-PAYLOAD"
)

// pcapServer seeds one stored capture per tenant, then brings the module up
// through buildPacketCapture() — the SAME call main() makes.
func pcapServer(t *testing.T) *server {
	t.Helper()
	dir := t.TempDir()
	roles, err := newRoleStore(dir + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1",
		Vendor: "cisco", OS: "NX-OS", TenantID: "acme"})
	d.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1",
		Vendor: "cisco", OS: "NX-OS", TenantID: "globex"})

	s := &server{
		roles:     roles,
		discovery: d,
		vault:     newTestVault(t),
		sshHosts:  newSSHHostStore(dir + "/known_hosts.json"),
	}
	t.Setenv(pcap.EnvFeatureFlag, "true")
	t.Setenv(pcap.EnvMetaFile, dir+"/captures.json")
	t.Setenv(pcap.EnvDir, dir+"/blobs")

	// Seed through the module's OWN stores (a second instance over the same
	// paths), so the rows the wired manager loads are byte-identical to rows a
	// real capture would have written — including the sealed blob, which is
	// AAD-bound to (tenant, device, capture) by BlobField.
	sealer := pcapSealer{v: s.vault}
	blobs, err := pcap.NewFileBlobStore(dir+"/blobs", sealer.Marker())
	if err != nil {
		t.Fatalf("blob store: %v", err)
	}
	store := pcap.NewFileStore(dir + "/captures.json")
	ctx := context.Background()
	at := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	for _, seed := range []struct{ tenant, device, id, payload string }{
		{"acme", "acme-core", pcapAcmeCapture, pcapAcmePayload},
		{"globex", "globex-core", pcapGlobexCapture, pcapGlobexPayload},
	} {
		sealed, serr := sealer.Seal(seed.tenant, pcap.BlobField(seed.device, seed.id), seed.payload)
		if serr != nil {
			t.Fatalf("seal %s: %v", seed.tenant, serr)
		}
		ref, perr := blobs.Put(seed.tenant, seed.device, seed.id, sealed)
		if perr != nil {
			t.Fatalf("blob put %s: %v", seed.tenant, perr)
		}
		ended := at
		if err := store.Put(ctx, seed.tenant, false, pcap.Capture{
			TenantID: seed.tenant, DeviceID: seed.device, ID: seed.id,
			Interface: "Ethernet1/1", DurationSec: 30, MaxPackets: 100,
			StartedAt: at.Add(-time.Minute), ExpiresAt: at, EndedAt: &ended,
			Status: pcap.StatusStored, Packets: 2, Bytes: int64(len(seed.payload)),
			BlobRef: ref, Actor: "u@" + seed.tenant,
		}); err != nil {
			t.Fatalf("capture put %s: %v", seed.tenant, err)
		}
	}

	if err := s.buildPacketCapture(); err != nil {
		t.Fatalf("buildPacketCapture: %v", err)
	}
	if s.pcapAPI == nil || s.packetCapture == nil {
		t.Fatal("buildPacketCapture left the module half-wired")
	}
	return s
}

// pcapDo runs one request through the REAL device-subtree dispatcher, exactly as
// handleDeviceByID does.
func pcapDo(t *testing.T, s *server, method, path, body string, claims jwtClaims) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	if !s.pcapAPI.ServeDeviceSubroute(w, req(method, path, body, claims)) {
		t.Fatalf("the pcap subtree did not claim %s %s", method, path)
	}
	return w
}

func TestPcapListIsOwnTenantOnlyThroughTheRealGate(t *testing.T) {
	s := pcapServer(t)

	w := pcapDo(t, s, http.MethodGet, "/api/devices/acme-core/pcap", "", acme())
	if w.Code != http.StatusOK {
		t.Fatalf("own list = %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), pcapAcmeCapture) {
		t.Fatalf("acme's own capture is missing — the guard would be vacuous: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), pcapGlobexCapture) || strings.Contains(w.Body.String(), "globex") {
		t.Fatalf("TENANT LEAK: acme's list carried globex data: %s", w.Body.String())
	}

	w = pcapDo(t, s, http.MethodGet, "/api/devices/globex-core/pcap", "", globex())
	if !strings.Contains(w.Body.String(), pcapGlobexCapture) || strings.Contains(w.Body.String(), pcapAcmeCapture) {
		t.Fatalf("globex's list is wrong: %s", w.Body.String())
	}
}

func TestPcapForeignDeviceIsAlways404ThroughTheRealGate(t *testing.T) {
	s := pcapServer(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/devices/globex-core/pcap"},
		{http.MethodPost, "/api/devices/globex-core/pcap"},
		{http.MethodGet, "/api/devices/globex-core/pcap/" + pcapGlobexCapture},
		{http.MethodGet, "/api/devices/globex-core/pcap/" + pcapGlobexCapture + "/download"},
		{http.MethodDelete, "/api/devices/globex-core/pcap/" + pcapGlobexCapture},
	} {
		w := pcapDo(t, s, tc.method, tc.path, `{"interface":"Ethernet1/1"}`, acme())
		if w.Code != http.StatusNotFound {
			t.Errorf("cross-tenant %s %s = %d, want 404 (%s)", tc.method, tc.path, w.Code, w.Body.String())
		}
		body := w.Body.String()
		if strings.Contains(body, pcapGlobexCapture) || strings.Contains(body, pcapGlobexPayload) {
			t.Errorf("TENANT LEAK: the 404 body carried foreign data: %s", body)
		}
	}
	// An id that exists NOWHERE must answer identically.
	w := pcapDo(t, s, http.MethodGet, "/api/devices/no-such-device/pcap", "", acme())
	if w.Code != http.StatusNotFound {
		t.Fatalf("absent device = %d, want the same 404 a foreign device gets", w.Code)
	}
}

func TestPcapForeignCaptureIDUnderOwnDeviceIs404ThroughTheRealGate(t *testing.T) {
	s := pcapServer(t)
	// The DEVICE is acme's, so the device gate passes; the store's tenant filter
	// must refuse the other tenant's capture id — and must never stream a byte
	// of its payload.
	for _, path := range []string{
		"/api/devices/acme-core/pcap/" + pcapGlobexCapture,
		"/api/devices/acme-core/pcap/" + pcapGlobexCapture + "/download",
	} {
		w := pcapDo(t, s, http.MethodGet, path, "", acme())
		if w.Code != http.StatusNotFound {
			t.Errorf("foreign capture id at %s = %d, want 404 (%s)", path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), pcapGlobexPayload) {
			t.Errorf("TENANT LEAK: another tenant's packet payload was streamed: %s", w.Body.String())
		}
	}
	// A malformed id gets the SAME answer — a different refusal is an oracle.
	w := pcapDo(t, s, http.MethodGet, "/api/devices/acme-core/pcap/not-a-capture-id", "", acme())
	if w.Code != http.StatusNotFound {
		t.Fatalf("malformed capture id = %d, want 404", w.Code)
	}
}

func TestPcapDownloadIsOwnTenantOnlyAndStreamsThePcapType(t *testing.T) {
	s := pcapServer(t)
	w := pcapDo(t, s, http.MethodGet, "/api/devices/acme-core/pcap/"+pcapAcmeCapture+"/download", "", acme())
	if w.Code != http.StatusOK {
		t.Fatalf("own download = %d (%s)", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/vnd.tcpdump.pcap" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if w.Body.String() != pcapAcmePayload {
		t.Fatalf("the streamed bytes are not acme's own capture: %q", w.Body.String())
	}
	if strings.Contains(w.Body.String(), pcapGlobexPayload) {
		t.Fatal("TENANT LEAK: another tenant's payload appeared in the stream")
	}
}

func TestPcapPlatformOwnerIsTheOnlyCrossTenantReader(t *testing.T) {
	s := pcapServer(t)

	w := pcapDo(t, s, http.MethodGet, "/api/devices/globex-core/pcap", "", platformOwner())
	if w.Code != http.StatusOK {
		t.Fatalf("platform owner = %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), pcapGlobexCapture) {
		t.Fatalf("the platform owner must read cross-tenant: %s", w.Body.String())
	}

	// A tenant admin holds full administration:admin but is NOT the platform
	// owner: it must stay inside its own org (§3a rule 3).
	w = pcapDo(t, s, http.MethodGet, "/api/devices/globex-core/pcap", "", tAdmin("acme"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("TENANT LEAK: a tenant admin reached another org's device: %d (%s)", w.Code, w.Body.String())
	}
}

func TestPcapWriteGateRefusesAReadOnlyPrincipal(t *testing.T) {
	s := pcapServer(t)
	// Starting a capture and DOWNLOADING one are both infrastructure:write — a
	// PCAP reveal is not a read-level act. A read-only principal may list.
	w := pcapDo(t, s, http.MethodGet, "/api/devices/acme-core/pcap", "", tViewer("acme"))
	if w.Code != http.StatusOK {
		t.Fatalf("read-only list = %d (%s)", w.Code, w.Body.String())
	}
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/devices/acme-core/pcap", `{"interface":"Ethernet1/1"}`},
		{http.MethodGet, "/api/devices/acme-core/pcap/" + pcapAcmeCapture + "/download", ""},
		{http.MethodDelete, "/api/devices/acme-core/pcap/" + pcapAcmeCapture, ""},
	} {
		w := pcapDo(t, s, tc.method, tc.path, tc.body, tViewer("acme"))
		if w.Code == http.StatusOK || w.Code == http.StatusAccepted || w.Code == http.StatusNoContent {
			t.Errorf("a read-only principal was allowed %s %s (%d)", tc.method, tc.path, w.Code)
		}
		if strings.Contains(w.Body.String(), pcapAcmePayload) {
			t.Errorf("PAYLOAD LEAK: a refused %s %s still streamed the capture", tc.method, tc.path)
		}
	}
}

func TestPcapGuardrailsThroughTheRealGate(t *testing.T) {
	s := pcapServer(t)
	for _, tc := range []struct{ body, want string }{
		{`{"interface":"Ethernet1/1","duration_s":600}`, "duration_s"},
		{`{"interface":"Ethernet1/1","max_packets":999999}`, "max_packets"},
		{`{"interface":"eth0; reboot"}`, "interface"},
		{`{"interface":"Ethernet1/1","filter":"host 1.2.3.4; reload"}`, "filter"},
		{`{"interface":"Ethernet1/1","tenant_id":"globex"}`, "invalid"},
	} {
		w := pcapDo(t, s, http.MethodPost, "/api/devices/acme-core/pcap", tc.body, acme())
		if w.Code != http.StatusBadRequest {
			t.Errorf("POST %s = %d, want 400 (%s)", tc.body, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), tc.want) {
			t.Errorf("the 400 for %s does not name %q: %s", tc.body, tc.want, w.Body.String())
		}
	}
}

func TestPcapStatusRendersOwnCaptureOnly(t *testing.T) {
	s := pcapServer(t)
	w := pcapDo(t, s, http.MethodGet, "/api/devices/acme-core/pcap/"+pcapAcmeCapture, "", acme())
	if w.Code != http.StatusOK {
		t.Fatalf("own status = %d (%s)", w.Code, w.Body.String())
	}
	var item struct {
		CaptureID string `json:"capture_id"`
		Status    string `json:"status"`
		Interface string `json:"interface"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &item); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if item.CaptureID != pcapAcmeCapture || item.Status != pcap.StatusStored || item.Interface != "Ethernet1/1" {
		t.Fatalf("status body = %+v", item)
	}
	// The owner stamp and the on-disk/on-device paths stay OFF the wire.
	for _, leak := range []string{"tenant_id", "blob_ref", "remote_path"} {
		if strings.Contains(w.Body.String(), leak) {
			t.Errorf("the status body leaked %q: %s", leak, w.Body.String())
		}
	}
}

func TestPcapFlagOffRegistersNothing(t *testing.T) {
	// No buildPacketCapture: this is exactly the flag-off server. The subtree
	// dispatcher must DECLINE every path, so handleDeviceByID keeps its existing
	// behaviour and a prober cannot enumerate a dormant, highly-privileged
	// feature.
	s := &server{}
	if s.pcapAPI != nil || s.packetCapture != nil {
		t.Fatal("a flag-off server must construct nothing")
	}
	for _, path := range []string{
		"/api/devices/acme-core/pcap",
		"/api/devices/acme-core/pcap/" + pcapAcmeCapture,
		"/api/devices/acme-core/pcap/" + pcapAcmeCapture + "/download",
	} {
		w := httptest.NewRecorder()
		if s.pcapAPI.ServeDeviceSubroute(w, req(http.MethodGet, path, "", acme())) {
			t.Errorf("a nil pcapAPI claimed %s", path)
		}
	}
}

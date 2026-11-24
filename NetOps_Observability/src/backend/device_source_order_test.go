// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"netops/backend/internal/srcauthority"
	"netops/backend/models"
)

// Tracker 389 (owner decision 2026-11-24): the device page and the inventory
// API use the SAME per-tenant source order as Iris, and show the disagreement
// the way Iris states it. Before, mergeDevices' base record (NetBox > directly
// collected > controller) decided the page while Iris cited the source order,
// so the two could show different values for one device.

func devicesAs(t *testing.T, h http.Handler, c jwtClaims) []models.Device {
	t.Helper()
	w := serveAs(h, c, http.MethodGet, "/api/devices", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/devices: %d %s", w.Code, w.Body.String())
	}
	var ds []models.Device
	if err := json.Unmarshal(w.Body.Bytes(), &ds); err != nil {
		t.Fatalf("not a device list: %v: %s", err, w.Body.String())
	}
	return ds
}

func deviceNamed(t *testing.T, ds []models.Device, name string) models.Device {
	t.Helper()
	for _, d := range ds {
		if d.Name == name {
			return d
		}
	}
	t.Fatalf("no device named %q in %d rows", name, len(ds))
	return models.Device{}
}

func disagreementOn(d models.Device, fact string) (models.FactDisagreement, bool) {
	for _, fd := range d.SourceDisagreements {
		if fd.Fact == fact {
			return fd, true
		}
	}
	return models.FactDisagreement{}, false
}

// irisWinner is the value Iris states for one fact, through the same server.
func irisWinner(s *server, dev models.Device, c jwtClaims, fact srcauthority.Fact) string {
	tenant, cross := principalTenant(c)
	for _, r := range s.deviceFactsFor(context.Background(), dev, tenant, cross).Resolutions {
		if r.Fact == fact {
			return r.Value
		}
	}
	return ""
}

func TestDevicePageAndIrisAgreeOnEveryFact(t *testing.T) {
	s, h, alice, _ := srcAuthFixture(t)
	srcAuthSeed(t, s)

	dev := deviceNamed(t, devicesAs(t, h, alice), "edge-1")
	// The default order: controller > discovered > declared > manual.
	if dev.SoftwareVersion != "20.6.1" {
		t.Fatalf("the page must show the controller's version (the default order's winner), got %q", dev.SoftwareVersion)
	}
	for _, f := range []srcauthority.Fact{srcauthority.FactSoftwareVersion, srcauthority.FactVendor, srcauthority.FactModel} {
		page := map[srcauthority.Fact]string{
			srcauthority.FactSoftwareVersion: dev.SoftwareVersion,
			srcauthority.FactVendor:          dev.Vendor,
			srcauthority.FactModel:           dev.Model,
		}[f]
		if iris := irisWinner(s, dev, alice, f); iris != page {
			t.Errorf("%s: the page shows %q, Iris cites %q — they must agree", f, page, iris)
		}
	}

	fd, ok := disagreementOn(dev, "software_version")
	if !ok {
		t.Fatalf("the page must carry the disagreement Iris states: %+v", dev.SourceDisagreements)
	}
	if fd.Value != "20.6.1" || !strings.Contains(fd.Source, "controller") || len(fd.Others) != 2 {
		t.Fatalf("disagreement: %+v", fd)
	}
	for _, want := range []string{"Sources disagree on the software version", "the device itself (SNMP) reports 20.6.2", "a manual entry reports 9.9.9"} {
		if !strings.Contains(fd.Text, want) {
			t.Errorf("the page's sentence lacks %q (Iris states it): %s", want, fd.Text)
		}
	}
	if _, ok := disagreementOn(dev, "vendor"); ok {
		t.Errorf("Cisco and cisco agree; no vendor disagreement: %+v", dev.SourceDisagreements)
	}

	// The single-device read is the same read.
	w := serveAs(h, alice, http.MethodGet, "/api/devices/"+dev.ID, "")
	var one models.Device
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &one) != nil {
		t.Fatalf("GET /api/devices/%s: %d %s", dev.ID, w.Code, w.Body.String())
	}
	if one.SoftwareVersion != dev.SoftwareVersion || len(one.SourceDisagreements) != len(dev.SourceDisagreements) {
		t.Fatalf("the device read and the list must agree: %+v vs %+v", one, dev)
	}
}

func TestTheTenantsOrderDecidesThePageToo(t *testing.T) {
	s, h, alice, bob := srcAuthFixture(t)
	srcAuthSeed(t, s)
	if w := serveAs(h, alice, http.MethodPut, srcAuthPath, orderManualFirst); w.Code != http.StatusOK {
		t.Fatalf("put: %d", w.Code)
	}
	dev := deviceNamed(t, devicesAs(t, h, alice), "edge-1")
	if dev.SoftwareVersion != "9.9.9" {
		t.Fatalf("tenant A's own order (manual first) must decide its page: %q", dev.SoftwareVersion)
	}
	if iris := irisWinner(s, dev, alice, srcauthority.FactSoftwareVersion); iris != "9.9.9" {
		t.Fatalf("Iris must cite the same winner: %q", iris)
	}
	fd, _ := disagreementOn(dev, "software_version")
	if !strings.Contains(fd.Text, "this workspace's source order") || !strings.Contains(fd.Text, "the controller (vmanage) reports 20.6.1") {
		t.Fatalf("the sentence names the workspace's order and the overruled controller: %s", fd.Text)
	}
	// Tenant B's page is untouched by tenant A's order.
	if b := deviceNamed(t, devicesAs(t, h, bob), "edge-1"); b.SoftwareVersion != "66.6" {
		t.Fatalf("tenant A's order changed tenant B's page: %q", b.SoftwareVersion)
	}
}

// §3a: a tenant's page never shows another tenant's value, and a tenant's
// order never reaches another tenant's devices.
func TestDeviceSourceDisagreementsNeverCrossATenant(t *testing.T) {
	s, h, alice, bob := srcAuthFixture(t)
	srcAuthSeed(t, s)
	for _, d := range devicesAs(t, h, alice) {
		raw, _ := json.Marshal(d)
		if strings.Contains(string(raw), "66.6") || strings.Contains(strings.ToLower(string(raw)), "juniper") {
			t.Fatalf("CROSS-TENANT LEAK: tenant B's value on tenant A's page: %s", raw)
		}
	}
	b := deviceNamed(t, devicesAs(t, h, bob), "edge-1")
	if len(b.SourceDisagreements) != 0 || b.SoftwareVersion != "66.6" {
		t.Fatalf("tenant B has one source and nothing to disagree about: %+v", b)
	}
	raw, _ := json.Marshal(b)
	for _, leak := range []string{"20.6.1", "20.6.2", "9.9.9", "vmanage"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("CROSS-TENANT LEAK: tenant A's %q on tenant B's page: %s", leak, raw)
		}
	}
}

// The stamped field is a read: a body that carries it is never persisted.
func TestSourceDisagreementsAreNeverPersisted(t *testing.T) {
	s, _, _, _ := srcAuthFixture(t)
	in := models.Device{ID: "hand-1", Name: "h1", TenantID: "t-a",
		SourceDisagreements: []models.FactDisagreement{{Fact: "vendor", Value: "x", Text: "forged"}}}
	if err := s.discovery.Upsert(in); err != nil {
		t.Fatal(err)
	}
	for _, rec := range s.discovery.Constituents("hand-1") {
		if len(rec.SourceDisagreements) != 0 {
			t.Fatalf("a client-sent disagreement was persisted: %+v", rec.SourceDisagreements)
		}
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/collectors"
	"netops/backend/models"
)

// The device's own SD-WAN site id first, then its controller's; never the
// operator's site field, which this does not touch (manual wins, 2026-10-18).
func TestReportedSite(t *testing.T) {
	ctl := models.Device{ID: "d1", Labels: map[string]string{"site": "nyc-manual", "controller_site_id": "200", "source_system": "vmanage"}}
	cases := []struct {
		name       string
		d          models.Device
		facts      collectors.OverlayDeviceFacts
		id, source string
	}{
		{"the device's own overlay facts win", ctl, collectors.OverlayDeviceFacts{SiteID: "100"}, "100", "device"},
		{"else the controller's", ctl, collectors.OverlayDeviceFacts{}, "200", "vmanage"},
		{"a controller label without a system name", models.Device{Labels: map[string]string{"controller_site_id": "7"}}, collectors.OverlayDeviceFacts{}, "7", "controller"},
		{"nothing reports one", models.Device{Labels: map[string]string{"site": "lon"}}, collectors.OverlayDeviceFacts{}, "", ""},
	}
	for _, c := range cases {
		id, src := reportedSite(c.d, c.facts)
		if id != c.id || src != c.source {
			t.Errorf("%s: got (%q,%q) want (%q,%q)", c.name, id, src, c.id, c.source)
		}
	}
	if ctl.Labels["site"] != "nyc-manual" {
		t.Errorf("the operator's site was touched: %q", ctl.Labels["site"])
	}
}

// serveFakeOverlayKV answers the two reads FetchOverlayFacts makes (SMEMBERS +
// MGET) and a nil bulk for everything else, so the inventory read runs against
// real published facts rather than an unread store.
func serveFakeOverlayKV(t *testing.T, facts map[string]string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		if err := ln.Close(); err != nil {
			t.Logf("close fake kv: %v", err)
		}
	})
	serve := func(c net.Conn) {
		defer c.Close()
		r := bufio.NewReader(c)
		for {
			args, err := readRESPCommand(r)
			if err != nil {
				return
			}
			var reply strings.Builder
			switch strings.ToUpper(args[0]) {
			case "SMEMBERS":
				fmt.Fprintf(&reply, "*%d\r\n", len(facts))
				for id := range facts {
					fmt.Fprintf(&reply, "$%d\r\n%s\r\n", len(id), id)
				}
			case "MGET":
				fmt.Fprintf(&reply, "*%d\r\n", len(args)-1)
				for _, k := range args[1:] {
					if v, ok := facts[strings.TrimPrefix(k, "netops:sdwan:overlay:")]; ok {
						fmt.Fprintf(&reply, "$%d\r\n%s\r\n", len(v), v)
					} else {
						reply.WriteString("$-1\r\n")
					}
				}
			default:
				reply.WriteString("$-1\r\n")
			}
			if _, err := io.WriteString(c, reply.String()); err != nil {
				return
			}
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(c)
		}
	}()
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split %q: %v", ln.Addr(), err)
	}
	t.Setenv("REDIS_HOST", host)
	t.Setenv("REDIS_PORT", port)
}

// TestReportedSiteIsTenantScoped (§3a) — the overlay facts are one key space for
// every tenant, so the scoping is the inventory read's: a caller sees the site id
// of its own devices only, another tenant's device by id is 404, acting into
// another tenant does not widen it, and an operator does not see a restricted
// tenant's.
func TestReportedSiteIsTenantScoped(t *testing.T) {
	f := newRestrictedMapFixture(t)
	serveFakeOverlayKV(t, map[string]string{
		"acme-edge":   `{"device_id":"acme-edge","site_id":"100"}`,
		"globex-core": `{"device_id":"globex-core","site_id":"300"}`,
	})
	for _, id := range []string{"acme-core", "globex-core"} {
		d, ok := f.s.discovery.Get(id)
		if !ok {
			t.Fatalf("fixture lost %s", id)
		}
		d.Labels["source_system"] = "vmanage"
		d.Labels["controller_site_id"] = map[string]string{"acme-core": "200", "globex-core": "399"}[id]
		if err := f.s.discovery.Upsert(d); err != nil {
			t.Fatalf("upsert %s: %v", id, err)
		}
	}

	list := func(c jwtClaims) (string, map[string]models.Device) {
		t.Helper()
		w := httptest.NewRecorder()
		f.s.handleDevices(w, req(http.MethodGet, "/api/devices", "", c))
		if w.Code != http.StatusOK {
			t.Fatalf("GET /api/devices = %d (%s)", w.Code, w.Body.String())
		}
		var rows []models.Device
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
			t.Fatalf("decode: %v (%s)", err, w.Body.String())
		}
		byID := map[string]models.Device{}
		for _, d := range rows {
			byID[d.ID] = d
		}
		return w.Body.String(), byID
	}

	raw, own := list(f.acmeUser())
	if own["acme-edge"].ReportedSiteID != "100" || own["acme-edge"].ReportedSiteSource != "device" {
		t.Errorf("acme-edge's own report: %q / %q", own["acme-edge"].ReportedSiteID, own["acme-edge"].ReportedSiteSource)
	}
	if own["acme-core"].ReportedSiteID != "200" || own["acme-core"].ReportedSiteSource != "vmanage" {
		t.Errorf("acme-core's controller report: %q / %q", own["acme-core"].ReportedSiteID, own["acme-core"].ReportedSiteSource)
	}
	if _, leaked := own["globex-core"]; leaked || strings.Contains(raw, `"300"`) || strings.Contains(raw, `"399"`) {
		t.Errorf("CROSS-TENANT LEAK: acme read globex's site id: %s", raw)
	}

	byID := func(id string, c jwtClaims) (int, string) {
		t.Helper()
		w := httptest.NewRecorder()
		f.s.handleDeviceByID(w, req(http.MethodGet, "/api/devices/"+id, "", c))
		return w.Code, w.Body.String()
	}
	if code, body := byID("acme-edge", f.acmeUser()); code != http.StatusOK || !strings.Contains(body, `"reported_site_id":"100"`) {
		t.Errorf("own device by id = %d %s", code, body)
	}
	if code, body := byID("globex-core", f.acmeUser()); code != http.StatusNotFound || strings.Contains(body, "300") {
		t.Errorf("another tenant's device by id = %d %s, want 404", code, body)
	}

	// as_tenant into another org is ignored for a tenant user.
	acting := f.acmeUser()
	acting.ActingTenant = f.globex
	if raw, rows := list(acting); strings.Contains(raw, `"300"`) || len(rows) != 2 {
		t.Errorf("acting into globex widened the read: %s", raw)
	}

	// A platform owner acting into acme reads acme's only.
	if raw, rows := list(ownerActing(f.owner(), f.acme)); strings.Contains(raw, `"300"`) || rows["acme-edge"].ReportedSiteID != "100" {
		t.Errorf("owner acting as acme: %s", raw)
	}

	// An operator's Global view does not name a restricted tenant's site id.
	f.restrictAcme()
	if raw, rows := list(f.owner()); strings.Contains(raw, `"reported_site_id":"100"`) || rows["globex-core"].ReportedSiteID != "300" {
		t.Errorf("restricted tenant's site id in the Global view: %s", raw)
	}
}

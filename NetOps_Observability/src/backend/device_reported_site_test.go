// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
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

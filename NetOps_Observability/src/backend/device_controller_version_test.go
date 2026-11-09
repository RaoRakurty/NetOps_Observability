// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"testing"

	"netops/backend/models"
)

func TestControllerReportedVersion(t *testing.T) {
	cases := []struct {
		name string
		d    models.Device
		want string
	}{
		{"a controller's report is used", models.Device{OS: "Catalyst SD-WAN", OSVersion: "20.9.1", OSVersionSource: "api:vmanage"}, "20.9.1"},
		{"a manual or probed version is not (the patterns decide those)", models.Device{OS: "whatever", OSVersion: "x.y", OSVersionSource: "manual"}, ""},
		{"no provenance", models.Device{OSVersion: "17.3.2"}, ""},
	}
	for _, c := range cases {
		if got := controllerReportedVersion(c.d); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

// The read path, not just the helper: a controller-only device's OS label is
// not one the vendor patterns parse, so the inventory's Version column depends
// on this fallback.
func TestStampedVersionOfAControllerOnlyDevice(t *testing.T) {
	f := newRestrictedMapFixture(t)
	got := f.s.stampDeviceReadFields(context.Background(), f.owner(), []models.Device{
		{ID: "ctl-1", Vendor: "cisco", OS: "Catalyst SD-WAN", OSVersion: "20.9.1", OSVersionSource: "api:vmanage"},
		{ID: "man-1", Vendor: "cisco", OS: "Catalyst SD-WAN", OSVersion: "x.y", OSVersionSource: "manual"},
	})
	if got[0].SoftwareVersion != "20.9.1" {
		t.Errorf("controller-reported version = %q, want 20.9.1", got[0].SoftwareVersion)
	}
	if got[1].SoftwareVersion != "" {
		t.Errorf("a free-form manual version was shown as parsed: %q", got[1].SoftwareVersion)
	}
}

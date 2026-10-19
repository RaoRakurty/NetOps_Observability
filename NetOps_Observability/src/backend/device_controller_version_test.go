// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
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

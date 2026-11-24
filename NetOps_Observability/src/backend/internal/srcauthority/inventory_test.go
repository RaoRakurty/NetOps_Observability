// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package srcauthority

import (
	"strings"
	"testing"

	"netops/backend/models"
)

func TestApplyToDeviceStampsTheWinnerAndTheDisagreement(t *testing.T) {
	records := []models.Device{
		{ID: "ctl", Source: "nms:controller", Vendor: "Cisco", Model: "vedge-cloud", OSVersion: "20.6.1", OSVersionSource: "api:vmanage"},
		{ID: "snmp", Source: "snmp", Vendor: "cisco", OSVersion: "20.6.2", OSVersionSource: "snmp", SerialNumber: "FDO1"},
		{ID: "hand", Source: "manual", OSVersion: "9.9.9"},
	}
	order := DefaultOrder()
	d := models.Device{ID: "merged", Vendor: "stale", Model: "stale", SoftwareVersion: "stale",
		SourceDisagreements: []models.FactDisagreement{{Fact: "vendor", Text: "left over"}}}
	ApplyToDevice(&d, ResolveDevice(order, records), order, false)

	if d.SoftwareVersion != "20.6.1" || d.Model != "vedge-cloud" || d.SerialNumber != "FDO1" {
		t.Fatalf("winners not stamped: %+v", d)
	}
	if len(d.SourceDisagreements) != 1 || d.SourceDisagreements[0].Fact != "software_version" {
		t.Fatalf("exactly the version disagrees (Cisco/cisco agree), and a stale list is replaced: %+v", d.SourceDisagreements)
	}
	fd := d.SourceDisagreements[0]
	if fd.Label != "software version" || len(fd.Others) != 2 || !strings.Contains(fd.Text, "platform default source order") {
		t.Fatalf("disagreement: %+v", fd)
	}
}

func TestApplyToDeviceLeavesUnreportedFactsAlone(t *testing.T) {
	d := models.Device{ID: "x", Vendor: "Arista", SoftwareVersion: "4.30"}
	ApplyToDevice(&d, nil, DefaultOrder(), false)
	if d.Vendor != "Arista" || d.SoftwareVersion != "4.30" || d.SourceDisagreements != nil {
		t.Fatalf("no resolution must change nothing: %+v", d)
	}
}

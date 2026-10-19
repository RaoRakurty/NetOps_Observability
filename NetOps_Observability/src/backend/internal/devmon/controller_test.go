// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package devmon

import (
	"strings"
	"testing"
	"time"

	"netops/backend/models"
)

// A controller-sourced device counts like any monitored device, says it is
// known through its controller, and lists the controller as its one method —
// none of Correlix's own collectors reach it.
func TestControllerSourcedDevicesAreMonitoredThroughTheController(t *testing.T) {
	d := models.Device{ID: "ctl-vmanage-aaaaaaaaaaaa", Name: "vEdge-20", Address: "10.255.255.20", Source: SourceController}
	v := Assign([]Candidate{{Device: d, FirstSeen: time.Unix(1, 0)}}, NoLimit)[d.ID]
	if !v.Monitored || v.State != StateMonitored || v.Reason != ReasonController {
		t.Fatalf("%+v", v)
	}
	if got := Methods(d); len(got) != 1 || got[0] != MethodController {
		t.Fatalf("methods %v — want only the controller, never snmp", got)
	}
	// An over-limit controller device is over the limit like any other.
	two := []Candidate{{Device: models.Device{ID: "a", Address: "10.0.0.1"}, FirstSeen: time.Unix(1, 0)}, {Device: d, FirstSeen: time.Unix(2, 0)}}
	if v := Assign(two, 1)[d.ID]; v.Monitored || v.State != StateOverLimit || !strings.Contains(v.Reason, "limit") {
		t.Fatalf("over limit: %+v", v)
	}
}

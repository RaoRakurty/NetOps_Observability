// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"testing"

	"netops/backend/models"
)

// Owner, 2026-11-23: alert summaries (and so incidents, tickets and
// notifications built from them) name a device by its hostname, never by the
// internal `<sysName>-<address hash>` id. The engine reads the server's
// registry-backed snapshot once per tick.
func TestAlertDeviceNamesComeFromTheRegistry(t *testing.T) {
	_, s := newTestServerState(t)
	s.discovery.Upsert(models.Device{ID: "cedge-40-fdf7b64f", Name: "cEDGE-40", Address: "10.255.255.40", TenantID: "t_a"})
	s.discovery.Upsert(models.Device{ID: "vedge-51-79fbba30", Name: "vEdge-51", Address: "10.255.255.51", TenantID: "t_b"})
	s.discovery.Upsert(models.Device{ID: "noname-dddd", Address: "10.0.0.4", TenantID: "t_a"})
	// Same-name devices of one tenant are told apart by address, counted per
	// tenant (§3a) — pinned in internal/devname; the registry's identity merge
	// folds same-name rows before they reach this snapshot.

	names := s.alertDeviceNames()
	want := map[string]string{
		"cedge-40-fdf7b64f": "cEDGE-40",
		"vedge-51-79fbba30": "vEdge-51",
	}
	for id, w := range want {
		if names[id] != w {
			t.Errorf("name of %s = %q, want %q", id, names[id], w)
		}
	}
	if _, ok := names["noname-dddd"]; ok {
		t.Errorf("a device with no name must keep its id (no entry), got %q", names["noname-dddd"])
	}
}

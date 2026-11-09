// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery

import (
	"testing"

	"netops/backend/models"
)

// reported_site_id is server-stamped on read: a request body that carries it
// is ignored and nothing persists it (it could otherwise pose as the device's
// own answer and sit beside the operator's site as if the device said so).
func TestReportedSiteIsNeverPersistedFromInput(t *testing.T) {
	a := NewDiscoveryAggregator()
	if err := a.Upsert(models.Device{ID: "edge-1", Name: "edge-1", Address: "10.0.0.1",
		ReportedSiteID: "999", ReportedSiteSource: "device"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, ok := a.Get("edge-1")
	if !ok {
		t.Fatal("device not stored")
	}
	if got.ReportedSiteID != "" || got.ReportedSiteSource != "" {
		t.Errorf("a request-supplied reported site was persisted: %q / %q", got.ReportedSiteID, got.ReportedSiteSource)
	}
}

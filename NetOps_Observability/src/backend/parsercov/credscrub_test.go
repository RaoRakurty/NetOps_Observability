// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package parsercov

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"netops/backend/internal/credscrub"
)

// The unrecognized-lines miner serves raw sample lines and templates. A
// configured SNMP community in a line's text is masked before mining, so no
// sample, template or template id carries it.
func TestUnrecognizedMasksAConfiguredCommunityBeforeMining(t *testing.T) {
	comm := "fixture-comm-" + strings.Repeat("q", 6)
	cs := credscrub.New(func(context.Context) ([]string, error) { return []string{comm}, nil })
	if err := cs.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	seed := func(h *harness) {
		h.seedStamped("netops-syslog-acme-2026.09.01", 10, "0538afc1b47c")
		h.seedDoc("netops-syslog-acme-2026.09.01",
			syslogDoc("rtr-1", "poller", "", "poller "+comm+" answered from 127.0.0.1", "info", "2026-09-01T00:00:00Z"))
	}

	h := newHarness(t, acme())
	h.api.d.Mask = cs.Mask
	seed(h)
	w, page := h.get(t, "/api/telemetry/unrecognized")
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if len(page.Items) != 1 {
		t.Fatalf("items = %d, want the one shape", len(page.Items))
	}
	body, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), comm) {
		t.Fatalf("a configured community reached the page: %s", body)
	}
	if !strings.Contains(page.Items[0].Sample, credscrub.Mask) {
		t.Errorf("sample = %q, want the mask", page.Items[0].Sample)
	}

	// Without the seam the fixture does carry the value, so the test is live.
	plain := newHarness(t, acme())
	seed(plain)
	_, p2 := plain.get(t, "/api/telemetry/unrecognized")
	if len(p2.Items) != 1 || !strings.Contains(p2.Items[0].Sample, comm) {
		t.Fatal("the fixture no longer carries the value: the assertion above proves nothing")
	}
}

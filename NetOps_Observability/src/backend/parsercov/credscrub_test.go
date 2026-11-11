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
// sample, template or template id carries it, with the CALLER's set: acme's own
// value is masked, another tenant's is not (that would be an oracle on it).
func TestUnrecognizedMasksTheCallersCommunityBeforeMining(t *testing.T) {
	own := "fixture-comm-" + strings.Repeat("q", 6)
	other := "fixture-other-" + strings.Repeat("z", 4)
	cs := credscrub.New(func(context.Context) ([]credscrub.Value, error) {
		return []credscrub.Value{{Tenant: "acme", Text: own}, {Tenant: "globex", Text: other}}, nil
	})
	if err := cs.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	seed := func(h *harness) {
		h.seedStamped("netops-syslog-acme-2026.09.01", 10, "0538afc1b47c")
		h.seedDoc("netops-syslog-acme-2026.09.01",
			syslogDoc("rtr-1", "poller", "", "poller "+own+" answered "+other, "info", "2026-09-01T00:00:00Z"))
	}

	h := newHarness(t, acme())
	h.api.d.Mask = func(tenant string, cross bool, text string) string { return cs.For(tenant, cross).Mask(text) }
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
	if strings.Contains(string(body), own) {
		t.Fatalf("acme's community reached acme's page: %s", body)
	}
	if !strings.Contains(page.Items[0].Sample, credscrub.Mask) || !strings.Contains(page.Items[0].Sample, other) {
		t.Errorf("sample = %q, want acme's value masked and globex's left as text", page.Items[0].Sample)
	}

	// Without the seam the fixture does carry the value, so the test is live.
	plain := newHarness(t, acme())
	seed(plain)
	_, p2 := plain.get(t, "/api/telemetry/unrecognized")
	if len(p2.Items) != 1 || !strings.Contains(p2.Items[0].Sample, own) {
		t.Fatal("the fixture no longer carries the value: the assertion above proves nothing")
	}
}

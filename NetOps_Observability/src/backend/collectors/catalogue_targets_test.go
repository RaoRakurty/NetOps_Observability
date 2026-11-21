// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"strings"
	"testing"

	"netops/backend/internal/probercontrol"
)

type fakeRecord struct {
	configured bool
	list       []probercontrol.WireTarget
	refused    int
	why        probercontrol.Reason
	asked      string
}

func (f *fakeRecord) Configured() bool { return f.configured }
func (f *fakeRecord) Read(_ context.Context, which string) ([]probercontrol.WireTarget, int, probercontrol.Reason) {
	f.asked = which
	return f.list, f.refused, f.why
}

type fixedTargets []ProbeTarget

func (f fixedTargets) Targets(context.Context) ([]ProbeTarget, error) { return f, nil }

// Paths P3 target swap: with a channel the signed catalogue record is the
// ONLY source — each target keeps its tenant and site, STAMP gets the
// reflector port — and the env list is read only when no channel exists.
func TestCatalogueTargetsSwapsInTheSignedList(t *testing.T) {
	env := fixedTargets{{Addr: "10.99.0.1"}}
	rec := &fakeRecord{configured: true, why: probercontrol.ReasonPublished,
		list: []probercontrol.WireTarget{{ID: "dem-1", Tenant: "acme", Site: "branch-40", Addr: "203.0.113.10"}}}
	c := &catalogueTargets{rec: rec, which: probercontrol.ForStamp, port: 862, fallback: env}
	got, err := c.Targets(context.Background())
	if err != nil || len(got) != 1 || got[0] != (ProbeTarget{Addr: "203.0.113.10:862", Tenant: "acme", Site: "branch-40"}) {
		t.Fatalf("got %+v %v", got, err)
	}
	if rec.asked != probercontrol.ForStamp {
		t.Fatalf("asked for %q", rec.asked)
	}
	rec.configured = false
	got, err = c.Targets(context.Background())
	if err != nil || len(got) != 1 || got[0].Addr != "10.99.0.1" {
		t.Fatalf("no channel: the env list is the source: %+v %v", got, err)
	}
}

// Every doubt is an empty list and NOT the env list; nothing published yet is
// simply nothing to measure; refusals are counted on the status, never named.
func TestCatalogueTargetsFailsClosed(t *testing.T) {
	env := fixedTargets{{Addr: "10.99.0.1"}}
	for _, why := range []probercontrol.Reason{probercontrol.ReasonUnread, probercontrol.ReasonBadSignature,
		probercontrol.ReasonUnsigned, probercontrol.ReasonStale, probercontrol.ReasonNoKey, probercontrol.ReasonInvalid} {
		c := &catalogueTargets{rec: &fakeRecord{configured: true, why: why}, which: probercontrol.ForTraceroute, fallback: env}
		got, err := c.Targets(context.Background())
		if len(got) != 0 || err == nil || !strings.Contains(err.Error(), string(why)) {
			t.Fatalf("%s: got %+v %v — must be empty with the reason, never the env list", why, got, err)
		}
	}
	c := &catalogueTargets{rec: &fakeRecord{configured: true, why: probercontrol.ReasonNotPublished}, which: probercontrol.ForTraceroute, fallback: env}
	if got, err := c.Targets(context.Background()); len(got) != 0 || err != nil {
		t.Fatalf("not published: %+v %v", got, err)
	}
	c = &catalogueTargets{rec: &fakeRecord{configured: true, why: probercontrol.ReasonPublished, refused: 2,
		list: []probercontrol.WireTarget{{ID: "a", Tenant: "acme", Addr: "203.0.113.1"}}}, which: probercontrol.ForTraceroute, fallback: env}
	got, err := c.Targets(context.Background())
	if len(got) != 1 || err == nil || !strings.Contains(err.Error(), "2 catalogue target(s) refused") {
		t.Fatalf("refusals: %+v %v", got, err)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package invfacts

import (
	"context"
	"errors"
	"strings"
	"testing"

	"netops/backend/models"
	"netops/backend/nms"
)

func TestResolveDeviceFactsPrecedence(t *testing.T) {
	votes := func(model, site, role []string) *Votes {
		v := NewVotes()
		for _, m := range model {
			v.Models[m] = true
		}
		for _, s := range site {
			v.Sites[s] = true
		}
		for _, r := range role {
			v.Roles[r] = true
		}
		return v
	}
	cases := []struct {
		name   string
		d      models.Device
		manual string
		v      *Votes
		want   Facts
	}{
		{"nothing states anything", models.Device{}, "", nil, Facts{
			Model: Outcome{"", SourceNone, StateBlank}, Site: Outcome{"", SourceNone, StateBlank}, Role: Outcome{"", SourceNone, StateBlank}}},
		{"NMS fills all three", models.Device{}, "", votes([]string{"vedge-CSR-1000v"}, []string{"81"}, []string{"edge"}), Facts{
			Model: Outcome{"vedge-CSR-1000v", SourceNMS, StateSet}, Site: Outcome{"81", SourceNMS, StateSet}, Role: Outcome{"edge", SourceNMS, StateSet}}},
		{"manual site and role win over the NMS", models.Device{Labels: map[string]string{"role": "hub"}}, "dc-east", votes(nil, []string{"81"}, []string{"edge"}), Facts{
			Model: Outcome{"", SourceNone, StateBlank}, Site: Outcome{"dc-east", SourceManual, StateSet}, Role: Outcome{"hub", SourceManual, StateSet}}},
		{"inventory model agrees with the NMS", models.Device{Model: "vedge-CSR-1000v"}, "", votes([]string{"vedge-CSR-1000v"}, nil, nil), Facts{
			Model: Outcome{"vedge-CSR-1000v", SourceNMS, StateSet}, Site: Outcome{"", SourceNone, StateBlank}, Role: Outcome{"", SourceNone, StateBlank}}},
		{"inventory model alone", models.Device{Model: "C8300", Type: "router"}, "", nil, Facts{
			Model: Outcome{"C8300", SourceInventory, StateSet}, Site: Outcome{"", SourceNone, StateBlank}, Role: Outcome{"router", SourceInventory, StateSet}}},
		{"inventory and NMS disagree: blank", models.Device{Model: "CSR1000V"}, "", votes([]string{"vedge-CSR-1000v"}, nil, nil), Facts{
			Model: Outcome{"", SourceNMS, StateConflict}, Site: Outcome{"", SourceNone, StateBlank}, Role: Outcome{"", SourceNone, StateBlank}}},
		{"two controllers disagree: blank, and no type fallback", models.Device{Type: "router"}, "", votes(nil, []string{"40", "41"}, []string{"edge", "controller"}), Facts{
			Model: Outcome{"", SourceNone, StateBlank}, Site: Outcome{"", SourceNMS, StateConflict}, Role: Outcome{"", SourceNMS, StateConflict}}},
	}
	for _, c := range cases {
		if got := Resolve(c.d, c.manual, c.v); got != c.want {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, got, c.want)
		}
	}
}

func TestCleanCellAndSole(t *testing.T) {
	if got := CleanCell(" a\x00b\n "); got != "ab" {
		t.Fatalf("CleanCell %q", got)
	}
	if got := CleanCell(strings.Repeat("é", 300)); len([]rune(got)) != MaxCellRunes {
		t.Fatal("not bounded")
	}
	if Sole(map[string]bool{"a": true}) != "a" || Sole(map[string]bool{"a": true, "b": true}) != "" || Sole(nil) != "" {
		t.Fatal("Sole")
	}
}

type resolver map[string]string

func (r resolver) peek(tenant string, _ nms.KeyKind, key, _ string) (string, bool) {
	id, ok := r[tenant+"|"+key]
	return id, ok
}

func TestCollectIsOwnerKeyedAndCleans(t *testing.T) {
	votes := Collect([]IntegrationDevices{
		{Tenant: "t_a", Devs: []nms.ControllerDevice{
			{KeyKind: nms.KeySystemIP, Key: "10.0.0.1", Model: " M1\n", SiteID: "7", Role: "edge"},
			{KeyKind: nms.KeySystemIP, Key: "10.0.0.9", Model: "unresolved"},
			{KeyKind: nms.KeySystemIP, Key: "10.0.0.2", Role: "made-up"},
		}},
		{Tenant: "GLOBAL", Devs: []nms.ControllerDevice{{KeyKind: nms.KeySystemIP, Key: "10.0.0.1", Model: "P1"}}},
	}, resolver{"t_a|10.0.0.1": "d1", "t_a|10.0.0.2": "d2", "GLOBAL|10.0.0.1": "p1"}.peek)
	if v := votes[Key{"t_a", "d1"}]; v == nil || !v.Models["M1"] || !v.Sites["7"] || !v.Roles["edge"] {
		t.Fatalf("t_a/d1 %+v", v)
	}
	if v := votes[Key{"t_a", "d2"}]; v == nil || len(v.Roles) != 0 {
		t.Fatalf("an undefined role voted: %+v", v)
	}
	if v := votes[KeyFor("", "p1")]; v == nil || !v.Models["P1"] {
		t.Fatalf("platform spelled GLOBAL not keyed as the platform: %v", votes)
	}
	if len(votes) != 3 {
		t.Fatalf("an unresolved device voted: %v", votes)
	}
	if len(Collect(nil, nil)) != 0 {
		t.Fatal("nil resolver voted")
	}
}

type failingLister struct{}

func (failingLister) ListEnabled(context.Context) ([]nms.Integration, error) {
	return nil, errors.New("down")
}
func (failingLister) Devices(context.Context, string, bool, string) ([]nms.ControllerDevice, error) {
	return nil, nil
}

func TestRefreshNilSafety(t *testing.T) {
	var s *Store
	if s.Refresh(context.Background(), failingLister{}, resolver{}.peek) != nil || s.Current() != nil {
		t.Fatal("nil store")
	}
	if NewStore().Refresh(context.Background(), failingLister{}, resolver{}.peek) == nil {
		t.Fatal("failure not returned")
	}
}

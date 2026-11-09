// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package vendorprofile

import (
	"strings"
	"testing"
)

// Every detectable vendor resolves to itself by id and by display name. A new
// profile that breaks this would silently fall back to format matching for its
// whole estate.
func TestInventoryVendorIDRoundTripsEveryVendor(t *testing.T) {
	reg := Default()
	for _, id := range reg.VendorIDs() {
		rec, _ := reg.Vendor(id)
		if rec.Detection.AgentIdentity {
			continue
		}
		for _, spelling := range []string{id, rec.DisplayName, strings.ToUpper(id)} {
			if got, ok := reg.InventoryVendorID(spelling); !ok || got != id {
				t.Errorf("InventoryVendorID(%q) = %q, %v; want %q", spelling, got, ok, id)
			}
		}
	}
}

func TestInventoryVendorIDRefusesWhatIsNotAVendorFact(t *testing.T) {
	reg := Default()
	for _, v := range []string{"net-snmp", "Net-SNMP", "linux", "Linux", "generic", "Vendor-neutral", "", "   ", "Definitely Not A Vendor"} {
		if got, ok := reg.InventoryVendorID(v); ok {
			t.Errorf("InventoryVendorID(%q) = %q; a non-vendor must never narrow a grammar", v, got)
		}
	}
	// A sysDescr marker reaching an agent identity is refused too: the text said
	// Linux, which is not who built the box.
	if got, ok := reg.InventoryVendorID("Some Linux Appliance"); ok {
		t.Errorf("a text match on an agent identity resolved to %q", got)
	}
}

func TestInventoryVendorIDReadsFreeFormNames(t *testing.T) {
	reg := Default()
	for spelling, want := range map[string]string{
		"Cisco Systems":              "cisco",
		"Cisco Systems, Inc.":        "cisco",
		"Arista Networks":            "arista",
		"Juniper Networks":           "juniper",
		"Palo Alto Networks":         "paloalto",
		"Hewlett Packard Enterprise": "hp",
		"HPE":                        "hp",
		"Dell EMC":                   "dell",
		"F5, Inc.":                   "f5",
	} {
		if got, ok := reg.InventoryVendorID(spelling); !ok || got != want {
			t.Errorf("InventoryVendorID(%q) = %q, %v; want %q", spelling, got, ok, want)
		}
	}
}

func TestSONiCIsDetectedFromSysDescrBehindTheAgentEnterprise(t *testing.T) {
	reg := Default()
	const sonic = "SONiC Software Version: SONiC.20230531.26 - HwSku: Force10-S6000 - Distribution: Debian 11.9 - Kernel: 5.10.0-23-2-amd64"

	if v, ok := reg.VendorForSysObjectID("1.3.6.1.4.1.8072.3.2.10"); !ok || v != "net-snmp" {
		t.Fatalf("premise: enterprise 8072 must answer net-snmp, got %q, %v", v, ok)
	}
	if v, ok := reg.VendorRefiningAgent("net-snmp", sonic); !ok || v != "sonic" {
		t.Fatalf("the sysDescr must refine the agent to sonic, got %q, %v", v, ok)
	}
	// The refinement is scoped to the agent it declares...
	if v, ok := reg.VendorRefiningAgent("cisco", sonic); ok {
		t.Fatalf("a real vendor's enterprise must not be refined, got %q", v)
	}
	// ...and a plain host behind the same agent keeps its detection answer.
	for _, plain := range []string{"Linux host 5.15.0-198-generic #208-Ubuntu SMP x86_64", "", "supersonic router"} {
		if v, ok := reg.VendorRefiningAgent("net-snmp", plain); ok {
			t.Fatalf("sysDescr %q refined to %q", plain, v)
		}
	}
	// The text backstop finds it too, ahead of the Linux rung its kernel would hit.
	if v, ok := reg.VendorForSysDescr(sonic + " Linux"); !ok || v != "sonic" {
		t.Fatalf("text backstop: got %q, %v", v, ok)
	}
	if v, ok := reg.InventoryVendorID("sonic"); !ok || v != "sonic" {
		t.Fatalf("SONiC is a network OS, so telemetry may be narrowed by it: got %q, %v", v, ok)
	}
}

func TestRefinesAgentsMustNameAnAgentIdentity(t *testing.T) {
	_, err := build([]vendorDoc{
		{SchemaVersion: 1, Vendor: "real", DisplayName: "Real", Detection: Detection{
			SysObjectIDPrefixes: []string{"1.3.6.1.4.1.99991"},
		}},
		{SchemaVersion: 1, Vendor: "nos", DisplayName: "NOS", Detection: Detection{
			SysDescrContains: []string{"nos"}, SysDescrRank: 5, RefinesAgents: []string{"real"},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "agent_identity") {
		t.Fatalf("refining a real vendor must not load, got %v", err)
	}
}

func TestInventoryNamesMustNotCollide(t *testing.T) {
	_, err := build([]vendorDoc{
		{SchemaVersion: 1, Vendor: "one", DisplayName: "One", Detection: Detection{InventoryNames: []string{"shared name"}}},
		{SchemaVersion: 1, Vendor: "two", DisplayName: "Two", Detection: Detection{InventoryNames: []string{"Shared-Name"}}},
	})
	if err == nil || !strings.Contains(err.Error(), "claimed by both") {
		t.Fatalf("one spelling naming two vendors must not load, got %v", err)
	}
}

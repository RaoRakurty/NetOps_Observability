// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package snmpcred

import (
	"sort"
	"strings"
	"testing"

	"netops/backend/models"
)

func ctlOnly(d models.Device) bool { return d.Source == "api" }

// Tracker 371 R2: a controller-only device's receive-only identity targets carry
// ONLY its owner's profiles (owner decision D2), are marked ReceiveOnly, and
// exist only for monitored controller-only devices.
func TestReceiveOnlyTargetsAreOwnerStrict(t *testing.T) {
	cs, _ := resolveFixture(t)
	if _, err := cs.Upsert(Credential{ID: "acme-v3", Name: "Acme v3", Version: "v3", SecurityName: "u", SecurityLevel: "authNoPriv",
		AuthProtocol: "SHA", AuthKey: "acmeauthkey123", TenantID: "acme"}); err != nil {
		t.Fatal(err)
	}
	devs := []models.Device{
		{ID: "ctl-acme", Name: "acme-b", Address: "10.0.0.1", TenantID: "acme", Source: "api", Monitored: true},
		{ID: "ctl-plat", Name: "plat-b", Address: "10.0.0.2", TenantID: "", Source: "api", Monitored: true},
		{ID: "ctl-over", Name: "over", Address: "10.0.0.3", TenantID: "acme", Source: "api", Monitored: false}, // past the licence ceiling
		{ID: "snmp-1", Name: "polled", Address: "10.0.0.4", TenantID: "acme", Source: "snmp", Monitored: true}, // a direct device
	}
	got := ReceiveOnlyTargets(devs, cs, ctlOnly)
	per := map[string][]string{}
	for _, tg := range got {
		if !tg.ReceiveOnly {
			t.Fatalf("a target was not marked receive-only: %+v", tg)
		}
		cred := tg.Community
		if tg.SNMPVersion == 3 {
			cred = "v3:" + tg.V3User
		}
		per[tg.ID] = append(per[tg.ID], cred)
		if tg.TenantID == "acme" && (tg.Community == "platform" || tg.Community == "globex" || tg.Community == "g") {
			t.Fatalf("a tenant device carried another owner's profile: %+v", tg)
		}
	}
	for id := range per {
		sort.Strings(per[id])
	}
	if strings.Join(per["ctl-acme"], ",") != "acme,v3:u" {
		t.Fatalf("acme's controller-only device: %v (want its two own profiles)", per["ctl-acme"])
	}
	// The platform's device gets the platform's profiles only.
	for _, c := range per["ctl-plat"] {
		if c == "acme" || c == "globex" || c == "v3:u" {
			t.Fatalf("the platform's device carried a tenant profile: %v", per["ctl-plat"])
		}
	}
	if len(per["ctl-plat"]) == 0 {
		t.Fatal("the platform's controller-only device got no target")
	}
	if _, ok := per["ctl-over"]; ok {
		t.Fatal("a device past the licence ceiling got an identity target")
	}
	if _, ok := per["snmp-1"]; ok {
		t.Fatal("a directly collected device got a receive-only target")
	}
}

// An owner with no profile gets no identity target (the device stays unprovable,
// as before); no store at all yields none. (A v2c profile with no community is
// refused by the store itself, so the builder's skip of one is defence only.)
func TestReceiveOnlyTargetsNeedAnOwnersProfile(t *testing.T) {
	cs, _ := resolveFixture(t)
	if got := ReceiveOnlyTargets([]models.Device{{ID: "ctl-solo", TenantID: "solo", Source: "api", Monitored: true}}, cs, ctlOnly); len(got) != 0 {
		t.Fatalf("an owner with no profile got an identity target: %+v", got)
	}
	if ReceiveOnlyTargets([]models.Device{{ID: "x", Source: "api", Monitored: true}}, nil, ctlOnly) != nil {
		t.Fatal("no credential store must yield no targets")
	}
}

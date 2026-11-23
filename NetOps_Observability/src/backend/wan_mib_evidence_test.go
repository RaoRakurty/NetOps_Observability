// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"errors"
	"testing"

	"netops/backend/collectors"
	"netops/backend/internal/ifbridge"
	"netops/backend/models"
	"netops/backend/wan"
)

// Tracker 436 (b)/(c) at the api: a plain-router estate (no controller rows, no
// TLOCs, no marks, no declared next-hops) used to show an EMPTY confirmed WAN
// list. The router's own IF-MIB ifType and BGP4-MIB sessions now confirm its
// WAN ports, which then become measured circuits.

func plainRouterEvidence(ifaddr map[string]map[string]string) func(context.Context) (ifbridge.Merged, error) {
	return func(context.Context) (ifbridge.Merged, error) {
		return ifbridge.Merged{
			Addr: ifaddr,
			Index: map[string]map[string]string{
				"br-gw-1": {"1": "Serial0/1/0", "2": "GigabitEthernet0/0/0", "3": "GigabitEthernet0/0/1"},
			},
			Kind: map[string]map[string]string{
				"br-gw-1": {"1": ifbridge.KindWANMedia, "2": ifbridge.KindEthernet, "3": ifbridge.KindEthernet},
			},
			IfType: map[string]map[string]int{"br-gw-1": {"1": 22, "2": 6, "3": 6}},
		}, nil
	}
}

// addrOnlyEvidence is a bridge with addresses and nothing else: no controller
// row states a role (newWanTestServer's default marks every port transport).
func addrOnlyEvidence(ifaddr map[string]map[string]string) func(context.Context) (ifbridge.Merged, error) {
	return func(context.Context) (ifbridge.Merged, error) { return ifbridge.Merged{Addr: ifaddr}, nil }
}

func TestPlainRouterEstateConfirmsWANPortsFromItsOwnMIBs(t *testing.T) {
	ifaddr := map[string]map[string]string{
		"br-gw-1": {"198.51.100.2": "Serial0/1/0", "203.0.113.2": "GigabitEthernet0/0/0", "10.10.0.1": "GigabitEthernet0/0/1"},
		"core-1":  {"10.10.0.2": "Ethernet1"},
	}
	s := newWanTestServer(t, ifaddr, nil)
	s.wanIfEvidence = plainRouterEvidence(ifaddr)
	s.wanBGP = func(context.Context) (map[string]collectors.BGPSessions, error) {
		return map[string]collectors.BGPSessions{"br-gw-1": {LocalAS: 65010, Peers: map[string]collectors.BGPSession{
			"203.0.113.1": {Local: "203.0.113.2", RemoteAS: 64500}, // the ISP: external eBGP
			"10.10.0.2":   {Local: "10.10.0.1", RemoteAS: 65020},   // eBGP to core-1, which IS in the inventory
		}}}, nil
	}
	s.discovery.Upsert(models.Device{ID: "br-gw-1", Name: "br-gw-1", TenantID: "acme"})
	s.discovery.Upsert(models.Device{ID: "core-1", Name: "core-1", TenantID: "acme"})

	p, err := s.wanProjectAll(context.Background(), wanVis(s, "acme"))
	if err != nil {
		t.Fatalf("projection: %v", err)
	}
	got := map[string]WanEndpoint{}
	for _, e := range p.Endpoints {
		got[e.Device+"/"+e.Interface] = e
	}
	if len(got) != 2 {
		t.Fatalf("confirmed = %v, want the serial port and the ISP hand-off only", got)
	}
	if e := got["br-gw-1/Serial0/1/0"]; e.WanBasis != wan.BasisWANMedia || len(e.WanEvidence) == 0 || e.WanEvidence[0].Detail != "IF-MIB ifType propPointToPointSerial(22)" {
		t.Errorf("serial: %+v", e)
	}
	if e := got["br-gw-1/GigabitEthernet0/0/0"]; e.WanBasis != wan.BasisExternalBGP || e.Measurable != "203.0.113.2" {
		t.Errorf("ISP hand-off: %+v", e)
	}
	if len(p.Circuits) != 2 {
		t.Errorf("confirmed interfaces become measured circuits: %+v", p.Circuits)
	}
}

// §3a: BGP sessions are keyed by device, so one tenant's sessions never touch
// another tenant's ports, and the "outside the inventory" test reads only the
// caller's devices.
func TestWanBGPEvidenceIsTenantScoped(t *testing.T) {
	ifaddr := map[string]map[string]string{
		"acme-gw":   {"203.0.113.2": "Gi0/0/0"},
		"globex-gw": {"203.0.113.1": "Gi0/0/0"},
	}
	s := newWanTestServer(t, ifaddr, nil)
	s.wanIfEvidence = addrOnlyEvidence(ifaddr)
	s.wanBGP = func(context.Context) (map[string]collectors.BGPSessions, error) {
		return map[string]collectors.BGPSessions{
			// acme peers with an address globex's router holds: to acme, globex is
			// an external party, so acme's port is confirmed.
			"acme-gw": {LocalAS: 65010, Peers: map[string]collectors.BGPSession{"203.0.113.1": {Local: "203.0.113.2", RemoteAS: 64500}}},
			// globex's own session must not confirm anything for acme.
			"globex-gw": {LocalAS: 64500, Peers: map[string]collectors.BGPSession{"203.0.113.2": {Local: "203.0.113.1", RemoteAS: 65010}}},
		}, nil
	}
	s.discovery.Upsert(models.Device{ID: "acme-gw", Name: "acme-gw", TenantID: "acme"})
	s.discovery.Upsert(models.Device{ID: "globex-gw", Name: "globex-gw", TenantID: "globex"})

	acme, _ := s.wanProjectAll(context.Background(), wanVis(s, "acme"))
	for _, e := range append(append([]WanEndpoint{}, acme.Endpoints...), acme.Candidates...) {
		if e.Device != "acme-gw" {
			t.Fatalf("TENANT LEAK: acme saw %s/%s", e.Device, e.Interface)
		}
	}
	if len(acme.Endpoints) != 1 || acme.Endpoints[0].WanBasis != wan.BasisExternalBGP {
		t.Fatalf("acme: %+v", acme.Endpoints)
	}
	// The platform view holds both routers: each one's peer is IN the inventory,
	// so neither session is external there.
	all, _ := s.wanProjectAll(context.Background(), wanVis(s, ""))
	for _, e := range all.Endpoints {
		if e.WanBasis == wan.BasisExternalBGP {
			t.Fatalf("a peer the caller's inventory holds read as external: %+v", e)
		}
	}
}

// An unread sessions source is reported and reads as no sessions: the view is
// still served, and nothing is confirmed on BGP evidence it did not read.
func TestWanBGPUnreadConfirmsNothingAndStillServes(t *testing.T) {
	ifaddr := map[string]map[string]string{"br-gw-1": {"203.0.113.2": "GigabitEthernet0/0/0"}}
	s := newWanTestServer(t, ifaddr, nil)
	s.wanIfEvidence = addrOnlyEvidence(ifaddr)
	s.wanBGP = func(context.Context) (map[string]collectors.BGPSessions, error) {
		return nil, errors.New("kv channel down")
	}
	s.discovery.Upsert(models.Device{ID: "br-gw-1", Name: "br-gw-1", TenantID: "acme"})
	p, _ := s.wanProjectAll(context.Background(), wanVis(s, "acme"))
	for _, e := range append(append([]WanEndpoint{}, p.Endpoints...), p.Candidates...) {
		if e.WanBasis == wan.BasisExternalBGP {
			t.Fatalf("an unread BGP source decided a port: %+v", e)
		}
	}
	if len(p.Candidates) == 0 {
		t.Fatal("the WAN router's ports are still offered as possible")
	}
}

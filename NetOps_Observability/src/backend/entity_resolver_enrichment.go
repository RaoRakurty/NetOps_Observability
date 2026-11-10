// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	"netops/backend/models"
)

// entity_resolver_enrichment.go — exports the C7.1 EntityResolver inputs to the
// shared enrichment dir as entity_resolver.json: the IP→device and
// (device,ifIndex)→ifName bridges that every directed-topology direction source
// (C7.3 NetFlow, C7.4 traceroute, C7.5 routing) and the G2 canonicalizer need to
// turn raw IPs / ifIndexes into correlation entities (device / device:ifName).
//
// Mirrors startTopologyLinksEnrichment: atomic write, 60s refresh, no-op without
// the shared volume / discovery. TENANT-SCOPED — every row carries its device's
// tenant ("" = global), so the correlation engine resolves within a tenant
// (a tenant's rows ∪ global); identity never crosses tenants (zero-leak bar).
// Sources: discovery devices (mgmt IP→device) + the SNMP collector's Redis maps
// (interface IP→ifName via ifAddrKey, ifIndex→ifName via ifIndexKey). An absent
// source simply omits those rows → the resolver abstains for that pair (UNKNOWN),
// never guesses. A source that could not be READ omits the same rows — the export
// is not worth refusing over a naming bridge — but it is LOGGED, because an
// abstention the engine was never told about looks exactly like a fleet that has
// no interface addresses (tracker 307, §10).

type erDevice struct {
	TenantID string `json:"tenant_id"`
	Device   string `json:"device"`            // correlation device entity (device id)
	Name     string `json:"name,omitempty"`    // human name (an alias for IP→device)
	MgmtIP   string `json:"mgmt_ip,omitempty"` // management address
}

type erIfaceIP struct {
	TenantID string `json:"tenant_id"`
	Device   string `json:"device"`
	IP       string `json:"ip"`
	IfName   string `json:"ifname"`
}

type erIfIndex struct {
	TenantID string `json:"tenant_id"`
	Device   string `json:"device"`
	IfIndex  string `json:"ifindex"`
	IfName   string `json:"ifname"`
}

type entityResolverExport struct {
	Devices      []erDevice  `json:"devices"`
	InterfaceIPs []erIfaceIP `json:"interface_ips"`
	IfIndex      []erIfIndex `json:"ifindex"`
}

// buildEntityResolverExport joins the inventory to the tenant-less SNMP maps. A row
// whose device is not in the inventory is LEFT OUT: its tenant is unknown, and ""
// means global, which every tenant's resolver reads (§3a). The maps and the inventory
// are read at different moments, so such a row exists for up to a poll interval after
// a device is removed.
func buildEntityResolverExport(devs []models.Device, ifaddr, ifidx map[string]map[string]string) entityResolverExport {
	tenantBy := make(map[string]string, len(devs))
	out := entityResolverExport{}
	for _, d := range devs {
		if d.ID == "" {
			continue
		}
		t := deviceTenant(d)
		tenantBy[d.ID] = t
		out.Devices = append(out.Devices, erDevice{
			TenantID: t, Device: d.ID, Name: d.Name, MgmtIP: d.Address,
		})
	}
	for dev, m := range ifaddr {
		t, known := tenantBy[dev]
		if !known {
			continue
		}
		for ip, name := range m {
			out.InterfaceIPs = append(out.InterfaceIPs, erIfaceIP{TenantID: t, Device: dev, IP: ip, IfName: name})
		}
	}
	for dev, m := range ifidx {
		t, known := tenantBy[dev]
		if !known {
			continue
		}
		for idx, name := range m {
			out.IfIndex = append(out.IfIndex, erIfIndex{TenantID: t, Device: dev, IfIndex: idx, IfName: name})
		}
	}
	return out
}

func (s *server) startEntityResolverEnrichment(ctx context.Context) {
	dir := os.Getenv("TENANT_ENRICHMENT_DIR")
	if dir == "" || s.discovery == nil {
		return
	}
	write := func() {
		// Both registry reads are OMIT-THE-ROWS-AND-SAY-SO (tracker 307). The
		// resolver abstains for a pair it has no row for, which is the correct and
		// safe behaviour — it never guesses — but "abstain" and "the SNMP collector
		// published nothing" are indistinguishable downstream: the correlation
		// engine simply resolves fewer IPs / ifIndexes to entities and every
		// direction source that needs them quietly weakens. The device rows above
		// come from discovery and are unaffected, so the export still happens.
		// One read of the merged interface bridge (if_bridge.go): the SNMP
		// collector's rows and the controllers' (tracker 387 PR 13a).
		bridge, bridgeErr := fetchIfBridge(ctx)
		reportIfRegistryUnread("enrichment", "entity_resolver.json is exported with NO interface-IP or ifIndex rows, so the correlation engine cannot resolve an interface IP or a NetFlow/gNMI ifIndex to device:ifName this cycle", bridgeErr, nil)
		out := buildEntityResolverExport(s.discovery.Devices(), bridge.Addr, bridge.Index)
		data, err := json.Marshal(out)
		if err != nil {
			log.Printf("entity-resolver-enrichment: marshal: %v", err)
			return
		}
		if err := writeFileAtomic(filepath.Join(dir, "entity_resolver.json"), data, 0o644); err != nil {
			log.Printf("entity-resolver-enrichment: write: %v", err)
			return
		}
		log.Printf("entity-resolver-enrichment: exported %d device(s), %d iface-ip(s), %d ifindex(es)",
			len(out.Devices), len(out.InterfaceIPs), len(out.IfIndex))
	}
	go func() {
		write()
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				write()
			}
		}
	}()
}

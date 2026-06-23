package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	"netops/backend/collectors"
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
// never guesses.

type erDevice struct {
	TenantID string `json:"tenant_id"`
	Device   string `json:"device"`           // correlation device entity (device id)
	Name     string `json:"name,omitempty"`   // human name (an alias for IP→device)
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

func (s *server) startEntityResolverEnrichment(ctx context.Context) {
	dir := os.Getenv("TENANT_ENRICHMENT_DIR")
	if dir == "" || s.discovery == nil {
		return
	}
	write := func() {
		// deviceID → tenant, to scope the tenant-less Redis maps below.
		tenantBy := map[string]string{}
		out := entityResolverExport{}
		for _, d := range s.discovery.Devices() {
			t := deviceTenant(d)
			if d.ID == "" {
				continue
			}
			tenantBy[d.ID] = t
			out.Devices = append(out.Devices, erDevice{
				TenantID: t, Device: d.ID, Name: d.Name, MgmtIP: d.Address,
			})
		}
		if ifaddr, err := collectors.FetchIfAddrMap(ctx); err == nil {
			for dev, m := range ifaddr {
				for ip, name := range m {
					out.InterfaceIPs = append(out.InterfaceIPs, erIfaceIP{
						TenantID: tenantBy[dev], Device: dev, IP: ip, IfName: name,
					})
				}
			}
		}
		if ifidx, err := collectors.FetchIfIndexMap(ctx); err == nil {
			for dev, m := range ifidx {
				for idx, name := range m {
					out.IfIndex = append(out.IfIndex, erIfIndex{
						TenantID: tenantBy[dev], Device: dev, IfIndex: idx, IfName: name,
					})
				}
			}
		}
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

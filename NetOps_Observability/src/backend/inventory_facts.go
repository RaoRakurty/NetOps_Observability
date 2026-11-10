// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/owner"
	"netops/backend/models"
	"netops/backend/nms"
)

// inventory_facts.go — model, site and role from the NMS onto the registry
// (tracker 387 PR 13a; nms/facts.go maps each vendor's words).
//
// The registry (device_tenant.csv) stamps model, site and role on every syslog
// line and trap. On the lab all three were blank for every device: the SNMP
// scan reads none of them, and the controller that knows all three was never
// asked. Every minute the api reads each enabled integration's device list,
// resolves each controller device to the inventory device the INTEGRATION'S
// OWN OWNER owns (nms.InventoryResolver, owner-strict), and votes its facts
// onto that device. A controller device that resolves to nothing, or to more
// than one device, votes nothing. So a fact never crosses a tenant: another
// owner's integration can name only its own owner's devices.
//
// Precedence, per fact (owner decision 2026-10-18 for site; the same shape for
// role):
//
//	model: the inventory record's model and every NMS model must agree;
//	site:  the operator's site (SoT binding, then the site label, then the
//	       location label) wins; else the NMS site id;
//	role:  the operator's role label wins; else the NMS role; else the
//	       inventory type.
//
// Never invent: a fact nobody states stays blank, and two sources that
// disagree leave it blank (the registry's soleFact rule), counted as a
// conflict.

// Fact names, sources and states — the closed label sets of
// netops_inventory_facts{fact,source,state}.
const (
	factModel = "model"
	factSite  = "site"
	factRole  = "role"

	factSourceManual    = "manual"
	factSourceInventory = "inventory"
	factSourceNMS       = "nms"
	factSourceNone      = "none"

	factStateSet      = "set"
	factStateBlank    = "blank"
	factStateConflict = "conflict"
)

// factKey is one inventory device of one owner.
type factKey struct{ owner, device string }

// factVotes are the values the NMS states for one device, per fact.
type factVotes struct{ models, sites, roles map[string]bool }

func newFactVotes() *factVotes {
	return &factVotes{models: map[string]bool{}, sites: map[string]bool{}, roles: map[string]bool{}}
}

// integrationDevices is one integration's controller device list.
type integrationDevices struct {
	Tenant string
	Devs   []nms.ControllerDevice
}

// deviceResolveFunc resolves a controller key to an inventory id of the
// tenant's OWN devices (nms.InventoryResolver.Peek).
type deviceResolveFunc func(tenant string, kind nms.KeyKind, key, name string) (string, bool)

// collectNMSFacts votes every integration's facts onto the inventory devices
// their keys resolve to. Pure.
func collectNMSFacts(ints []integrationDevices, resolve deviceResolveFunc) map[factKey]*factVotes {
	out := map[factKey]*factVotes{}
	if resolve == nil {
		return out
	}
	for _, ic := range ints {
		own := owner.Of(ic.Tenant)
		for _, d := range ic.Devs {
			id, ok := resolve(ic.Tenant, d.KeyKind, d.Key, d.Name)
			if !ok || id == "" {
				continue
			}
			f := nms.FactsOf(d)
			k := factKey{own, id}
			v := out[k]
			if v == nil {
				v = newFactVotes()
				out[k] = v
			}
			for _, c := range []struct {
				into  map[string]bool
				value string
			}{{v.models, f.Model}, {v.sites, f.Site}, {v.roles, f.Role}} {
				if s := cleanEnrichmentCell(c.value); s != "" {
					c.into[s] = true
				}
			}
		}
	}
	return out
}

// factOutcome is one fact of one device: the value the registry stamps, and
// where it came from.
type factOutcome struct{ value, source, state string }

// invDeviceFacts is the three facts of one device.
type invDeviceFacts struct{ model, site, role factOutcome }

// voteOutcome settles a fact from the NMS votes alone.
func voteOutcome(votes map[string]bool) factOutcome {
	switch len(votes) {
	case 0:
		return factOutcome{source: factSourceNone, state: factStateBlank}
	case 1:
		return factOutcome{value: soleFact(votes), source: factSourceNMS, state: factStateSet}
	}
	return factOutcome{source: factSourceNMS, state: factStateConflict}
}

// resolveDeviceFacts applies the precedence above. manualSite is the
// operator's site for the device (enrichmentSite); votes may be nil.
func resolveDeviceFacts(d models.Device, manualSite string, votes *factVotes) invDeviceFacts {
	if votes == nil {
		votes = newFactVotes()
	}
	var out invDeviceFacts

	inv := cleanEnrichmentCell(d.Model)
	all := map[string]bool{}
	for m := range votes.models {
		all[m] = true
	}
	if inv != "" {
		all[inv] = true
	}
	switch {
	case len(all) == 0:
		out.model = factOutcome{source: factSourceNone, state: factStateBlank}
	case len(all) > 1:
		out.model = factOutcome{source: factSourceNMS, state: factStateConflict}
	case len(votes.models) > 0:
		out.model = factOutcome{value: soleFact(all), source: factSourceNMS, state: factStateSet}
	default:
		out.model = factOutcome{value: inv, source: factSourceInventory, state: factStateSet}
	}

	if s := cleanEnrichmentCell(manualSite); s != "" {
		out.site = factOutcome{value: s, source: factSourceManual, state: factStateSet}
	} else {
		out.site = voteOutcome(votes.sites)
	}

	if r := cleanEnrichmentCell(d.Labels["role"]); r != "" {
		out.role = factOutcome{value: r, source: factSourceManual, state: factStateSet}
	} else if out.role = voteOutcome(votes.roles); out.role.state == factStateBlank {
		if t := cleanEnrichmentCell(d.Type); t != "" {
			out.role = factOutcome{value: t, source: factSourceInventory, state: factStateSet}
		}
	}
	return out
}

// factStatKey is one netops_inventory_facts series.
type factStatKey struct{ fact, source, state string }

// inventoryFacts holds the last good NMS votes and the last export's counts.
// Safe for concurrent use.
type inventoryFacts struct {
	mu        sync.Mutex
	votes     map[factKey]*factVotes
	stats     map[factStatKey]int
	readFails uint64
}

func newInventoryFacts() *inventoryFacts {
	return &inventoryFacts{votes: map[factKey]*factVotes{}, stats: map[factStatKey]int{}}
}

// current returns the last good votes.
func (f *inventoryFacts) current() map[factKey]*factVotes {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.votes
}

// refresh reads every enabled integration's device list and replaces the
// votes. A failed read keeps the previous votes: losing every fact for a
// minute because one read failed would rewrite the registry twice.
func (f *inventoryFacts) refresh(ctx context.Context, store nms.EnabledLister, resolve deviceResolveFunc) error {
	if f == nil || store == nil || resolve == nil {
		return nil
	}
	ints, err := store.ListEnabled(ctx)
	if err != nil {
		f.failed()
		return fmt.Errorf("controller integrations unread: %w", err)
	}
	sort.Slice(ints, func(i, j int) bool { return nms.Key(ints[i].Tenant, ints[i].ID) < nms.Key(ints[j].Tenant, ints[j].ID) })
	per := make([]integrationDevices, 0, len(ints))
	for _, ic := range ints {
		// Tenant-scoped read (§3a): the integration's own owner's rows only.
		devs, err := store.Devices(ctx, ic.Tenant, false, ic.ID)
		if err != nil {
			f.failed()
			return fmt.Errorf("controller devices for %s unread: %w", ic.ID, err)
		}
		per = append(per, integrationDevices{Tenant: ic.Tenant, Devs: devs})
	}
	votes := collectNMSFacts(per, resolve)
	f.mu.Lock()
	f.votes = votes
	f.mu.Unlock()
	return nil
}

func (f *inventoryFacts) failed() {
	f.mu.Lock()
	f.readFails++
	f.mu.Unlock()
}

// setStats replaces the last export's counts.
func (f *inventoryFacts) setStats(stats map[factStatKey]int) {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.stats = stats
	f.mu.Unlock()
}

// factStatKeys is the closed, zero-filled label set, in exposition order.
func factStatKeys() []factStatKey {
	var out []factStatKey
	for _, fact := range []string{factModel, factSite, factRole} {
		for _, k := range []factStatKey{
			{fact, factSourceManual, factStateSet}, {fact, factSourceInventory, factStateSet},
			{fact, factSourceNMS, factStateSet}, {fact, factSourceNMS, factStateConflict},
			{fact, factSourceNone, factStateBlank},
		} {
			out = append(out, k)
		}
	}
	return out
}

// WriteMetrics renders netops_inventory_facts and the read-failure counter.
func (f *inventoryFacts) WriteMetrics(w io.Writer) {
	if f == nil {
		return
	}
	f.mu.Lock()
	stats := make(map[factStatKey]int, len(f.stats))
	for k, v := range f.stats {
		stats[k] = v
	}
	fails := f.readFails
	f.mu.Unlock()
	fmt.Fprintf(w, "# HELP netops_inventory_facts Inventory devices in the last registry export, by fact, the source that settled it, and state (set, blank, conflict).\n")
	fmt.Fprintf(w, "# TYPE netops_inventory_facts gauge\n")
	for _, k := range factStatKeys() {
		fmt.Fprintf(w, "netops_inventory_facts{fact=%q,source=%q,state=%q} %d\n", k.fact, k.source, k.state, stats[k])
	}
	fmt.Fprintf(w, "# HELP netops_inventory_facts_read_failures_total Registry exports whose NMS facts could not be read (the previous facts were kept).\n")
	fmt.Fprintf(w, "# TYPE netops_inventory_facts_read_failures_total counter\n")
	fmt.Fprintf(w, "netops_inventory_facts_read_failures_total %d\n", fails)
}

// refreshInventoryFacts is the registry export's facts step: bounded, logged
// on failure, never fatal to the export.
func (s *server) refreshInventoryFacts() {
	if s.invFacts == nil || s.nms == nil || s.nmsResolver == nil {
		return
	}
	var store nms.EnabledLister = s.nms.Store()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := s.invFacts.refresh(ctx, store, s.nmsResolver.Peek); err != nil {
		logWarn("tenant-enrichment", "NMS inventory facts unread: the registry keeps the previous model/site/role facts this cycle",
			map[string]any{"error": strings.TrimSpace(err.Error())})
	}
}

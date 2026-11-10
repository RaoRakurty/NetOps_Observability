// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package invfacts settles each inventory device's model, site and role for
// the registry from the inventory record, the operator and every NMS
// integration (tracker 387 PR 13a; nms/facts.go maps each vendor's words).
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
package invfacts

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"unicode"

	"netops/backend/internal/owner"
	"netops/backend/models"
	"netops/backend/nms"
)

// Fact names, sources and states — the closed label sets of
// netops_inventory_facts{fact,source,state}.
const (
	FactModel = "model"
	FactSite  = "site"
	FactRole  = "role"

	SourceManual    = "manual"
	SourceInventory = "inventory"
	SourceNMS       = "nms"
	SourceNone      = "none"

	StateSet      = "set"
	StateBlank    = "blank"
	StateConflict = "conflict"
)

// MaxCellRunes bounds one fact. It lands on every record of the device, so an
// inventory field somebody pasted a paragraph into must not ride along.
const MaxCellRunes = 128

// CleanCell makes one inventory value safe to stamp on telemetry: no control
// characters, no surrounding space, bounded. Inventory text is written by
// operators, importers and controllers, so it is treated as input (§3).
func CleanCell(v string) string {
	v = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, v)
	v = strings.TrimSpace(v)
	if r := []rune(v); len(r) > MaxCellRunes {
		v = strings.TrimSpace(string(r[:MaxCellRunes]))
	}
	return v
}

// Sole returns the one value a set agrees on, or "". A source that states
// nothing does not disagree; two different values is a conflict, and a
// conflict is left blank rather than settled by a guess.
func Sole(values map[string]bool) string {
	if len(values) != 1 {
		return ""
	}
	for v := range values {
		return v
	}
	return ""
}

// Key is one inventory device of one owner (owner.Of spelling).
type Key struct{ Owner, Device string }

// KeyFor is the Key of a device id under an owner spelling.
func KeyFor(ownerID, device string) Key { return Key{owner.Of(ownerID), device} }

// Votes are the values the NMS states for one device, per fact.
type Votes struct{ Models, Sites, Roles map[string]bool }

// NewVotes returns empty votes.
func NewVotes() *Votes {
	return &Votes{Models: map[string]bool{}, Sites: map[string]bool{}, Roles: map[string]bool{}}
}

// IntegrationDevices is one integration's controller device list.
type IntegrationDevices struct {
	Tenant string
	Devs   []nms.ControllerDevice
}

// ResolveFunc resolves a controller key to an inventory id of the tenant's
// OWN devices (nms.InventoryResolver.Peek).
type ResolveFunc func(tenant string, kind nms.KeyKind, key, name string) (string, bool)

// Collect votes every integration's facts onto the inventory devices their
// keys resolve to. Pure.
func Collect(ints []IntegrationDevices, resolve ResolveFunc) map[Key]*Votes {
	out := map[Key]*Votes{}
	if resolve == nil {
		return out
	}
	for _, ic := range ints {
		for _, d := range ic.Devs {
			id, ok := resolve(ic.Tenant, d.KeyKind, d.Key, d.Name)
			if !ok || id == "" {
				continue
			}
			f := nms.FactsOf(d)
			k := KeyFor(ic.Tenant, id)
			v := out[k]
			if v == nil {
				v = NewVotes()
				out[k] = v
			}
			for _, c := range []struct {
				into  map[string]bool
				value string
			}{{v.Models, f.Model}, {v.Sites, f.Site}, {v.Roles, f.Role}} {
				if s := CleanCell(c.value); s != "" {
					c.into[s] = true
				}
			}
		}
	}
	return out
}

// Outcome is one fact of one device: the value the registry stamps, and where
// it came from.
type Outcome struct{ Value, Source, State string }

// Facts is the three facts of one device.
type Facts struct{ Model, Site, Role Outcome }

// voteOutcome settles a fact from the NMS votes alone.
func voteOutcome(votes map[string]bool) Outcome {
	switch len(votes) {
	case 0:
		return Outcome{Source: SourceNone, State: StateBlank}
	case 1:
		return Outcome{Value: Sole(votes), Source: SourceNMS, State: StateSet}
	}
	return Outcome{Source: SourceNMS, State: StateConflict}
}

// Resolve applies the precedence above. manualSite is the operator's site for
// the device; votes may be nil.
func Resolve(d models.Device, manualSite string, votes *Votes) Facts {
	if votes == nil {
		votes = NewVotes()
	}
	var out Facts

	inv := CleanCell(d.Model)
	all := map[string]bool{}
	for m := range votes.Models {
		all[m] = true
	}
	if inv != "" {
		all[inv] = true
	}
	switch {
	case len(all) == 0:
		out.Model = Outcome{Source: SourceNone, State: StateBlank}
	case len(all) > 1:
		out.Model = Outcome{Source: SourceNMS, State: StateConflict}
	case len(votes.Models) > 0:
		out.Model = Outcome{Value: Sole(all), Source: SourceNMS, State: StateSet}
	default:
		out.Model = Outcome{Value: inv, Source: SourceInventory, State: StateSet}
	}

	if s := CleanCell(manualSite); s != "" {
		out.Site = Outcome{Value: s, Source: SourceManual, State: StateSet}
	} else {
		out.Site = voteOutcome(votes.Sites)
	}

	if r := CleanCell(d.Labels["role"]); r != "" {
		out.Role = Outcome{Value: r, Source: SourceManual, State: StateSet}
	} else if out.Role = voteOutcome(votes.Roles); out.Role.State == StateBlank {
		if t := CleanCell(d.Type); t != "" {
			out.Role = Outcome{Value: t, Source: SourceInventory, State: StateSet}
		}
	}
	return out
}

// StatKey is one netops_inventory_facts series.
type StatKey struct{ Fact, Source, State string }

// Count adds one device's three facts to stats.
func Count(stats map[StatKey]int, f Facts) {
	for _, fo := range []struct {
		name string
		o    Outcome
	}{{FactModel, f.Model}, {FactSite, f.Site}, {FactRole, f.Role}} {
		stats[StatKey{fo.name, fo.o.Source, fo.o.State}]++
	}
}

// Store holds the last good NMS votes and the last export's counts. Safe for
// concurrent use; every method is nil-safe.
type Store struct {
	mu        sync.Mutex
	votes     map[Key]*Votes
	stats     map[StatKey]int
	readFails uint64
}

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{votes: map[Key]*Votes{}, stats: map[StatKey]int{}}
}

// Current returns the last good votes.
func (f *Store) Current() map[Key]*Votes {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.votes
}

// Refresh reads every enabled integration's device list and replaces the
// votes. A failed read keeps the previous votes: losing every fact for a
// minute because one read failed would rewrite the registry twice.
func (f *Store) Refresh(ctx context.Context, store nms.EnabledLister, resolve ResolveFunc) error {
	if f == nil || store == nil || resolve == nil {
		return nil
	}
	ints, err := store.ListEnabled(ctx)
	if err != nil {
		f.failed()
		return fmt.Errorf("controller integrations unread: %w", err)
	}
	sort.Slice(ints, func(i, j int) bool { return nms.Key(ints[i].Tenant, ints[i].ID) < nms.Key(ints[j].Tenant, ints[j].ID) })
	per := make([]IntegrationDevices, 0, len(ints))
	for _, ic := range ints {
		// Tenant-scoped read (§3a): the integration's own owner's rows only.
		devs, err := store.Devices(ctx, ic.Tenant, false, ic.ID)
		if err != nil {
			f.failed()
			return fmt.Errorf("controller devices for %s unread: %w", ic.ID, err)
		}
		per = append(per, IntegrationDevices{Tenant: ic.Tenant, Devs: devs})
	}
	votes := Collect(per, resolve)
	f.mu.Lock()
	f.votes = votes
	f.mu.Unlock()
	return nil
}

func (f *Store) failed() {
	f.mu.Lock()
	f.readFails++
	f.mu.Unlock()
}

// SetStats replaces the last export's counts.
func (f *Store) SetStats(stats map[StatKey]int) {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.stats = stats
	f.mu.Unlock()
}

// StatKeys is the closed, zero-filled label set, in exposition order.
func StatKeys() []StatKey {
	var out []StatKey
	for _, fact := range []string{FactModel, FactSite, FactRole} {
		out = append(out,
			StatKey{fact, SourceManual, StateSet}, StatKey{fact, SourceInventory, StateSet},
			StatKey{fact, SourceNMS, StateSet}, StatKey{fact, SourceNMS, StateConflict},
			StatKey{fact, SourceNone, StateBlank},
		)
	}
	return out
}

// WriteMetrics renders netops_inventory_facts and the read-failure counter.
// No tenant or device label: the series are platform plumbing.
func (f *Store) WriteMetrics(w io.Writer) {
	if f == nil {
		return
	}
	f.mu.Lock()
	stats := make(map[StatKey]int, len(f.stats))
	for k, v := range f.stats {
		stats[k] = v
	}
	fails := f.readFails
	f.mu.Unlock()
	fmt.Fprintf(w, "# HELP netops_inventory_facts Inventory devices in the last registry export, by fact, the source that settled it, and state (set, blank, conflict).\n")
	fmt.Fprintf(w, "# TYPE netops_inventory_facts gauge\n")
	for _, k := range StatKeys() {
		fmt.Fprintf(w, "netops_inventory_facts{fact=%q,source=%q,state=%q} %d\n", k.Fact, k.Source, k.State, stats[k])
	}
	fmt.Fprintf(w, "# HELP netops_inventory_facts_read_failures_total Registry exports whose NMS facts could not be read (the previous facts were kept).\n")
	fmt.Fprintf(w, "# TYPE netops_inventory_facts_read_failures_total counter\n")
	fmt.Fprintf(w, "netops_inventory_facts_read_failures_total %d\n", fails)
}

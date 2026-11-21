// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package siteres is the ONE rule for "which site is this device at", used by
// every surface that groups devices by site (the Topology canvas, the Iris
// network-topology read that summarises the same view, and the discovered-site
// adoption).
//
// Precedence (owner decision 2026-10-18: a site set MANUALLY by an operator
// always wins; a site id read from the device or its controller never replaces
// it — it is a DISCOVERED value with provenance):
//
//  1. manual     — the operator's device→site binding (internal SoT, importer,
//     or an adopted discovered site).
//  2. label      — a discovery-stamped `site` / `location` inventory label.
//  3. discovered — a site id the network itself reports, in this order: the
//     device's own SD-WAN MIB answer ("device"), the controller's record for it
//     ("vmanage", "catalyst_center", …), then what its SD-WAN overlay peers
//     report about it ("sdwan_peers").
//
// A discovered site is a VIRTUAL grouping: nothing here writes a binding. Its
// key is (tenant, namespace, site id), so the same site id in two tenants is two
// sites (CLAUDE.md §3a), and a Catalyst SD-WAN site 50 never merges with a
// Meraki network that happens to be called 50. Pure: no IO, no clock.
package siteres

import (
	"sort"
	"strings"
)

// Source says where a resolved site came from.
type Source string

const (
	// SourceManual is the operator's device→site binding.
	SourceManual Source = "manual"
	// SourceLabel is a discovery-stamped `site` / `location` label.
	SourceLabel Source = "label"
	// SourceDiscovered is a site id the device, its controller or its SD-WAN
	// peers report — never written as a binding by this package.
	SourceDiscovered Source = "discovered"
)

// Origin values for a discovered site that are not a controller system name.
const (
	OriginDevice     = "device"      // the device's own SD-WAN MIB
	OriginSDWANPeers = "sdwan_peers" // what its overlay peers report about it
	originController = "controller"  // a controller record with no system name
	nsSDWAN          = "sdwan"       // the Catalyst SD-WAN site-id namespace
)

// maxField bounds every caller-influenced string this package echoes (§9).
const maxField = 120

// Input is everything the rule reads for ONE device. Every field is optional;
// an empty field is simply not evidence.
type Input struct {
	// Tenant is the device's OWNING tenant; it qualifies a discovered key.
	Tenant string
	// BindingSlug / BindingName: the operator's binding and that site's name.
	BindingSlug string
	BindingName string
	// Label is the discovery `site` (or `location`) label.
	Label string
	// DeviceSiteID is the device's own SD-WAN site id (validated SNMP answer).
	DeviceSiteID string
	// ControllerSiteID / ControllerSiteName / ControllerSystem: the controller
	// record's site id, its site name when the controller has one, and the
	// controller's system name ("vmanage", "catalyst_center", …).
	ControllerSiteID   string
	ControllerSiteName string
	ControllerSystem   string
	// PeerSiteID is the site id the device's SD-WAN peers agree on.
	PeerSiteID string
}

// Site is the resolved answer. A zero Key means "no site known".
type Site struct {
	// Key groups devices: two devices are at the same site iff their keys are
	// equal. A manual key is its slug, a label key its text, a discovered key
	// DiscoveredKey(tenant, namespace, id).
	Key string
	// Label is what a person reads: the site name for manual/label, and for a
	// discovered site its name plus provenance ("Site 50 · from vManage").
	Label string
	// Name (discovered only) is the label WITHOUT provenance — what an adopted
	// SoT site is called ("Site 50", or the controller's own site name).
	Name string
	// Source is manual | label | discovered.
	Source Source
	// Origin (discovered only): device | sdwan_peers | the controller system.
	Origin string
	// SiteID (discovered only): the reported site id.
	SiteID string
	// Reported is the site id the network reports for the device whatever won
	// (so a surface can say "device reports a different site"), with its origin.
	Reported       string
	ReportedOrigin string
	// Note is set when an operator-set site and the reported id disagree.
	Note string
}

// Discovered returns the site id the network reports for the device and where
// it was read: the device's own answer, then the controller's, then its peers'.
// ("", "") when nothing reports one.
func Discovered(in Input) (id, origin string) {
	if v := clean(in.DeviceSiteID); v != "" {
		return v, OriginDevice
	}
	if v := clean(in.ControllerSiteID); v != "" {
		sys := strings.ToLower(clean(in.ControllerSystem))
		if sys == "" {
			sys = originController
		}
		return v, sys
	}
	if v := clean(in.PeerSiteID); v != "" {
		return v, OriginSDWANPeers
	}
	return "", ""
}

// Namespace is the site-id space an origin's ids live in. The device's own
// SD-WAN MIB, its overlay peers and vManage all speak Catalyst SD-WAN site ids,
// so they share one namespace (a branch where one edge answers the MIB and the
// other is only known to vManage is still ONE site); every other controller is
// its own namespace.
func Namespace(origin string) string {
	switch origin {
	case OriginDevice, OriginSDWANPeers, "vmanage":
		return nsSDWAN
	}
	return origin
}

// OriginName is how an origin reads in a provenance label.
func OriginName(origin string) string {
	switch origin {
	case OriginDevice:
		return "device"
	case OriginSDWANPeers:
		return "SD-WAN peers"
	case "vmanage":
		return "vManage"
	case "catalyst_center":
		return "Catalyst Center"
	case "catalyst_9800":
		return "Catalyst 9800"
	case "meraki":
		return "Meraki"
	case "versa":
		return "Versa"
	case "", originController:
		return "controller"
	}
	return origin
}

// Resolve applies the precedence to one device.
func Resolve(in Input) Site {
	rep, repOrigin := Discovered(in)
	out := Site{Reported: rep, ReportedOrigin: repOrigin}
	if slug := clean(in.BindingSlug); slug != "" {
		out.Key, out.Source = slug, SourceManual
		out.Label = firstNonEmpty(clean(in.BindingName), slug)
		if disagrees(slug, in.BindingName, rep) {
			out.Note = "device reports site " + rep + " (from " + OriginName(repOrigin) + "); the site set by an operator is shown"
		}
		return out
	}
	if lbl := clean(in.Label); lbl != "" {
		out.Key, out.Label, out.Source = lbl, lbl, SourceLabel
		return out
	}
	if rep == "" {
		return out
	}
	out.Key = DiscoveredKey(in.Tenant, Namespace(repOrigin), rep)
	out.Source, out.Origin, out.SiteID = SourceDiscovered, repOrigin, rep
	// A controller's own site name names the site better than its number —
	// but only when that controller is the source of the id it names.
	name := ""
	if repOrigin != OriginDevice && repOrigin != OriginSDWANPeers {
		name = clean(in.ControllerSiteName)
	}
	out.Name = firstNonEmpty(name, "Site "+rep)
	out.Label = out.Name + " · from " + OriginName(repOrigin)
	return out
}

// DiscoveredKey is the tenant- and namespace-qualified key of a discovered site.
func DiscoveredKey(tenant, namespace, siteID string) string {
	return "discovered:" + strings.ToLower(clean(tenant)) + ":" + namespace + ":" + clean(siteID)
}

// labelRank orders the members of one discovered site for choosing the group's
// label: a controller that NAMES the site beats one that only numbers it, which
// beats the device's own answer, which beats its peers' inference.
func labelRank(s Site) int {
	switch {
	case s.Origin == OriginSDWANPeers:
		return 3
	case s.Origin == OriginDevice:
		return 2
	case s.Name != "Site "+s.SiteID:
		return 0
	}
	return 1
}

// Harmonize gives every member of one discovered site the same Name and Label —
// the best-ranked member's — so a group never reads differently depending on
// which device the renderer happened to look at first. Manual and label sites
// are left alone. The slice is updated in place.
func Harmonize(sites []Site) {
	best := map[string]Site{}
	for _, s := range sites {
		if s.Source != SourceDiscovered {
			continue
		}
		cur, ok := best[s.Key]
		if !ok || labelRank(s) < labelRank(cur) || (labelRank(s) == labelRank(cur) && s.Label < cur.Label) {
			best[s.Key] = s
		}
	}
	for i := range sites {
		if b, ok := best[sites[i].Key]; ok && sites[i].Source == SourceDiscovered {
			sites[i].Name, sites[i].Label, sites[i].Origin = b.Name, b.Label, b.Origin
		}
	}
}

// disagrees reports whether an operator-set site and the reported site id point
// at different places. It "agrees" when the slug or name carries the reported id
// as a whole token (a site the operator named "Branch 50" or slugged "site-50").
func disagrees(slug, name, reported string) bool {
	if reported == "" {
		return false
	}
	want := strings.ToLower(reported)
	for _, v := range []string{slug, name} {
		for _, tok := range strings.FieldsFunc(strings.ToLower(v), func(r rune) bool {
			return (r < 'a' || r > 'z') && (r < '0' || r > '9')
		}) {
			if tok == want {
				return false
			}
		}
	}
	return true
}

// ── adoption ────────────────────────────────────────────────────────────────

// Device is one device as the adoption planner sees it.
type Device struct {
	ID     string
	Name   string
	Tenant string
	Site   Site // Resolve's answer for it
}

// Adoption row actions.
const (
	ActionCreate = "create" // a new SoT site is created
	ActionReuse  = "reuse"  // a SoT site with this slug already exists; devices bind to it
	ActionBind   = "bind"   // the device is bound to the site
	ActionSkip   = "skip"   // the device is left alone (it has a site of record)
	// Outcomes only an APPLY can report (the plan pre-seeds them at 0 so a
	// preview and an apply carry the same summary keys).
	ActionRefused = "refused" // the slug belongs to a site the caller may not read
	ActionError   = "error"   // the write failed
)

// AdoptDevice is one device row of a plan.
type AdoptDevice struct {
	DeviceID string `json:"device_id"`
	Name     string `json:"name"`
	Action   string `json:"action"`
	Detail   string `json:"detail,omitempty"`
}

// AdoptSite is one discovered site of a plan.
type AdoptSite struct {
	Key     string        `json:"key"`
	SiteID  string        `json:"site_id"`
	Origin  string        `json:"origin"`
	Label   string        `json:"label"`
	Slug    string        `json:"slug"`
	Name    string        `json:"name"`
	Action  string        `json:"action"`
	Devices []AdoptDevice `json:"devices"`
}

// Plan is the whole adoption plan. Preview and apply build the SAME plan; apply
// then performs it.
type Plan struct {
	Sites   []AdoptSite    `json:"sites"`
	Summary map[string]int `json:"summary"`
}

// PlanAdoption groups the devices that report a site id into the discovered
// sites an operator could adopt. Only a site with at least one device whose
// EFFECTIVE site is that discovered site appears (so a second run after an
// apply is empty — idempotence). Inside it, a device placed manually or by a
// label is listed as skip and never bound: adoption never moves a device that
// already has a site of record.
//
// slugify derives a slug; existing reports whether the slug is already a SoT
// site in the adopting tenant. Devices must already be scoped to one tenant by
// the caller.
func PlanAdoption(devs []Device, slugify func(string) string, existing func(slug string) bool) Plan {
	type group struct {
		site    AdoptSite
		members []Device
		adopt   int
	}
	groups := map[string]*group{}
	for _, d := range devs {
		if d.Site.Reported == "" {
			continue
		}
		key := DiscoveredKey(d.Tenant, Namespace(d.Site.ReportedOrigin), d.Site.Reported)
		g := groups[key]
		if g == nil {
			g = &group{site: AdoptSite{Key: key, SiteID: d.Site.Reported}}
			groups[key] = g
		}
		g.members = append(g.members, d)
		if d.Site.Source == SourceDiscovered && d.Site.Key == key {
			g.adopt++
			// The group's name/label come from its discovered members (Harmonize
			// made them agree).
			g.site.Origin, g.site.Label, g.site.Name = d.Site.Origin, d.Site.Label, d.Site.Name
		}
	}
	keys := make([]string, 0, len(groups))
	for k, g := range groups {
		if g.adopt > 0 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	plan := Plan{Sites: []AdoptSite{}, Summary: map[string]int{ActionCreate: 0, ActionReuse: 0, ActionBind: 0, ActionSkip: 0, ActionRefused: 0, ActionError: 0}}
	taken := map[string]string{} // slug → key, within this plan
	for _, k := range keys {
		g := groups[k]
		slug := slugify(g.site.Name)
		if slug == "" {
			slug = slugify("site " + g.site.SiteID)
		}
		if other, dup := taken[slug]; dup && other != k {
			// Two discovered sites would land on one slug (a controller's site
			// name equal to another namespace's): qualify the later one.
			slug = slugify(slug + " " + Namespace(g.site.Origin))
		}
		taken[slug] = k
		g.site.Slug = slug
		g.site.Action = ActionCreate
		if existing(slug) {
			g.site.Action = ActionReuse
		}
		plan.Summary[g.site.Action]++
		sort.Slice(g.members, func(i, j int) bool { return g.members[i].ID < g.members[j].ID })
		for _, d := range g.members {
			row := AdoptDevice{DeviceID: d.ID, Name: d.Name, Action: ActionBind}
			switch d.Site.Source {
			case SourceManual:
				row.Action, row.Detail = ActionSkip, "already placed at "+d.Site.Label+" by an operator"
			case SourceLabel:
				row.Action, row.Detail = ActionSkip, "already placed at "+d.Site.Label+" by its site label"
			}
			plan.Summary[row.Action]++
			g.site.Devices = append(g.site.Devices, row)
		}
		plan.Sites = append(plan.Sites, g.site)
	}
	return plan
}

// clean trims and bounds a field to maxField runes (never splitting one).
func clean(v string) string {
	v = strings.TrimSpace(v)
	if r := []rune(v); len(r) > maxField {
		v = string(r[:maxField])
	}
	return v
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

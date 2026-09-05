// Package devmon is the ONE definition of "Correlix is monitoring this device".
//
// # Why it exists (owner decision C4, 2026-09-05)
//
// The Community tier covers 25 devices. The product question the owner
// resolved is WHICH 25: a device consumes one entitlement when Correlix is
// actively monitoring it through at least one enabled collector, and NOT
// merely because a row for it exists in the inventory. Subnet discovery that
// finds 500 devices creates 500 inventory records and consumes NOTHING; the
// operator enables monitoring on twelve of them and the usage is 12 of 25.
//
// Discovery is free by design: finding a device costs the platform nothing
// beyond the scan itself, and a free tier that charged for looking would make
// the honest thing (inventory everything, then decide) the expensive one. The
// ceiling sits where the ongoing cost is — telemetry ingestion, storage,
// correlation — which is exactly the set this package defines.
//
// # What it is NOT
//
// It is not a licensing package and it never imports one: it answers "is this
// device monitored", never "may it be". The licence gate (internal/entitlement)
// asks this package for the COUNT and applies the ceiling; keeping the two
// apart is what lets the isolation and collection paths use this definition
// without acquiring a dependency on entitlement state (see
// internal/entitlement/safety_invariant_test.go).
//
// # The definition
//
// A device is monitored when BOTH hold:
//
//  1. Correlix can reach it at all — it has an address. The collector pool
//     skips an addressless record (main.go's target builder), so counting one
//     would charge for a device nothing can ever poll.
//  2. Monitoring is ON for it: the operator's explicit decision when there is
//     one, and otherwise the default for how the device entered the inventory
//     (Default below).
//
// Several telemetry methods on one device (SNMP creds AND a gNMI subscription
// AND syslog) are still ONE monitored device: the unit is the device, and
// Methods exists to show that, never to count it.
package devmon

import (
	"sort"
	"strings"
	"time"

	"netops/backend/models"
)

// Record is one operator decision about whether Correlix collects from a
// device. It is the persisted form of the monitoring state; a device with NO
// record has never been decided and Default applies.
//
// The type lives in this leaf package so the device registry, its persistence
// and the HTTP surface all name the same thing.
type Record struct {
	// TenantID is the OWNING tenant, stamped from the device record (whose
	// tenant the create path stamped from the authenticated principal), never
	// from a request body (CLAUDE.md §3a rule 2).
	TenantID string `json:"tenant_id,omitempty"`
	// DeviceID is the device this decision belongs to.
	DeviceID string `json:"device_id"`
	// Enabled is the decision itself.
	Enabled bool `json:"enabled"`
	// UpdatedBy is the principal who made it; UpdatedAt is when.
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Source names of the discovery sources this package reasons about. They are
// the names the sources report (DiscoverySource.Name), duplicated here as
// CONSTANTS rather than imported so this package stays a leaf that
// internal/discovery may depend on.
const (
	// SourceSubnetScan is the platform's own SNMP subnet sweep. Its output is a
	// CANDIDATE list: an address answered a probe. Nobody asked for it to be
	// monitored, so it is not — that is the whole C4 decision.
	SourceSubnetScan = "snmp"
	// SourceNetbox is the external source of truth. A device in the SoT is one
	// the organisation has declared it operates, so it is monitored by default.
	SourceNetbox = "netbox"
	// SourceStatic is the operator-authored devices file.
	SourceStatic = "static"
	// SourceManual is a device created through the API/UI.
	SourceManual = "manual"
	// SourceWireless is a wireless controller or access point reported by the
	// wireless canonical inventory (wireless.DeviceSource). An operator
	// configured an integration and enabled it, and that integration is polling
	// the controller right now — so the entity is DECLARED, not a candidate,
	// and it counts (owner decision, tracker 256, 2026-09-05: a controller is
	// one device and each of its access points is one device).
	//
	// Only the entities an ENABLED integration polls are reported under this
	// source; the rest never reach the registry and are shown by the api's
	// read-time projection as not monitored (ReasonWirelessNotPolled).
	SourceWireless = "wireless"
)

// Reasons — the operator sentence attached to every decision. They are stated
// once, here, so the API, the UI and the logs cannot drift into three different
// explanations of the same fact.
const (
	ReasonNoAddress  = "no management address — nothing can collect from this device until it has one"
	ReasonDiscovered = "found by subnet discovery and not yet enabled for monitoring — " +
		"discovery is free and costs no licence allowance; enable monitoring to start collecting"
	ReasonDeclared = "monitoring is on: this device was declared in the inventory " +
		"(added by an operator, an operator-authored file, or the source of truth)"
	ReasonWireless          = "monitoring is on: this device is polled through its wireless controller integration"
	ReasonWirelessNotPolled = "monitoring is off: no enabled wireless integration is polling this device — " +
		"it stays in the inventory, nothing has been deleted or hidden, and it costs no licence allowance; " +
		"enable its controller integration to start collecting"
	ReasonEnabled  = "monitoring was enabled for this device by an operator"
	ReasonDisabled = "monitoring was turned off for this device by an operator — " +
		"the device, its history and its topology stay exactly where they are"
)

// Telemetry method tokens. DISPLAY ONLY — the licensed unit is the device.
const (
	// MethodSNMP is SNMP polling. Every device with an address is polled by the
	// SNMP collectors when monitoring is on: with the credential profile bound
	// to it, or with the deployment-wide community when none is bound
	// (collectors/poller.go Target.creds).
	MethodSNMP = "snmp"
	// MethodGNMI is a gNMI subscription, declared per device by the `gnmi`
	// label (main.go's target builder reads exactly that).
	MethodGNMI = "gnmi"
)

// HasAddress reports whether anything can collect from d at all. It mirrors the
// collector pool's own skip condition; if that condition ever changes, this is
// the line that must change with it.
func HasAddress(d models.Device) bool { return strings.TrimSpace(d.Address) != "" }

// Default reports whether a device with NO explicit operator decision is
// monitored, and why.
//
// The rule is provenance, and it is the only defensible one in this codebase:
// every path that puts a device in the inventory is either somebody DECLARING a
// device (a manual create, the operator's devices file, the source of truth) or
// the platform REPORTING that an address answered a probe (the subnet scan).
// The first is a request to monitor; the second is a candidate list.
//
// Defaulting a declared device to monitored is also what keeps an upgrade
// honest: every device an existing deployment declared keeps being collected
// from, so no monitoring is silently switched off by installing this build.
func Default(d models.Device) (bool, string) {
	if !HasAddress(d) {
		return false, ReasonNoAddress
	}
	switch {
	case strings.EqualFold(strings.TrimSpace(d.Source), SourceSubnetScan):
		return false, ReasonDiscovered
	case strings.EqualFold(strings.TrimSpace(d.Source), SourceWireless):
		// Declared, like any other, but say WHY in the operator's own terms:
		// "declared in the inventory" would send them looking for a device file
		// or a SoT entry that does not exist.
		return true, ReasonWireless
	}
	return true, ReasonDeclared
}

// Explicit reports the decision for a device that HAS an operator decision
// (enabled true/false), and why.
//
// An explicit "on" still requires an address: enabling monitoring on a device
// nothing can reach would consume an entitlement and collect nothing.
func Explicit(d models.Device, enabled bool) (bool, string) {
	if !enabled {
		return false, ReasonDisabled
	}
	if !HasAddress(d) {
		return false, ReasonNoAddress
	}
	return true, ReasonEnabled
}

// Methods lists the per-device telemetry configured for d, for display beside
// the monitoring state. Order is stable (sorted) so a UI does not reshuffle.
//
// It answers "what would we collect", not "how many entitlements": a device
// with SNMP and gNMI is one monitored device with two methods.
func Methods(d models.Device) []string {
	if !HasAddress(d) {
		return nil
	}
	set := map[string]bool{}
	proto := strings.ToLower(strings.TrimSpace(d.PreferredProtocol))
	// "" means SNMP — the poller's own default (byProtocol treats an unset
	// protocol as snmp), so an unlabelled device is an SNMP device.
	if proto == "" || proto == MethodSNMP {
		set[MethodSNMP] = true
	} else {
		set[proto] = true
	}
	if strings.EqualFold(strings.TrimSpace(d.Labels["gnmi"]), "true") {
		set[MethodGNMI] = true
	}
	out := make([]string, 0, len(set))
	for m := range set {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package devmon is the ONE definition of "Correlix is monitoring this device".
//
// # The rule (owner decision, 2026-10-03 — supersedes the C4 switch)
//
// There is no per-device monitoring switch. EVERY device in the inventory that
// has a management address is monitored — whoever put it there: an operator,
// the operator's devices file, the source of truth, a wireless controller
// integration, or a subnet scan. The licence still counts monitored devices
// (the C4 unit), so "monitored" now means "in the inventory and addressable",
// up to the licence ceiling.
//
// # Over the ceiling
//
// When there are more addressable devices than the licence covers, the FIRST N
// by first-seen time are collected from. The rest stay in the inventory, are
// NOT collected from, and are marked over the licence limit with a reason that
// says so — nothing is silently dropped. Because the order is first-seen and
// the ranking is recomputed on every read, deleting a monitored device or
// growing the licence starts collection on the next devices in line with no
// operator action.
//
// The ceiling is PLATFORM-WIDE (one installation, one allowance), so the
// ranking runs over every tenant's devices at once. What a tenant is SHOWN of
// it is scoped by the caller (the registry and the API filter by tenant); this
// package only decides.
//
// # What it is NOT
//
// It is not a licensing package and it never imports one: it is handed the
// ceiling as a number and answers "which devices are monitored", never "what
// does the licence say". Keeping entitlement out of this package is what lets
// the isolation and collection paths use this definition without acquiring a
// dependency on entitlement state (internal/entitlement/safety_invariant_test.go).
//
// Several telemetry methods on one device (SNMP creds AND a gNMI subscription)
// are still ONE monitored device: the unit is the device, and Methods exists to
// show that, never to count it.
package devmon

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"netops/backend/models"
)

// NoLimit is the ceiling value meaning "collect from every addressable
// device". Any negative limit is treated the same way. It mirrors the
// licence's own Unlimited without importing it.
const NoLimit = -1

// Source names this package mentions in its reasons. They are the names the
// discovery sources report (DiscoverySource.Name), duplicated as CONSTANTS
// rather than imported so this package stays a leaf.
const (
	// SourceSubnetScan is the platform's own SNMP subnet sweep. Every address it
	// finds is monitored like any other device — which is why a discovery scope
	// must be narrow: each device a scan finds consumes the licence.
	SourceSubnetScan = "snmp"
	// SourceNetbox is the external source of truth.
	SourceNetbox = "netbox"
	// SourceStatic is the operator-authored devices file.
	SourceStatic = "static"
	// SourceManual is a device created through the API/UI.
	SourceManual = "manual"
	// SourceWireless is a wireless controller or access point reported by an
	// ENABLED wireless integration (wireless.DeviceSource). Entities no enabled
	// integration polls never reach the registry; the api's read-time
	// projection shows them as StateNotPolled.
	SourceWireless = "wireless"
)

// Monitoring states — the machine token beside the operator sentence.
const (
	// StateMonitored: addressable and within the licence ceiling.
	StateMonitored = "monitored"
	// StateOverLimit: addressable, but found after the first N devices the
	// licence covers. In the inventory, not collected from.
	StateOverLimit = "over_limit"
	// StateNoAddress: nothing can collect from it until it has an address.
	StateNoAddress = "no_address"
	// StateNotPolled: a wireless entity whose integration is off (the api's
	// read-time projection; never produced by Assign).
	StateNotPolled = "not_polled"
)

// Reasons — the operator sentence attached to every state. Stated once, here,
// so the API, the UI and the logs cannot drift into different explanations.
const (
	ReasonNoAddress = "not monitored: this device has no management address, so nothing can collect from it until it has one"
	ReasonMonitored = "monitored: this device is in the inventory, has a management address and is within the licence"
	ReasonWireless  = "monitored: this device is polled through its wireless controller integration and is within the licence"
	// ReasonWirelessNotPolled is the api's read-time projection of a wireless
	// entity whose integration is disabled.
	ReasonWirelessNotPolled = "not monitored: no enabled wireless integration is polling this device — " +
		"it stays in the inventory, nothing has been deleted or hidden, and it does not use the licence; " +
		"enable its controller integration to start collecting"
)

// OverLimitReason is the sentence for a device past the licence ceiling. The
// limit is the installation's licence, not another tenant's data.
func OverLimitReason(limit int) string {
	return fmt.Sprintf("not monitored: licence limit of %d %s reached — this device was found after the first %d, "+
		"so it stays in the inventory but nothing is collected from it; it starts being monitored automatically "+
		"when a monitored device is deleted or the licence grows", limit, devicesWord(limit), limit)
}

func devicesWord(n int) string {
	if n == 1 {
		return "device"
	}
	return "devices"
}

// Telemetry method tokens. DISPLAY ONLY — the licensed unit is the device.
const (
	// MethodSNMP is SNMP polling: with the credential profile bound to the
	// device, or the deployment-wide community when none is bound.
	MethodSNMP = "snmp"
	// MethodGNMI is a gNMI subscription, declared per device by the `gnmi`
	// label (main.go's target builder reads exactly that).
	MethodGNMI = "gnmi"
)

// HasAddress reports whether anything can collect from d at all. It mirrors the
// collector pool's own skip condition; if that condition ever changes, this is
// the line that must change with it.
func HasAddress(d models.Device) bool { return strings.TrimSpace(d.Address) != "" }

// Candidate is one DEDUPLICATED device as the ranking sees it. FirstSeen is
// when the platform first saw any record of it (the earliest over every source
// that reports it); the caller guarantees it is set.
type Candidate struct {
	Device    models.Device
	FirstSeen time.Time
}

// Verdict is one device's monitoring state.
type Verdict struct {
	State     string
	Monitored bool
	Reason    string
	// Limit is the licence ceiling an over-limit device is past. Zero for
	// every other state.
	Limit int
}

// Assign decides the monitoring state of every candidate, keyed by device id.
//
// Addressless devices are never monitored and never take a slot. The
// addressable ones are ordered by first-seen time (ties broken by id, so two
// reads never disagree) and the first `limit` are monitored; the rest are over
// the limit. A negative limit means no ceiling.
func Assign(cands []Candidate, limit int) map[string]Verdict {
	out := make(map[string]Verdict, len(cands))
	ranked := make([]Candidate, 0, len(cands))
	for _, c := range cands {
		if !HasAddress(c.Device) {
			out[c.Device.ID] = Verdict{State: StateNoAddress, Reason: ReasonNoAddress}
			continue
		}
		ranked = append(ranked, c)
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if !ranked[i].FirstSeen.Equal(ranked[j].FirstSeen) {
			return ranked[i].FirstSeen.Before(ranked[j].FirstSeen)
		}
		return ranked[i].Device.ID < ranked[j].Device.ID
	})
	for i, c := range ranked {
		if limit >= 0 && i >= limit {
			out[c.Device.ID] = Verdict{State: StateOverLimit, Reason: OverLimitReason(limit), Limit: limit}
			continue
		}
		reason := ReasonMonitored
		if strings.EqualFold(strings.TrimSpace(c.Device.Source), SourceWireless) {
			reason = ReasonWireless
		}
		out[c.Device.ID] = Verdict{State: StateMonitored, Monitored: true, Reason: reason}
	}
	return out
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

// Collecting narrows methods to the ones a collector is actually running for
// on this installation. A monitored device whose methods are ALL off is
// counted by the licence but nothing is being collected from it — the status
// surface must say so instead of reporting "monitored" as if data flowed.
func Collecting(methods []string, enabled func(method string) bool) []string {
	if enabled == nil {
		return nil
	}
	out := make([]string, 0, len(methods))
	for _, m := range methods {
		if enabled(m) {
			out = append(out, m)
		}
	}
	return out
}

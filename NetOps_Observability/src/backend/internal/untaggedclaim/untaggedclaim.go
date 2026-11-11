// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package untaggedclaim is the ONE rule for which device identities a scope may
// use to claim an UNTAGGED telemetry row (tracker 370).
//
// The hybrid model ties a row that carries no tenant_id to a tenant when one of
// the row's device-identity fields (syslog host/hostname/source_ip, a flow's
// sampler/src/dst address, a finding's or tunnel's device column) names one of
// the tenant's devices. Neither a device name nor an address is unique across
// owners: two customers can both run `core-rtr-1`, RFC 1918 space overlaps, and a
// controller integration lists the very routers the platform also polls over
// SNMP. Matching on the caller's own identities alone therefore let a tenant read
// every untagged row that named a device ANOTHER owner also has — on the lab,
// RETAIL's vManage devices share names with the Provider's SNMP devices and
// RETAIL's log search returned the Provider's syslog.
//
// So an identity claims an untagged row only when it is UNAMBIGUOUS: held by the
// caller's devices and by no device of any other owner. An identity two owners
// hold claims nothing for the tenant — the row stays with the platform, which is
// whom the owner rule (internal/owner) gives every untagged row anyway.
//
// Rows a tenant's channel STAMPED with its tenant_id are not claims and are not
// decided here: every store keeps reading those by tenant_id.
//
// The package is pure (no registry, no principal): the caller hands it one
// registry snapshot and the visibility predicate it already applies to the
// device list, so the device-visibility rule stays in exactly one place.
package untaggedclaim

import (
	"net/netip"
	"strings"

	"netops/backend/models"
)

// Claim is the answer for one scope.
type Claim struct {
	// Keys are the caller's device ids and names, in their stored spelling (the
	// stores match them exactly), minus every ambiguous one.
	Keys []string
	// Addrs are the caller's device management addresses, minus every
	// ambiguous one.
	Addrs []string
	// Devices is how many devices the scope can see at all, ambiguous or not.
	// The ClickHouse clause builders keep their "no device → read nothing"
	// default-closed contract on it; a scope whose identities are all ambiguous
	// still reads its own STAMPED rows.
	Devices int
}

// Unambiguous computes the claim over one registry snapshot holding ALL owners'
// devices. owns reports whether a device is the caller's (the caller's device
// visibility rule); every other device belongs to some other owner and
// contributes its identities to the foreign index.
//
// platform marks the platform's own scope (the Provider). Untagged rows are the
// platform's by the owner rule, so for that scope the claim is ownership, not a
// claim, and nothing is dropped: dropping would hide the platform's own SNMP
// devices from it the moment a tenant's controller listed the same routers.
//
// A nil owns claims nothing (default-closed).
func Unambiguous(devices []models.Device, owns func(models.Device) bool, platform bool) Claim {
	if owns == nil {
		return Claim{}
	}
	foreign := map[string]bool{}
	if !platform {
		for _, d := range devices {
			if owns(d) {
				continue
			}
			for _, v := range []string{d.ID, d.Name, d.Address} {
				for _, f := range Forms(v) {
					foreign[f] = true
				}
			}
		}
	}
	ambiguous := func(v string) bool {
		forms := Forms(v)
		return len(forms) == 0 || foreign[forms[0]]
	}

	var c Claim
	seenKey, seenAddr := map[string]bool{}, map[string]bool{}
	for _, d := range devices {
		if !owns(d) {
			continue
		}
		c.Devices++
		for _, k := range []string{d.ID, d.Name} {
			if k != "" && !seenKey[k] && !ambiguous(k) {
				seenKey[k] = true
				c.Keys = append(c.Keys, k)
			}
		}
		if a := d.Address; a != "" && !seenAddr[a] && !ambiguous(a) {
			seenAddr[a] = true
			c.Addrs = append(c.Addrs, a)
		}
	}
	return c
}

// Forms returns the comparison forms of one identity value; the first is the
// value's own canonical form, and an empty value has none.
//
// Names and addresses share ONE namespace on purpose: a device with no sysName
// is named by its address, and a syslog `host` field carries either, so an
// address another owner holds must also make a same-spelled NAME ambiguous.
// Comparison is case-insensitive and an address is canonicalised (10.0.0.1 and
// ::ffff:10.0.0.1 are one sender), which errs towards "ambiguous".
//
// A dotted host name also contributes its first label: another owner's
// `core-rtr-1.lab.local` sends syslog as `core-rtr-1` often enough that a tenant
// device called `core-rtr-1` must not claim it. Only the foreign index uses that
// extra form; a caller's identity is looked up by its own canonical form.
func Forms(v string) []string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return nil
	}
	if ip, err := netip.ParseAddr(v); err == nil && ip.Zone() == "" {
		return []string{ip.Unmap().String()}
	}
	out := []string{v}
	if i := strings.IndexByte(v, '.'); i > 0 {
		out = append(out, v[:i])
	}
	return out
}

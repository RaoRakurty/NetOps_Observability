// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package srcauthority decides, per descriptive device fact, WHICH source
// Iris believes when several sources report the same device — and keeps the
// losers visible (tracker 337 N-F6, docs/architecture/iris-natural-language-
// platform.md §4.2.1).
//
// Owner decision 2026-11-09 (binding): the platform default is
// controller-observed > SNMP-discovered > manually entered, and each tenant's
// administrator may reorder it for their own tenant. Iris must cite the source
// that won and say when others disagreed — never a silent pick.
//
// The package is pure (no I/O) except for the Store implementations; the
// server injects the store and the device records.
package srcauthority

import (
	"errors"
	"fmt"
	"strings"
)

// Class is a closed authority class. A device record's source (and, for the
// version and serial, the field's own provenance) maps to exactly one.
type Class string

const (
	// ClassController — an NMS / controller integration reported it
	// (device source "api" or "wireless"; field source "api:<system>").
	ClassController Class = "controller"
	// ClassDiscovered — read off the device itself: the SNMP sweep, and the
	// snmp / gnmi / ssh field sources of the osprobe ladder.
	ClassDiscovered Class = "discovered"
	// ClassDeclared — an imported source of truth (NetBox).
	ClassDeclared Class = "declared"
	// ClassManual — an operator: the devices API, the inventory file, a
	// "manual" field source, or an EMPTY field source on a row that carries a
	// value (models.Device documents that as manual, never as probed).
	ClassManual Class = "manual"
	// ClassUnranked — a source this package does not know. It is shown, and it
	// never outranks a ranked class (default-closed).
	ClassUnranked Class = "unranked"
)

// Classes are the rankable classes in the PLATFORM DEFAULT order.
func Classes() []Class {
	return []Class{ClassController, ClassDiscovered, ClassDeclared, ClassManual}
}

// DefaultOrder is the platform default (owner 2026-11-09): controller >
// discovered > declared > manual. A fresh slice every call, so no caller can
// mutate the default for everyone.
func DefaultOrder() []Class { return Classes() }

// Label is the operator wording of a class (plain language, no jargon).
func Label(c Class) string {
	switch c {
	case ClassController:
		return "the controller"
	case ClassDiscovered:
		return "the device itself (SNMP)"
	case ClassDeclared:
		return "the imported source of truth (NetBox)"
	case ClassManual:
		return "a manual entry"
	}
	return "another source"
}

// ErrInvalidOrder is returned for an order that is not a permutation of
// Classes().
var ErrInvalidOrder = errors.New("the order must list each of controller, discovered, declared and manual exactly once")

// ValidateOrder accepts exactly a permutation of Classes(): every class once,
// nothing else (unranked is not orderable).
func ValidateOrder(order []Class) error {
	want := Classes()
	if len(order) != len(want) {
		return ErrInvalidOrder
	}
	seen := make(map[Class]bool, len(order))
	for _, c := range order {
		if !isRankable(c) || seen[c] {
			return ErrInvalidOrder
		}
		seen[c] = true
	}
	return nil
}

// ParseOrder converts wire strings to a validated order.
func ParseOrder(in []string) ([]Class, error) {
	out := make([]Class, 0, len(in))
	for _, s := range in {
		out = append(out, Class(strings.TrimSpace(s)))
	}
	if err := ValidateOrder(out); err != nil {
		return nil, err
	}
	return out, nil
}

// IsDefault reports whether order equals the platform default.
func IsDefault(order []Class) bool {
	d := DefaultOrder()
	if len(order) != len(d) {
		return false
	}
	for i := range d {
		if order[i] != d[i] {
			return false
		}
	}
	return true
}

func isRankable(c Class) bool {
	for _, k := range Classes() {
		if c == k {
			return true
		}
	}
	return false
}

// rank is the position of c in order; unranked (and anything not in the
// order) sorts after every ranked class.
func rank(order []Class, c Class) int {
	for i, k := range order {
		if k == c {
			return i
		}
	}
	return len(order)
}

// OrderText renders an order for an operator: "the controller > the device
// itself (SNMP) > …".
func OrderText(order []Class) string {
	parts := make([]string, 0, len(order))
	for _, c := range order {
		parts = append(parts, Label(c))
	}
	return strings.Join(parts, " > ")
}

// Device-record source names (models.Device.Source) this package classifies.
// They mirror the discovery sources' Name(): nms.ControllerSourceName ("api"),
// wireless.SourceName, the SNMP sweep, NetBox, the devices API ("manual") and
// the inventory file ("static"). They are spelled here, not imported, so the
// package stays a leaf; source_names_test pins them to the real constants.
const (
	SourceController = "api"
	SourceWireless   = "wireless"
	SourceSNMP       = "snmp"
	SourceNetBox     = "netbox"
	SourceManual     = "manual"
	SourceStatic     = "static"
)

// ClassOfRecord classifies a device record by the discovery source that
// produced it.
func ClassOfRecord(source string) Class {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case SourceController, SourceWireless:
		return ClassController
	case SourceSNMP:
		return ClassDiscovered
	case SourceNetBox:
		return ClassDeclared
	case SourceManual, SourceStatic:
		return ClassManual
	}
	return ClassUnranked
}

// ClassOfField classifies a field-level provenance (os_version_source,
// serial_source). An empty provenance on a row that carries the value is
// manual — the models.Device contract ("treated as manual, never as probed").
func ClassOfField(source string) Class {
	s := strings.ToLower(strings.TrimSpace(source))
	switch {
	case s == "", s == "manual":
		return ClassManual
	case strings.HasPrefix(s, "api:"):
		return ClassController
	case s == "snmp", s == "gnmi", s == "ssh":
		return ClassDiscovered
	}
	return ClassUnranked
}

// SourceText is the operator wording of one claim's source: the class label,
// plus the concrete system when the provenance names one ("the controller
// (vmanage)").
func SourceText(c Claim) string {
	src := strings.ToLower(strings.TrimSpace(c.Source))
	switch {
	case c.Class == ClassDiscovered:
		// The device itself, over the transport that read it.
		via := map[string]string{"snmp": "SNMP", "gnmi": "gNMI", "ssh": "SSH"}[src]
		if via == "" {
			via = "SNMP"
		}
		return "the device itself (" + via + ")"
	case strings.HasPrefix(src, "api:"):
		if sys := Clean(src[4:], 32); sys != "" {
			return fmt.Sprintf("%s (%s)", Label(c.Class), sys)
		}
	case c.Class == ClassUnranked:
		if sys := Clean(c.Source, 32); sys != "" {
			return fmt.Sprintf("%s (%s)", Label(c.Class), sys)
		}
	}
	return Label(c.Class)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package wan

import (
	"strings"
	"time"
	"unicode"
)

// marks.go — an operator's statement that one interface is, or is not, WAN.
// The classifier reads it first (Classify rule 1): "WAN" confirms the port,
// "not WAN" hides it, whatever the evidence says.

// MaxMarkInterfaceRunes bounds an interface name in a mark.
const MaxMarkInterfaceRunes = 128

// InterfaceMark is one operator mark. TenantID is the DEVICE's owner, stamped by
// the api from the inventory, never from a request body.
type InterfaceMark struct {
	TenantID  string    `json:"tenant_id,omitempty"`
	DeviceID  string    `json:"device_id"`
	Interface string    `json:"interface"`
	Mark      string    `json:"mark"` // MarkWAN | MarkNotWAN
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// MarkKey is a mark's id within its tenant: device id and interface.
func MarkKey(deviceID, iface string) string { return deviceID + "\x00" + iface }

// ValidMark reports whether m is one of the two marks.
func ValidMark(m string) bool { return m == MarkWAN || m == MarkNotWAN }

// CleanInterfaceName trims an interface name from a request and refuses an
// empty one, one with control characters, or one longer than the bound.
func CleanInterfaceName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len([]rune(s)) > MaxMarkInterfaceRunes {
		return "", false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return s, true
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package wan

import (
	"strings"
	"testing"
)

func TestMarkValidation(t *testing.T) {
	if !ValidMark(MarkWAN) || !ValidMark(MarkNotWAN) || ValidMark("") || ValidMark("WAN") || ValidMark("maybe") {
		t.Fatal("ValidMark is the closed pair")
	}
	for in, want := range map[string]string{
		"  GigabitEthernet1 ": "GigabitEthernet1", "ge-0/0/0.0": "ge-0/0/0.0", "1/1/1": "1/1/1",
	} {
		if got, ok := CleanInterfaceName(in); !ok || got != want {
			t.Errorf("CleanInterfaceName(%q) = %q,%v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "   ", "Eth\x00ernet1", "Eth\nernet1", strings.Repeat("x", MaxMarkInterfaceRunes+1)} {
		if _, ok := CleanInterfaceName(bad); ok {
			t.Errorf("CleanInterfaceName(%q) accepted", bad)
		}
	}
	if MarkKey("d1", "Gi1") == MarkKey("d1G", "i1") {
		t.Fatal("MarkKey must not collide across the device/interface boundary")
	}
}

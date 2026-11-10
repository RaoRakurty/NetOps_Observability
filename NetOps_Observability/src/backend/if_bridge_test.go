// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import "testing"

// if_bridge_test.go — the interface bridge's port comparison (tracker 387 PR
// 13a; the cycle is tested in internal/ifbridge).

func TestSamePortIsTheTopologyCanonicalKey(t *testing.T) {
	for _, c := range [][2]string{{"Gi3", "GigabitEthernet3"}, {"Te0/1/0", "TenGigabitEthernet0/1/0"}, {"ge0/3", "ge0/3"}} {
		if !samePort(c[0], c[1]) {
			t.Errorf("%q and %q are one port", c[0], c[1])
		}
	}
	for _, c := range [][2]string{{"Gi3", "Gi4"}, {"ge0/3", "ge0/4"}, {"Gi0/1", "Te0/1"}} {
		if samePort(c[0], c[1]) {
			t.Errorf("%q and %q are different ports", c[0], c[1])
		}
	}
}

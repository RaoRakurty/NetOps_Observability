// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package alerts

import "testing"

// The BGP summary names a VRF only when the peer has one (vmalert renders the
// conditional natively; the in-API engine must say the same sentence).
func TestRenderSummaryConditionalLabel(t *testing.T) {
	tmpl := "{{ $labels.device }} BGP peer {{ $labels.peer }}{{ if $labels.vrf }} in {{ $labels.vrf }}{{ end }} not established"
	if got := renderSummary(tmpl, map[string]string{"device": "pe1", "peer": "10.0.0.2", "vrf": "CUST-A"}, 3); got != "pe1 BGP peer 10.0.0.2 in CUST-A not established" {
		t.Errorf("vrf peer: %q", got)
	}
	if got := renderSummary(tmpl, map[string]string{"device": "pe1", "peer": "192.0.2.1"}, 1); got != "pe1 BGP peer 192.0.2.1 not established" {
		t.Errorf("global peer: %q", got)
	}
}

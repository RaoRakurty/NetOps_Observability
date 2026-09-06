// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"math"
	"strings"
	"testing"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestNormalizeJuniperDOM(t *testing.T) {
	// jnxDom: power 0.01 dBm, temp 1 C, bias 0.001 mA (µA).
	rx, tx, tmp, bias := normalizeJuniperDOM(-321, -150, 42, 7500)
	if !approx(rx, -3.21) || !approx(tx, -1.5) || !approx(tmp, 42) || !approx(bias, 7.5) {
		t.Fatalf("juniper conversion wrong: rx=%v tx=%v temp=%v bias=%v", rx, tx, tmp, bias)
	}
}

func TestNormalizeNokiaDOM(t *testing.T) {
	// Nokia: power 0.01 dBm, temp 0.1 C, bias 0.1 mA.
	rx, tx, tmp, bias := normalizeNokiaDOM(-321, -150, 415, 75)
	if !approx(rx, -3.21) || !approx(tx, -1.5) || !approx(tmp, 41.5) || !approx(bias, 7.5) {
		t.Fatalf("nokia conversion wrong: rx=%v tx=%v temp=%v bias=%v", rx, tx, tmp, bias)
	}
}

func TestBuildVendorDOMLines(t *testing.T) {
	// One port (ifIndex 7 → Ethernet1) with all four raw columns.
	rx := map[string]int64{"7": -321}
	tx := map[string]int64{"7": -150}
	temp := map[string]int64{"7": 42}
	bias := map[string]int64{"7": 7500}
	ifNames := map[string]string{"7": "Ethernet1"}
	lines := buildVendorDOMLines("mx1", "juniper", ifNames, rx, tx, temp, bias, normalizeJuniperDOM, 1700000000000)
	if len(lines) != 4 {
		t.Fatalf("expected 4 lines, got %d: %v", len(lines), lines)
	}
	j := strings.Join(lines, "\n")
	if !strings.Contains(j, `port_optics_rx_power_dbm{device="mx1",vendor="juniper",port="Ethernet1"} -3.21`) {
		t.Errorf("rx line wrong:\n%s", j)
	}
	if !strings.Contains(j, `port_optics_tx_bias_ma{device="mx1",vendor="juniper",port="Ethernet1"} 7.5`) {
		t.Errorf("bias line wrong:\n%s", j)
	}
	// Cardinality law: no serial/part labels.
	if strings.Contains(j, "serial") || strings.Contains(j, "part") {
		t.Errorf("vendor DOM must not carry identity labels:\n%s", j)
	}
}

func TestBuildVendorDOMLinesFallsBackToIndexName(t *testing.T) {
	rx := map[string]int64{"9": -400}
	lines := buildVendorDOMLines("d", "nokia", nil, rx, nil, nil, nil, normalizeNokiaDOM, 1)
	if len(lines) != 1 || !strings.Contains(lines[0], `port="9"`) {
		t.Fatalf("no ifNames should keep the raw index as port: %v", lines)
	}
}

func TestDomAdapterRegistry(t *testing.T) {
	if domAdapterFor("juniper") == nil || domAdapterFor("nokia") == nil {
		t.Fatal("juniper/nokia adapters must be registered")
	}
	if domAdapterFor("arista") != nil {
		t.Fatal("arista uses ENTITY-SENSOR (no adapter) → nil")
	}
}

func TestOpenconfigTransceiverMetric(t *testing.T) {
	cases := map[string]string{
		"/components/component/transceiver/physical-channels/channel/state/input-power/instant": "port_optics_rx_power_dbm",
		"output-power/instant":          "port_optics_tx_power_dbm",
		"laser-bias-current/instant":    "port_optics_tx_bias_ma",
		"transceiver/state/temperature": "port_optics_temperature_c",
		"supply-voltage":                "port_optics_supply_voltage_v",
		"pre-fec-ber":                   "port_prefec_ber",
		"osnr/instant":                  "port_coherent_osnr_db",
		"admin-state":                   "", // not an optics leaf
	}
	for leaf, want := range cases {
		if got := openconfigTransceiverMetric(leaf); got != want {
			t.Errorf("openconfigTransceiverMetric(%q)=%q want %q", leaf, got, want)
		}
	}
}

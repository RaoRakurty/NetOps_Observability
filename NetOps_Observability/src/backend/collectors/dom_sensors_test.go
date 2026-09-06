// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"math"
	"strings"
	"testing"
)

func TestScaleSensorValue(t *testing.T) {
	// RFC 3433: real = value × 10^scalePow × 10^-precision.
	// A −3.21 dBm reading commonly arrives as value=-321, scale=units(9),
	// precision=2 → -3.21.
	if got := scaleSensorValue(-321, 9, 2); math.Abs(got-(-3.21)) > 1e-9 {
		t.Fatalf("dBm scale wrong: %v", got)
	}
	// Temperature 41.5 C as value=415, scale=units, precision=1.
	if got := scaleSensorValue(415, 9, 1); math.Abs(got-41.5) > 1e-9 {
		t.Fatalf("temp scale wrong: %v", got)
	}
	// milli-scale (scale=8 → 10^-3) with precision 0: value 3300 → 3.3 (volts from mV).
	if got := scaleSensorValue(3300, 8, 0); math.Abs(got-3.3) > 1e-9 {
		t.Fatalf("milli scale wrong: %v", got)
	}
	// Absent scale (0) must not fabricate a power-of-ten.
	if got := scaleSensorValue(42, 0, 0); got != 42 {
		t.Fatalf("absent scale must pass through: %v", got)
	}
}

func TestDomMetricFor(t *testing.T) {
	cases := []struct {
		st   int64
		name string
		want string
	}{
		{sensorCelsius, "Ethernet1/1 Module Temperature", "port_optics_temperature_c"},
		{sensorVoltsDC, "Et1 Supply Voltage", "port_optics_supply_voltage_v"},
		{sensorAmperes, "Et1 Bias Current", "port_optics_tx_bias_ma"},
		{sensorDBm, "Ethernet1/1 Receive Power", "port_optics_rx_power_dbm"},
		{sensorDBm, "Ethernet1/1 Transmit Power", "port_optics_tx_power_dbm"},
		{sensorDBm, "Ethernet1/1 Optical Power", ""}, // ambiguous dBm → no guess
		{7, "some hertz sensor", ""},                 // non-optics type → skip
	}
	for _, c := range cases {
		if got := domMetricFor(c.st, c.name); got != c.want {
			t.Errorf("domMetricFor(%d,%q)=%q want %q", c.st, c.name, got, c.want)
		}
	}
}

func TestPortNameFromSensor(t *testing.T) {
	if got := portNameFromSensor("Ethernet1/1 Receive Power", "7"); got != "Ethernet1/1" {
		t.Fatalf("rx suffix strip wrong: %q", got)
	}
	if got := portNameFromSensor("Ethernet1/1 Transmit Power", "7"); got != "Ethernet1/1" {
		t.Fatalf("tx suffix strip wrong: %q", got)
	}
	if got := portNameFromSensor("", "9"); got != "idx-9" {
		t.Fatalf("empty name fallback wrong: %q", got)
	}
}

func TestBuildDOMLines(t *testing.T) {
	// Two sensors on one port: RX power (dBm) + temperature.
	sType := map[string]string{"7": "14", "8": "8"}
	sScale := map[string]string{"7": "9", "8": "9"}
	sPrec := map[string]string{"7": "2", "8": "1"}
	sValue := map[string]string{"7": "-321", "8": "415"}
	physName := map[string]string{"7": "Ethernet1/1 Receive Power", "8": "Ethernet1/1 Module Temperature"}

	lines := buildDOMLines("leaf1", "arista", sType, sScale, sPrec, sValue, physName, 1700000000000)
	if len(lines) != 2 {
		t.Fatalf("expected 2 DOM lines, got %d: %v", len(lines), lines)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, `port_optics_rx_power_dbm{device="leaf1",vendor="arista",port="Ethernet1/1"} -3.21`) {
		t.Errorf("rx power line wrong:\n%s", joined)
	}
	if !strings.Contains(joined, `port_optics_temperature_c{device="leaf1",vendor="arista",port="Ethernet1/1"} 41.5`) {
		t.Errorf("temperature line wrong:\n%s", joined)
	}
	// Cardinality law: no serial/part in the label set.
	if strings.Contains(joined, "serial") || strings.Contains(joined, "part") {
		t.Errorf("DOM series must not carry identity labels:\n%s", joined)
	}
}

func TestBuildDOMLinesSkipsAmbiguousAndNonOptics(t *testing.T) {
	sType := map[string]string{"1": "14", "2": "7"} // ambiguous dBm + hertz
	sScale := map[string]string{"1": "9", "2": "9"}
	sPrec := map[string]string{"1": "0", "2": "0"}
	sValue := map[string]string{"1": "-5", "2": "100"}
	physName := map[string]string{"1": "Et1 Optical Power", "2": "Et1 Frequency"}
	if lines := buildDOMLines("d", "v", sType, sScale, sPrec, sValue, physName, 1); len(lines) != 0 {
		t.Fatalf("ambiguous/non-optics sensors must not emit: %v", lines)
	}
}

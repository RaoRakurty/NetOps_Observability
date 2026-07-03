package collectors

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// dom_sensors.go — DOM/DDM optical diagnostics via ENTITY-SENSOR-MIB (RFC 3433),
// the universal SNMP fallback for Port Intelligence (#94, P3). Where a device
// exposes transceiver sensors as entPhySensor rows (temperature, supply
// voltage, TX bias, TX/RX optical power), this normalizes them — applying the
// per-sensor scale + precision so a raw integer becomes a real engineering unit
// — and emits them as VM series keyed by device + physical name ONLY.
//
// Cardinality law (owner): the series carry device + a stable port/sensor name,
// NEVER serial/part (those live in the relational transceiver inventory). The
// numeric readings are exactly the fast-changing values that belong in TSDB.
//
// gNMI/OpenConfig streaming (openconfig-platform/transceiver) and per-vendor DOM
// MIB adapters (Juniper jnxDomCurrentTable, Nokia TIMETRA-PORT DDM,
// Cisco/Arista enhanced DOM) are the richer sources and land as adapters that
// feed the SAME normalized emit path — this ENTITY-SENSOR walk is the baseline
// every ENTITY-SENSOR-capable platform answers.

var (
	entPhySensorTypeOID      = []int{1, 3, 6, 1, 2, 1, 99, 1, 1, 1, 1} // entPhySensorType
	entPhySensorScaleOID     = []int{1, 3, 6, 1, 2, 1, 99, 1, 1, 1, 2} // entPhySensorScale
	entPhySensorPrecisionOID = []int{1, 3, 6, 1, 2, 1, 99, 1, 1, 1, 3} // entPhySensorPrecision
	entPhySensorValueOID     = []int{1, 3, 6, 1, 2, 1, 99, 1, 1, 1, 4} // entPhySensorValue
	entPhysicalNameOID       = []int{1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1, 7} // entPhysicalName (for port naming)
)

// entPhySensorType enum (RFC 3433) — the subset relevant to optics DOM.
const (
	sensorVoltsDC = 4  // supply voltage
	sensorAmperes = 5  // TX bias current
	sensorCelsius = 8  // module temperature
	sensorDBm     = 14 // optical power (TX/RX)
)

// entPhySensorScale enum → power of ten. RFC 3433: yocto(1)…yotta(17), units(9)=10^0.
var sensorScalePow = map[int64]int{
	1: -24, 2: -21, 3: -18, 4: -15, 5: -12, 6: -9, 7: -6, 8: -3,
	9: 0, 10: 3, 11: 6, 12: 9, 13: 12, 14: 15, 15: 18, 16: 21, 17: 24,
}

// scaleSensorValue applies entPhySensorScale + entPhySensorPrecision to a raw
// entPhySensorValue (RFC 3433 §3): real = value × 10^scalePow × 10^(-precision).
// Pure + unit-tested — this is the arithmetic every DOM reading depends on.
func scaleSensorValue(raw, scale, precision int64) float64 {
	pow := sensorScalePow[scale]
	if scale == 0 {
		pow = 0 // absent/units → no scaling rather than a wrong 10^? guess
	}
	v := float64(raw) * math.Pow10(pow)
	if precision > 0 {
		v /= math.Pow10(int(precision))
	}
	return v
}

// domMetricFor maps an entPhySensorType to a normalized DOM metric name. dBm is
// ambiguous (TX vs RX) at the ENTITY-SENSOR layer — the caller disambiguates by
// the sensor's entPhysicalName ("...Transmit..."/"...Receive..."/"Tx"/"Rx").
func domMetricFor(sensorType int64, name string) string {
	switch sensorType {
	case sensorCelsius:
		return "port_optics_temperature_c"
	case sensorVoltsDC:
		return "port_optics_supply_voltage_v"
	case sensorAmperes:
		return "port_optics_tx_bias_ma"
	case sensorDBm:
		n := strings.ToLower(name)
		switch {
		case strings.Contains(n, "receive") || strings.Contains(n, "rx") || strings.Contains(n, "rcv"):
			return "port_optics_rx_power_dbm"
		case strings.Contains(n, "transmit") || strings.Contains(n, "tx") || strings.Contains(n, "xmit"):
			return "port_optics_tx_power_dbm"
		}
		return "" // an unlabeled dBm sensor is ambiguous — don't guess TX vs RX
	}
	return ""
}

// portNameFromSensor derives a stable, low-cardinality port label from the
// sensor's entPhysicalName, stripping the DOM-role suffix so "Ethernet1/1
// Receive Power" and "...Transmit Power" collapse to "Ethernet1/1". Falls back
// to the physical index when no name is available.
func portNameFromSensor(name, physIndex string) string {
	if name == "" {
		return "idx-" + physIndex
	}
	n := sanitizeLabel(name)
	// Trim trailing DOM-role words. MOST-SPECIFIC first — a longer suffix must
	// win over a substring of it ("Module Temperature" before "Temperature",
	// "Receive Optical Power" before "Receive Power").
	for _, suf := range []string{
		"Receive Optical Power", "Transmit Optical Power", "Receive Power", "Transmit Power",
		"Rx Power", "Tx Power", "Module Temperature", "Supply Voltage", "Bias Current",
		"Temperature", "Voltage", "Bias", "Rx", "Tx",
	} {
		if idx := strings.LastIndex(n, suf); idx > 0 {
			return strings.TrimSpace(strings.TrimRight(n[:idx], " -:"))
		}
	}
	return n
}

// buildDOMLines turns the four ENTITY-SENSOR columns + entPhysicalName into
// normalized VM series. Pure + unit-tested; the emit format matches the other
// collectors (name{labels} value ts). Only optics-relevant sensor types emit.
func buildDOMLines(device, vendor string, sType, sScale, sPrec, sValue, physName map[string]string, tsMillis int64) []string {
	var idxs []string
	for k := range sValue {
		idxs = append(idxs, k)
	}
	sort.Strings(idxs)

	var lines []string
	for _, idx := range idxs {
		st, _ := strconv.ParseInt(strings.TrimSpace(sType[idx]), 10, 64)
		name := physName[idx]
		metric := domMetricFor(st, name)
		if metric == "" {
			continue // not an optics sensor (or ambiguous dBm)
		}
		raw, err := strconv.ParseInt(strings.TrimSpace(sValue[idx]), 10, 64)
		if err != nil {
			continue
		}
		scale, _ := strconv.ParseInt(strings.TrimSpace(sScale[idx]), 10, 64)
		prec, _ := strconv.ParseInt(strings.TrimSpace(sPrec[idx]), 10, 64)
		val := scaleSensorValue(raw, scale, prec)
		port := portNameFromSensor(name, idx)
		lines = append(lines, fmt.Sprintf("%s{device=%q,vendor=%q,port=%q} %g %d",
			metric, device, vendor, port, val, tsMillis))
	}
	return lines
}

// collectDOMSensors walks ENTITY-SENSOR-MIB + entPhysicalName and returns the
// normalized DOM lines. Best-effort: a device without ENTITY-SENSOR yields no
// lines, so this is safe to call every poll alongside collectEntityInventory.
func collectDOMSensors(ctx context.Context, addr string, creds snmpCreds, device, vendor string, tsMillis int64) []string {
	walk := func(oid []int, asInt bool) map[string]string {
		out := map[string]string{}
		rows, err := snmpWalkColumn(ctx, addr, creds, oid)
		if err != nil {
			return out
		}
		for idx, v := range rows {
			if asInt {
				out[idx] = strconv.FormatInt(valueInt(v), 10)
			} else {
				out[idx] = string(v.raw)
			}
		}
		return out
	}
	return buildDOMLines(device, vendor,
		walk(entPhySensorTypeOID, true),
		walk(entPhySensorScaleOID, true),
		walk(entPhySensorPrecisionOID, true),
		walk(entPhySensorValueOID, true),
		walk(entPhysicalNameOID, false),
		tsMillis)
}

package collectors

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// dom_adapters.go — per-vendor DOM/DDM MIB adapters (#94 P3b(2)). Vendors that
// do NOT expose optics via the universal ENTITY-SENSOR-MIB (dom_sensors.go)
// publish DOM in vendor-private tables with vendor-specific raw units. Each
// adapter walks its table and feeds the SAME normalized emit path — the
// port_optics_* VM series — so downstream (scorer, UI, signatures) never sees a
// vendor difference.
//
// TESTABILITY NOTE: the live SNMP walk needs real hardware (the virtual lab has
// no optics), so the walks are not covered by CI. What IS covered — and what
// carries the risk — is the pure UNIT-CONVERSION math per vendor (raw table
// integer → dBm / °C / mA), isolated into normalize* functions with tests. OID
// tables are transcribed from published vendor MIBs; verify against a real
// device MIB dump before trusting a new adapter in production (known-gap policy).

// domReadingLine formats one normalized reading as a VM series (shared with the
// ENTITY-SENSOR path). Cardinality law: device + port labels only.
func domReadingLine(metric, device, vendor, port string, value float64, tsMillis int64) string {
	return fmt.Sprintf("%s{device=%q,vendor=%q,port=%q} %g %d", metric, device, vendor, port, value, tsMillis)
}

// domAdapter walks a vendor DOM table and returns normalized port_optics_* lines.
type domAdapter interface {
	vendor() string
	collect(ctx context.Context, addr string, creds snmpCreds, device string, ifNames map[string]string, tsMillis int64) []string
}

// domAdapterFor selects the vendor adapter (nil → fall back to the universal
// ENTITY-SENSOR collector). Registry is explicit, not reflection.
func domAdapterFor(vendor string) domAdapter {
	switch strings.ToLower(vendor) {
	case "juniper":
		return juniperDOM{}
	case "nokia":
		return nokiaDOM{}
	}
	return nil
}

// ---- Juniper (jnxDomCurrentTable, JUNIPER-DOM-MIB) ----------------------------
// Base 1.3.6.1.4.1.2636.3.60.1.1.1.1, indexed by ifIndex. Raw units (per the
// MIB): RX/TX optical power in units of 0.01 dBm (signed); module temperature
// in units of 1 °C; TX laser bias in units of 0.001 mA (µA). Verify against a
// live MX/PTX MIB dump before production trust.
var (
	jnxDomRxPowerOID = []int{1, 3, 6, 1, 4, 1, 2636, 3, 60, 1, 1, 1, 1, 6}  // jnxDomCurrentRxLaserPower (0.01 dBm)
	jnxDomTxPowerOID = []int{1, 3, 6, 1, 4, 1, 2636, 3, 60, 1, 1, 1, 1, 7}  // jnxDomCurrentTxLaserOutputPower (0.01 dBm)
	jnxDomTempOID    = []int{1, 3, 6, 1, 4, 1, 2636, 3, 60, 1, 1, 1, 1, 8}  // jnxDomCurrentModuleTemperature (1 C)
	jnxDomBiasOID    = []int{1, 3, 6, 1, 4, 1, 2636, 3, 60, 1, 1, 1, 1, 5}  // jnxDomCurrentTxLaserBiasCurrent (0.001 mA)
)

type juniperDOM struct{}

func (juniperDOM) vendor() string { return "juniper" }

// normalizeJuniperDOM converts the raw jnxDom integers to engineering units.
// Pure + tested — this is the conversion contract.
func normalizeJuniperDOM(rawRxPower, rawTxPower, rawTemp, rawBias int64) (rxDBm, txDBm, tempC, biasMA float64) {
	return float64(rawRxPower) / 100.0, float64(rawTxPower) / 100.0, float64(rawTemp), float64(rawBias) / 1000.0
}

func (a juniperDOM) collect(ctx context.Context, addr string, creds snmpCreds, device string, ifNames map[string]string, tsMillis int64) []string {
	walk := func(oid []int) map[string]int64 {
		out := map[string]int64{}
		if rows, err := snmpWalkColumn(ctx, addr, creds, oid); err == nil {
			for idx, v := range rows {
				out[idx] = valueInt(v)
			}
		}
		return out
	}
	rx, tx, temp, bias := walk(jnxDomRxPowerOID), walk(jnxDomTxPowerOID), walk(jnxDomTempOID), walk(jnxDomBiasOID)
	return buildVendorDOMLines(device, a.vendor(), ifNames, rx, tx, temp, bias, normalizeJuniperDOM, tsMillis)
}

// ---- Nokia SR (TIMETRA-PORT-MIB tmnxPortTransceiverDDM) -----------------------
// Base 1.3.6.1.4.1.6527.3.1.2.2.4.51, indexed by tmnxPortPortID. Raw units:
// power in units of 0.01 dBm; temperature in 0.1 °C; bias in 0.1 mA. Verify
// against a live 7750 MIB dump before production trust.
var (
	nokiaDDMRxPowerOID = []int{1, 3, 6, 1, 4, 1, 6527, 3, 1, 2, 2, 4, 51, 1, 11} // rx optical power (0.01 dBm)
	nokiaDDMTxPowerOID = []int{1, 3, 6, 1, 4, 1, 6527, 3, 1, 2, 2, 4, 51, 1, 12} // tx optical power (0.01 dBm)
	nokiaDDMTempOID    = []int{1, 3, 6, 1, 4, 1, 6527, 3, 1, 2, 2, 4, 51, 1, 5}  // temperature (0.1 C)
	nokiaDDMBiasOID    = []int{1, 3, 6, 1, 4, 1, 6527, 3, 1, 2, 2, 4, 51, 1, 9}  // tx bias (0.1 mA)
)

type nokiaDOM struct{}

func (nokiaDOM) vendor() string { return "nokia" }

// normalizeNokiaDOM: power 0.01 dBm, temp 0.1 C, bias 0.1 mA. Pure + tested.
func normalizeNokiaDOM(rawRxPower, rawTxPower, rawTemp, rawBias int64) (rxDBm, txDBm, tempC, biasMA float64) {
	return float64(rawRxPower) / 100.0, float64(rawTxPower) / 100.0, float64(rawTemp) / 10.0, float64(rawBias) / 10.0
}

func (a nokiaDOM) collect(ctx context.Context, addr string, creds snmpCreds, device string, ifNames map[string]string, tsMillis int64) []string {
	walk := func(oid []int) map[string]int64 {
		out := map[string]int64{}
		if rows, err := snmpWalkColumn(ctx, addr, creds, oid); err == nil {
			for idx, v := range rows {
				out[idx] = valueInt(v)
			}
		}
		return out
	}
	rx, tx, temp, bias := walk(nokiaDDMRxPowerOID), walk(nokiaDDMTxPowerOID), walk(nokiaDDMTempOID), walk(nokiaDDMBiasOID)
	return buildVendorDOMLines(device, a.vendor(), ifNames, rx, tx, temp, bias, normalizeNokiaDOM, tsMillis)
}

// buildVendorDOMLines is the shared normalize+emit for every vendor adapter:
// join the four raw columns by table index, run the vendor's unit conversion,
// resolve the index to a port name (ifNames when the table is ifIndex-keyed,
// else the raw index), and emit the normalized port_optics_* series. Pure +
// tested (the walk is the only untestable part).
func buildVendorDOMLines(device, vendor string, ifNames map[string]string,
	rawRx, rawTx, rawTemp, rawBias map[string]int64,
	normalize func(rx, tx, temp, bias int64) (float64, float64, float64, float64),
	tsMillis int64) []string {

	seen := map[string]bool{}
	var idxs []string
	for _, m := range []map[string]int64{rawRx, rawTx, rawTemp, rawBias} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				idxs = append(idxs, k)
			}
		}
	}
	sort.Strings(idxs)

	var lines []string
	for _, idx := range idxs {
		rxDBm, txDBm, tempC, biasMA := normalize(rawRx[idx], rawTx[idx], rawTemp[idx], rawBias[idx])
		port := idx
		if ifNames != nil {
			if n, ok := ifNames[idx]; ok && n != "" {
				port = n
			}
		}
		if _, ok := rawRx[idx]; ok {
			lines = append(lines, domReadingLine("port_optics_rx_power_dbm", device, vendor, port, rxDBm, tsMillis))
		}
		if _, ok := rawTx[idx]; ok {
			lines = append(lines, domReadingLine("port_optics_tx_power_dbm", device, vendor, port, txDBm, tsMillis))
		}
		if _, ok := rawTemp[idx]; ok {
			lines = append(lines, domReadingLine("port_optics_temperature_c", device, vendor, port, tempC, tsMillis))
		}
		if _, ok := rawBias[idx]; ok {
			lines = append(lines, domReadingLine("port_optics_tx_bias_ma", device, vendor, port, biasMA, tsMillis))
		}
	}
	return lines
}

// ---- gNMI / OpenConfig transceiver (openconfig-platform) ---------------------
// The owner's first-preference source. gnmic subscribes to
// /components/component/transceiver/physical-channels/channel/state and
// .../transceiver/state and writes the leaves to VM; this normalizer maps an
// OpenConfig transceiver leaf name to our port_optics_* metric so the rest of
// the pipeline is source-agnostic. OpenConfig already reports engineering units
// (dBm, °C, mA), so the value passes through unscaled. Pure + tested; the
// subscription itself is gnmic config (ops), not code.
func openconfigTransceiverMetric(leaf string) string {
	l := strings.ToLower(leaf)
	l = strings.TrimSuffix(l, "/instant")
	switch {
	case strings.HasSuffix(l, "input-power") || strings.Contains(l, "input-power"):
		return "port_optics_rx_power_dbm"
	case strings.HasSuffix(l, "output-power") || strings.Contains(l, "output-power"):
		return "port_optics_tx_power_dbm"
	case strings.Contains(l, "laser-bias-current"):
		return "port_optics_tx_bias_ma"
	case strings.Contains(l, "temperature"):
		return "port_optics_temperature_c"
	case strings.Contains(l, "supply-voltage") || strings.Contains(l, "input-voltage"):
		return "port_optics_supply_voltage_v"
	case strings.Contains(l, "osnr"):
		return "port_coherent_osnr_db"
	case strings.Contains(l, "pre-fec-ber"):
		return "port_prefec_ber"
	case strings.Contains(l, "post-fec-ber"):
		return "port_postfec_ber"
	}
	return ""
}

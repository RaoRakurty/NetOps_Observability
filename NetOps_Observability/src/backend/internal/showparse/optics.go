// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package showparse

// optics.go — transceiver digital-diagnostics (DDM) parsers
// (CmdInterfaceOptics). Optical Rx power is the single most useful physical-layer
// number in a fault investigation, and the single easiest to fabricate: the
// tables differ per platform AND per software train, and the columns are not
// self-labelling on the data rows. Every parser here therefore reads the
// COLUMN LABELS (or explicit key/value labels) and refuses a row whose shape
// does not match what the header actually promised.

import "strings"

func registerOpticsParsers(l *Library) {
	l.register(CmdInterfaceOptics, parseCiscoTransceiverTable,
		DialectCiscoIOS, DialectCiscoIOSXE)
	l.register(CmdInterfaceOptics, parseNXOSTransceiver, DialectCiscoNXOS)
	l.register(CmdInterfaceOptics, parseJunosOptics, DialectJunos)
	l.register(CmdInterfaceOptics, parseVRPTransceiver, DialectHuaweiVRP)
}

// opticsColumn is one recognized DDM column.
type opticsColumn string

const (
	colTemp    opticsColumn = "temperature"
	colVoltage opticsColumn = "voltage"
	colCurrent opticsColumn = "current"
	colTx      opticsColumn = "tx power"
	colRx      opticsColumn = "rx power"
)

// opticsPhrases is the closed set of column labels this parser understands, in
// no particular order — the ORDER is taken from the device's own header.
func opticsPhrases() []opticsColumn {
	return []opticsColumn{colTemp, colVoltage, colCurrent, colTx, colRx}
}

// parseCiscoTransceiverTable parses the IOS/IOS-XE combined transceiver table.
//
// It resolves the column ORDER from the header block (the up-to-three lines
// ending at the "Port …" line), then accepts a data row ONLY when its numeric
// field count equals the number of columns the header named. That is what makes
// the per-metric "detail" flavour — whose header names one metric but whose rows
// carry four threshold columns — SKIP instead of misreading a low-alarm
// threshold as an Rx power reading.
func parseCiscoTransceiverTable(lines []string) Result {
	var res Result
	cols, portLine, ok := ciscoOpticsHeader(lines)
	if !ok || len(cols) == 0 {
		return res
	}
	for i := portLine + 1; i < len(lines); i++ {
		ln := lines[i]
		if isSeparator(ln) || trim(ln) == "" {
			continue
		}
		fs := fields(ln)
		if len(fs) < 2 {
			continue
		}
		name := fs[0]
		var nums []float64
		clean := true
		for _, tok := range fs[1:] {
			if opticsAlarmMarker(tok) {
				continue
			}
			f, ok := atofOK(tok)
			if !ok {
				clean = false
				break
			}
			nums = append(nums, f)
		}
		if !clean || len(nums) != len(cols) {
			continue
		}
		st := InterfaceState{Name: name}
		for j, c := range cols {
			assignOpticsColumn(&st, c, nums[j])
		}
		res.Interfaces = append(res.Interfaces, st)
	}
	return res
}

// ciscoOpticsHeader finds the "Port …" header line and the ordered columns the
// header block names.
func ciscoOpticsHeader(lines []string) ([]opticsColumn, int, bool) {
	for i, ln := range lines {
		fs := fields(ln)
		if len(fs) == 0 || !strings.EqualFold(fs[0], "Port") {
			continue
		}
		start := i - 2
		if start < 0 {
			start = 0
		}
		header := strings.ToLower(strings.Join(lines[start:i+1], " "))
		type hit struct {
			idx int
			col opticsColumn
		}
		var hits []hit
		for _, p := range opticsPhrases() {
			if idx := strings.Index(header, string(p)); idx >= 0 {
				hits = append(hits, hit{idx: idx, col: p})
			}
		}
		// Insertion sort by header position: at most five elements, so this is
		// cheaper and more obviously total than sort.Slice.
		for a := 1; a < len(hits); a++ {
			for b := a; b > 0 && hits[b].idx < hits[b-1].idx; b-- {
				hits[b], hits[b-1] = hits[b-1], hits[b]
			}
		}
		cols := make([]opticsColumn, 0, len(hits))
		for _, h := range hits {
			cols = append(cols, h.col)
		}
		return cols, i, true
	}
	return nil, 0, false
}

// opticsAlarmMarker reports whether a token is one of the alarm/warning glyphs
// Cisco appends to a reading rather than a value of its own.
func opticsAlarmMarker(tok string) bool {
	switch tok {
	case "++", "+", "-", "--", "N/A", "NA":
		return true
	}
	return false
}

// assignOpticsColumn writes one recognized reading onto the interface row.
func assignOpticsColumn(st *InterfaceState, c opticsColumn, v float64) {
	switch c {
	case colTemp:
		st.TempC = f64Ptr(v)
	case colVoltage:
		st.VoltageV = f64Ptr(v)
	case colCurrent:
		st.BiasCurrentMa = f64Ptr(v)
	case colTx:
		st.TxPowerDbm = f64Ptr(v)
	case colRx:
		st.RxPowerDbm = f64Ptr(v)
	}
}

// parseNXOSTransceiver parses the NX-OS per-metric block, whose rows are
// "<label> <value> <unit> [thresholds…]". The UNIT token is the shape key: a
// reading is accepted only when the platform itself labelled it dBm / C / V / mA,
// so a threshold column can never be read as the measurement.
func parseNXOSTransceiver(lines []string) Result {
	var res Result
	st := InterfaceState{}
	for _, ln := range lines {
		t := trim(ln)
		if t == "" || isSeparator(t) {
			continue
		}
		if st.Name == "" && ln != "" && ln[0] != ' ' && len(fields(ln)) == 1 {
			st.Name = t
			continue
		}
		fs := fields(t)
		if len(fs) < 3 {
			continue
		}
		label := strings.ToLower(strings.Join(fs[:2], " "))
		switch {
		case strings.HasPrefix(label, "tx power"):
			if v, ok := nxosReading(fs, 2, "dbm"); ok && st.TxPowerDbm == nil {
				st.TxPowerDbm = f64Ptr(v)
			}
		case strings.HasPrefix(label, "rx power"):
			if v, ok := nxosReading(fs, 2, "dbm"); ok && st.RxPowerDbm == nil {
				st.RxPowerDbm = f64Ptr(v)
			}
		case strings.HasPrefix(strings.ToLower(fs[0]), "temperature"):
			if v, ok := nxosReading(fs, 1, "c"); ok && st.TempC == nil {
				st.TempC = f64Ptr(v)
			}
		case strings.HasPrefix(strings.ToLower(fs[0]), "voltage"):
			if v, ok := nxosReading(fs, 1, "v"); ok && st.VoltageV == nil {
				st.VoltageV = f64Ptr(v)
			}
		case strings.HasPrefix(strings.ToLower(fs[0]), "current"):
			if v, ok := nxosReading(fs, 1, "ma"); ok && st.BiasCurrentMa == nil {
				st.BiasCurrentMa = f64Ptr(v)
			}
		}
	}
	if st.Name == "" || (st.TxPowerDbm == nil && st.RxPowerDbm == nil && st.TempC == nil) {
		return res
	}
	res.Interfaces = append(res.Interfaces, st)
	return res
}

// nxosReading reads fs[at] as a float and requires fs[at+1] to be the expected
// unit. A missing or different unit yields ok=false.
func nxosReading(fs []string, at int, unit string) (float64, bool) {
	if at+1 >= len(fs) {
		return 0, false
	}
	if !strings.EqualFold(fs[at+1], unit) {
		return 0, false
	}
	return atofOK(fs[at])
}

// parseJunosOptics parses `show interfaces diagnostics optics <name>`, whose
// rows are "<long label> : <value> <unit>[ / <value> <unit>]". Junos prints
// optical power as "mW / dBm"; only the dBm half is taken, and only when the
// dBm unit is actually present.
func parseJunosOptics(lines []string) Result {
	var res Result
	st := InterfaceState{}
	for _, ln := range lines {
		t := trim(ln)
		if v, ok := strings.CutPrefix(t, "Physical interface: "); ok {
			st.Name = trim(strings.Split(v, ",")[0])
			continue
		}
		k, v, ok := kv(t)
		if !ok || v == "" {
			continue
		}
		switch strings.ToLower(k) {
		case "laser output power":
			if f, ok := junosDbm(v); ok && st.TxPowerDbm == nil {
				st.TxPowerDbm = f64Ptr(f)
			}
		case "receiver signal average optical power":
			if f, ok := junosDbm(v); ok && st.RxPowerDbm == nil {
				st.RxPowerDbm = f64Ptr(f)
			}
		case "laser bias current":
			if f, ok := junosUnit(v, "ma"); ok && st.BiasCurrentMa == nil {
				st.BiasCurrentMa = f64Ptr(f)
			}
		case "module temperature":
			if f, ok := junosDegreesC(v); ok && st.TempC == nil {
				st.TempC = f64Ptr(f)
			}
		}
	}
	if st.Name == "" || (st.TxPowerDbm == nil && st.RxPowerDbm == nil && st.TempC == nil) {
		return res
	}
	res.Interfaces = append(res.Interfaces, st)
	return res
}

// junosDbm extracts the dBm half of "0.6160 mW / -2.10 dBm".
func junosDbm(v string) (float64, bool) {
	for _, half := range strings.Split(v, "/") {
		if f, ok := junosUnit(half, "dbm"); ok {
			return f, true
		}
	}
	return 0, false
}

// junosUnit reads "<number> <unit>" and requires the unit to match.
func junosUnit(v, unit string) (float64, bool) {
	fs := fields(v)
	if len(fs) < 2 || !strings.EqualFold(fs[1], unit) {
		return 0, false
	}
	return atofOK(fs[0])
}

// junosDegreesC reads a "<n> degrees C [/ <n> degrees F]" reading from anywhere
// in the line, so it works both on a bare value and on a whole labelled line
// ("Temperature   34 degrees C / 93 degrees F"). The Celsius half is required:
// a Fahrenheit-only reading yields ok=false rather than an unconverted number.
func junosDegreesC(v string) (float64, bool) {
	for _, half := range strings.Split(v, "/") {
		fs := fields(half)
		for i := 1; i+1 < len(fs); i++ {
			if strings.EqualFold(fs[i], "degrees") && strings.EqualFold(fs[i+1], "C") {
				return atofOK(fs[i-1])
			}
		}
	}
	return 0, false
}

// parseVRPTransceiver parses `display transceiver interface <name> verbose`,
// whose diagnostic rows are "<label> (<unit>) :<value>" — the unit is inside the
// label, so it is matched there.
func parseVRPTransceiver(lines []string) Result {
	var res Result
	st := InterfaceState{}
	for _, ln := range lines {
		t := trim(ln)
		if name, ok := strings.CutSuffix(t, " transceiver information:"); ok {
			st.Name = trim(name)
			continue
		}
		k, v, ok := kv(t)
		if !ok || v == "" {
			continue
		}
		key := strings.ToLower(k)
		val, numeric := atofOK(strings.Fields(v + " x")[0])
		if !numeric {
			continue
		}
		switch {
		case strings.HasPrefix(key, "current tx power") && strings.Contains(key, "dbm"):
			if st.TxPowerDbm == nil {
				st.TxPowerDbm = f64Ptr(val)
			}
		case strings.HasPrefix(key, "current rx power") && strings.Contains(key, "dbm"):
			if st.RxPowerDbm == nil {
				st.RxPowerDbm = f64Ptr(val)
			}
		case strings.HasPrefix(key, "bias current") && strings.Contains(key, "ma"):
			if st.BiasCurrentMa == nil {
				st.BiasCurrentMa = f64Ptr(val)
			}
		case strings.HasPrefix(key, "temperature") && strings.Contains(key, "c"):
			if st.TempC == nil {
				st.TempC = f64Ptr(val)
			}
		case strings.HasPrefix(key, "voltage") && strings.Contains(key, "v"):
			if st.VoltageV == nil {
				st.VoltageV = f64Ptr(val)
			}
		}
	}
	if st.Name == "" || (st.TxPowerDbm == nil && st.RxPowerDbm == nil && st.TempC == nil) {
		return res
	}
	res.Interfaces = append(res.Interfaces, st)
	return res
}

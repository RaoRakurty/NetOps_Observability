// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
)

func c64Val(n uint64) berVal {
	raw := []byte{}
	for n > 0 {
		raw = append([]byte{byte(n & 0xff)}, raw...)
		n >>= 8
	}
	if len(raw) == 0 || raw[0]&0x80 != 0 {
		raw = append([]byte{0}, raw...)
	}
	return berVal{tag: 0x46, raw: raw}
}

// fakeGet answers scalar GETs from a map keyed by the dotted OID.
func fakeGet(vals map[string]berVal, calls *[]string) getFn {
	return func(_ context.Context, _ string, _ snmpCreds, oid []int) (berVal, error) {
		parts := make([]string, len(oid))
		for i, n := range oid {
			parts[i] = strconv.Itoa(n)
		}
		k := strings.Join(parts, ".")
		if calls != nil {
			*calls = append(*calls, k)
		}
		if v, ok := vals[k]; ok {
			return v, nil
		}
		return berVal{}, errors.New("noSuchObject")
	}
}

func TestSDWANNumberReadsByType(t *testing.T) {
	for _, c := range []struct {
		v    berVal
		want float64
		ok   bool
	}{
		{strVal("2.03"), 2.03, true},
		{strVal(" 97.5 "), 97.5, true},
		{strVal("12%"), 12, true},
		{intVal(42), 42, true},
		{c64Val(8_000_000_000), 8_000_000_000, true},
		{strVal("abc"), 0, false},
		{strVal(""), 0, false},
		{strVal("-1"), 0, false},
		{strVal("NaN"), 0, false},
		{strVal("Inf"), 0, false},
		{ipVal(1, 2, 3, 4), 0, false}, // an IpAddress is not a number
	} {
		got, ok := sdwanNumber(c.v)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("sdwanNumber(%q tag %#x) = %v,%v want %v,%v", c.v.raw, c.v.tag, got, ok, c.want, c.ok)
		}
	}
}

func TestSDWANPercentsRejectNonsense(t *testing.T) {
	if p, ok := sdwanCPUPercent(strVal("97.5")); !ok || p != 2.5 {
		t.Errorf("cpu from idle 97.5 = %v,%v want 2.5", p, ok)
	}
	if _, ok := sdwanCPUPercent(strVal("101")); ok {
		t.Error("idle above 100 must be dropped")
	}
	if p, ok := sdwanMemPercent(strVal("1024"), strVal("4096")); !ok || p != 25 {
		t.Errorf("mem = %v,%v want 25", p, ok)
	}
	if _, ok := sdwanMemPercent(strVal("1"), strVal("0")); ok {
		t.Error("zero total must be dropped, never 0 % or 100 %")
	}
	if _, ok := sdwanMemPercent(strVal("5"), strVal("4")); ok {
		t.Error("used > total must be dropped")
	}
}

// A vEdge answers text in VIPTELA-OPER-SYSTEM; the series carry the source.
func TestReadSDWANSystemVEdge(t *testing.T) {
	vals := map[string]berVal{
		"1.3.6.1.4.1.41916.11.1.16.0": strVal("88.00"),
		"1.3.6.1.4.1.41916.11.1.17.0": strVal("3920216"),
		"1.3.6.1.4.1.41916.11.1.18.0": strVal("1960108"),
	}
	s := readSDWANSystem(context.Background(), fakeGet(vals, nil), "x", v2c("c"), "viptela", true, true)
	if !s.hasCPU || s.cpu != 12 || !s.hasMem || s.mem != 50 {
		t.Fatalf("%+v", s)
	}
	lines := s.lines("vedge-51", "cisco", 1)
	want := []string{
		`device_cpu_percent{device="vedge-51",vendor="cisco",index="system",source="sdwan-system"} 12.00 1`,
		`device_mem_percent{device="vedge-51",vendor="cisco",index="system",source="sdwan-system"} 50.00 1`,
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lines:\n%s", strings.Join(lines, "\n"))
	}
}

// A cEdge answers memory as Counter64 at the same column numbers.
func TestReadSDWANSystemCEdgeCounter64Memory(t *testing.T) {
	vals := map[string]berVal{
		"1.3.6.1.4.1.9.9.1004.1.1.17.0": c64Val(8_000_000_000),
		"1.3.6.1.4.1.9.9.1004.1.1.18.0": c64Val(2_000_000_000),
	}
	var calls []string
	s := readSDWANSystem(context.Background(), fakeGet(vals, &calls), "x", v2c("c"), "cisco-sdwan", false, true)
	if s.hasCPU || !s.hasMem || s.mem != 25 {
		t.Fatalf("%+v", s)
	}
	for _, c := range calls {
		if strings.HasSuffix(c, ".16.0") {
			t.Error("CPU was not wanted, yet it was asked for")
		}
	}
}

// Nothing answers → nothing is published (no guessed zeros).
func TestReadSDWANSystemSilentDevicePublishesNothing(t *testing.T) {
	s := readSDWANSystem(context.Background(), fakeGet(nil, nil), "x", v2c("c"), "viptela", true, true)
	if s.hasCPU || s.hasMem || len(s.lines("d", "v", 1)) != 0 {
		t.Fatalf("%+v", s)
	}
	if fam := sdwanSystemFamily(2636); fam != "" {
		t.Errorf("juniper must not be read as SD-WAN, got %q", fam)
	}
}

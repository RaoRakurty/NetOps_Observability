// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package alerts

import (
	"strings"
	"testing"
)

// Owner, 2026-11-23: "Don't add random IDs to the hostname … keep them internal,
// don't show them." The device id (`<sysName>-<address hash>`) is the alert's
// machine key; the SUMMARY an operator reads names the device by its hostname.

func fireOnce(t *testing.T, names func() map[string]string, labels map[string]string) (summary, deviceID, labelDevice string) {
	t.Helper()
	e, _ := newTestEngine(t, func(Rule) ([]Sample, error) {
		return []Sample{{Labels: labels, Value: 91}}, nil
	})
	e.DeviceNames = names
	e.AddRule(Rule{Name: "HighCPU", Expr: "x > 90", Severity: "warning",
		Annotations: map[string]string{"summary": "{{ $labels.device }} CPU {{ $value }}%"}})
	e.evaluateAll()
	a := e.Active()
	if len(a) != 1 {
		t.Fatalf("want 1 active alert, got %d", len(a))
	}
	return a[0].Summary, a[0].DeviceID, a[0].Labels["device"]
}

func TestSummaryNamesTheDeviceByItsHostnameNotItsInternalID(t *testing.T) {
	names := func() map[string]string { return map[string]string{"cedge-40-fdf7b64f": "cEDGE-40"} }
	sum, dev, lbl := fireOnce(t, names, map[string]string{"device": "cedge-40-fdf7b64f"})
	if sum != "cEDGE-40 CPU 91%" {
		t.Fatalf("summary = %q, want the hostname", sum)
	}
	if strings.Contains(sum, "fdf7b64f") {
		t.Fatalf("the internal id leaked into the summary: %q", sum)
	}
	// Machine fields keep the id: dedup, tenant derivation and links depend on it.
	if dev != "cedge-40-fdf7b64f" || lbl != "cedge-40-fdf7b64f" {
		t.Fatalf("DeviceID/labels must keep the id, got %q / %q", dev, lbl)
	}
}

func TestSummaryFallsBackToTheIDWhenNoNameIsKnown(t *testing.T) {
	for name, names := range map[string]func() map[string]string{
		"no resolver":  nil,
		"unknown id":   func() map[string]string { return map[string]string{"other-1": "other"} },
		"empty name":   func() map[string]string { return map[string]string{"leaf1-aa": " "} },
		"nil snapshot": func() map[string]string { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			sum, _, _ := fireOnce(t, names, map[string]string{"device": "leaf1-aa"})
			if sum != "leaf1-aa CPU 91%" {
				t.Fatalf("summary = %q, want the id unchanged", sum)
			}
		})
	}
}

func TestDisplayLabelsNeverMutatesTheSampleLabels(t *testing.T) {
	in := map[string]string{"device": "pe1-0a0b", "peer": "10.0.0.2"}
	out := displayLabels(in, map[string]string{"pe1-0a0b": "pe1"})
	if out["device"] != "pe1" || out["peer"] != "10.0.0.2" {
		t.Fatalf("display labels = %v", out)
	}
	if in["device"] != "pe1-0a0b" {
		t.Fatalf("the sample's labels were modified: %v", in)
	}
}

func TestDeviceNamesIsReadOncePerTick(t *testing.T) {
	calls := 0
	e, _ := newTestEngine(t, func(Rule) ([]Sample, error) {
		return []Sample{{Labels: map[string]string{"device": "a-1"}}, {Labels: map[string]string{"device": "b-2"}}}, nil
	})
	e.DeviceNames = func() map[string]string { calls++; return map[string]string{"a-1": "a", "b-2": "b"} }
	for _, n := range []string{"R1", "R2", "R3"} {
		e.AddRule(Rule{Name: n, Expr: "x", Annotations: map[string]string{"summary": "{{ $labels.device }} down"}})
	}
	e.evaluateAll()
	if calls != 1 {
		t.Fatalf("DeviceNames called %d times in one tick, want 1", calls)
	}
}

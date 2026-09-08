// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package configstore

import (
	"fmt"
	"strings"
	"testing"
)

func TestDiffCountsAndRedacts(t *testing.T) {
	from := "hostname edge-01\nsnmp-server community " + canaryCommunity + " RO\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n"
	to := "hostname edge-01\nsnmp-server community " + canaryCommunity + "-NEW RO\ninterface Gi0/0\n ip address 10.0.0.2 255.255.255.0\n shutdown\n"

	res := Diff(VendorCisco, from, to)
	if res.Added != 3 || res.Removed != 2 {
		t.Fatalf("added/removed = %d/%d, want 3/2\n%s", res.Added, res.Removed, res.Unified)
	}
	if strings.Contains(res.Unified, canaryCommunity) {
		t.Fatalf("SECRET LEAK: community survived into the diff:\n%s", res.Unified)
	}
	if !strings.Contains(res.Unified, "-"+" ip address 10.0.0.1") ||
		!strings.Contains(res.Unified, "+"+" ip address 10.0.0.2") {
		t.Fatalf("diff did not render the real change:\n%s", res.Unified)
	}
	if res.Truncated {
		t.Error("a small diff must not report truncation")
	}
}

func TestDiffIdenticalIsEmpty(t *testing.T) {
	cfg := "hostname a\ninterface Gi0/0\n"
	res := Diff(VendorCisco, cfg, cfg)
	if res.Added != 0 || res.Removed != 0 {
		t.Fatalf("identical configs produced a diff: %+v", res)
	}
	if strings.TrimSpace(res.Unified) != "" {
		t.Fatalf("identical configs produced hunks:\n%s", res.Unified)
	}
}

func TestDiffFromEmptyCountsEveryLine(t *testing.T) {
	to := "a\nb\nc\n"
	res := Diff(VendorCisco, "", to)
	if res.Added != 3 || res.Removed != 0 {
		t.Fatalf("first capture diff = +%d/-%d, want +3/-0", res.Added, res.Removed)
	}
}

// TestDiffIsBounded is the §9 contract: two very large, very different configs
// must produce a BOUNDED result quickly and say so, never an unbounded
// allocation and never a silently wrong diff.
func TestDiffIsBounded(t *testing.T) {
	var a, b strings.Builder
	for i := 0; i < MaxDiffLines+5000; i++ {
		fmt.Fprintf(&a, "interface Gi0/%d\n description A-%d\n", i, i)
		fmt.Fprintf(&b, "interface Te0/%d\n description B-%d\n", i, i)
	}
	res := Diff(VendorCisco, a.String(), b.String())
	if !res.Truncated {
		t.Fatal("an oversized, fully-different diff must report truncation")
	}
	lines := strings.Count(res.Unified, "\n")
	if lines > MaxDiffOutput+2 {
		t.Fatalf("unified output = %d lines, cap is %d", lines, MaxDiffOutput)
	}
}

// TestDiffDegradesHonestlyBeyondEditDistance: past the Myers D cap the result is
// a whole-block replace MARKED truncated — never a plausible-looking wrong diff.
func TestDiffDegradesHonestlyBeyondEditDistance(t *testing.T) {
	var a, b strings.Builder
	for i := 0; i < maxEditDistance*2; i++ {
		fmt.Fprintf(&a, "line-a-%d\n", i)
		fmt.Fprintf(&b, "line-b-%d\n", i)
	}
	res := Diff(VendorCisco, a.String(), b.String())
	if !res.Truncated {
		t.Fatal("beyond the edit-distance cap the diff must be marked truncated")
	}
	if res.Added == 0 || res.Removed == 0 {
		t.Fatalf("block replace must count both sides: +%d/-%d", res.Added, res.Removed)
	}
}

func TestDiffContextWindow(t *testing.T) {
	var a strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&a, "line %d\n", i)
	}
	b := strings.Replace(a.String(), "line 100\n", "line 100 changed\n", 1)
	res := Diff(VendorCisco, a.String(), b)
	if res.Added != 1 || res.Removed != 1 {
		t.Fatalf("+%d/-%d, want +1/-1", res.Added, res.Removed)
	}
	// Only the change plus its context should be rendered, not all 200 lines.
	if n := strings.Count(res.Unified, "\n"); n > 2*diffContext+4 {
		t.Fatalf("context window not applied: %d rendered lines\n%s", n, res.Unified)
	}
}

// ── the diff endpoint must mask exactly what the version endpoint masks ──────
//
// Two endpoints read the same stored configuration. If they disagree about what
// is secret, the leaky one is the whole redactor's real behaviour. These tests
// pin the agreement rather than a list of patterns, so a new masking rule cannot
// be added to one reader and forgotten in the other.

// Fabricated key material. None of this is a key: the bodies are typed-out
// marker strings. They are long, and they contain letters that are not hex
// digits, so nothing but the PEM block state machine can mask them.
const (
	fakeKeyBodyOld = "NOTAREALPRIVATEKEYoldXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	fakeKeyBodyNew = "NOTAREALPRIVATEKEYnewYYYYYYYYYYYYYYYYYYYYYYYYYYYY"
	fakeCertBody   = "NOTAREALCERTIFICATEbodyZZZZZZZZZZZZZZZZZZZZZZZZZZ"
)

// fakePEM renders an obviously fabricated PEM block: the BEGIN marker, `shared`
// body lines that are identical in both configs, one body line that differs,
// then the END marker. The shared run is what pushes the BEGIN marker outside
// the diff's context window.
func fakePEM(kind, changed string, shared int) []string {
	out := []string{"-----BEGIN " + kind + "-----"}
	for i := 0; i < shared; i++ {
		out = append(out, fmt.Sprintf("NOTAREALKEYBODYshared%02d", i))
	}
	return append(out, changed, "-----END "+kind+"-----")
}

// redactionMap maps each raw line of a configuration to what the VERSION
// endpoint renders for it. A line that appears twice with different verdicts
// keeps the masked verdict, so the check errs toward calling a leak a leak.
func redactionMap(v Vendor, text string) map[string]string {
	raw := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	red := strings.Split(strings.TrimSuffix(Redact(v, text), "\n"), "\n")
	out := map[string]string{}
	for i := range raw {
		if i >= len(red) {
			break
		}
		if prev, seen := out[raw[i]]; seen && prev != raw[i] {
			continue // already recorded as masked
		}
		out[raw[i]] = red[i]
	}
	return out
}

// assertDiffAgreesWithVersion checks every line the unified diff prints against
// the redacted rendering of the side it came from.
func assertDiffAgreesWithVersion(t *testing.T, v Vendor, from, to string) DiffResult {
	t.Helper()
	fromMap, toMap := redactionMap(v, from), redactionMap(v, to)
	res := Diff(v, from, to)
	for _, ln := range strings.Split(res.Unified, "\n") {
		if ln == "" || strings.HasPrefix(ln, "@@") {
			continue
		}
		payload := ln[1:]
		sides := []map[string]string{fromMap, toMap}
		switch ln[:1] {
		case "-":
			sides = []map[string]string{fromMap}
		case "+":
			sides = []map[string]string{toMap}
		}
		for _, m := range sides {
			if masked, ok := m[payload]; ok && masked != payload {
				t.Errorf("SECRET LEAK: the diff printed %q; the version endpoint renders that line as %q",
					payload, masked)
			}
		}
	}
	return res
}

// TestDiffMasksPEMBodyTheVersionEndpointMasks: a device rotates its private key.
// The changed body line is deep inside the block, so the "-----BEGIN-----" line
// is outside the context window and never printed. A redactor that only reads
// the lines it is about to print has no way to know it is inside a key, which is
// exactly how both bodies used to reach the caller verbatim.
func TestDiffMasksPEMBodyTheVersionEndpointMasks(t *testing.T) {
	head := []string{"hostname edge-01", "ip domain-name lab.example"}
	tail := []string{"interface Gi0/0", " ip address 10.0.0.1 255.255.255.0"}

	from := append(append([]string{}, head...), fakePEM("RSA PRIVATE KEY", fakeKeyBodyOld, 8)...)
	from = append(from, tail...)
	to := append(append([]string{}, head...), fakePEM("RSA PRIVATE KEY", fakeKeyBodyNew, 8)...)
	to = append(to, tail...)

	fromCfg := strings.Join(from, "\n") + "\n"
	toCfg := strings.Join(to, "\n") + "\n"

	res := assertDiffAgreesWithVersion(t, VendorCisco, fromCfg, toCfg)
	// The removed side and the added side both carry key material.
	if strings.Contains(res.Unified, fakeKeyBodyOld) {
		t.Errorf("SECRET LEAK: the old key body survived on the removed side:\n%s", res.Unified)
	}
	if strings.Contains(res.Unified, fakeKeyBodyNew) {
		t.Errorf("SECRET LEAK: the new key body survived on the added side:\n%s", res.Unified)
	}
	if strings.Contains(res.Unified, "NOTAREALKEYBODYshared") {
		t.Errorf("SECRET LEAK: an unchanged key body line was printed as context:\n%s", res.Unified)
	}
	if res.Added != 1 || res.Removed != 1 {
		t.Fatalf("+%d/-%d, want +1/-1 (only the body line changed)", res.Added, res.Removed)
	}
}

// TestDiffMasksKeyPresentOnOneSideOnly: a certificate is installed, so the whole
// PEM block exists only in the new configuration. Its BEGIN marker IS printed
// here, which is the easier case, but the block still has to be masked.
func TestDiffMasksKeyPresentOnOneSideOnly(t *testing.T) {
	head := []string{"hostname edge-01", "ip domain-name lab.example"}
	fromCfg := strings.Join(append(append([]string{}, head...), "interface Gi0/0"), "\n") + "\n"

	to := append([]string{}, head...)
	to = append(to, fakePEM("CERTIFICATE", fakeCertBody, 3)...)
	to = append(to, "interface Gi0/0")
	toCfg := strings.Join(to, "\n") + "\n"

	res := assertDiffAgreesWithVersion(t, VendorCisco, fromCfg, toCfg)
	if strings.Contains(res.Unified, fakeCertBody) || strings.Contains(res.Unified, "NOTAREALKEYBODYshared") {
		t.Errorf("SECRET LEAK: a one-sided certificate body was printed:\n%s", res.Unified)
	}
	// The change itself must still be visible: an operator has to see that a
	// certificate appeared, just not what it contains.
	if !strings.Contains(res.Unified, "+-----BEGIN CERTIFICATE-----") {
		t.Errorf("the diff hid the fact that a certificate was installed:\n%s", res.Unified)
	}
}

// TestDiffMasksInlineHexCertificateLines: Cisco prints a certificate chain as
// bare hex. The version endpoint masks those lines; the diff must too, on both
// the added and the removed side.
func TestDiffMasksInlineHexCertificateLines(t *testing.T) {
	const (
		hexOld = "  30820229308201 92A0030201020202 0130 0D06092A864886F70D01010505003031"
		hexNew = "  30820229308201 92A0030201020202 0130 0D06092A864886F70D01010505003099"
	)
	fromCfg := "crypto pki certificate chain TP\n certificate self-signed 01\n" + hexOld + "\n  quit\n"
	toCfg := "crypto pki certificate chain TP\n certificate self-signed 01\n" + hexNew + "\n  quit\n"

	res := assertDiffAgreesWithVersion(t, VendorCisco, fromCfg, toCfg)
	if strings.Contains(res.Unified, "0D06092A864886F70D0101050500") {
		t.Errorf("SECRET LEAK: an inline hex certificate body was printed:\n%s", res.Unified)
	}
}

// TestDiffBlockReplaceMasksBothSides: past the edit-distance cap the differ
// dumps both configurations whole. That degraded path carries the most key
// material of any, so it gets its own guard.
func TestDiffBlockReplaceMasksBothSides(t *testing.T) {
	build := func(tag, body string) string {
		lines := []string{}
		for i := 0; i < maxEditDistance; i++ {
			lines = append(lines, fmt.Sprintf("interface Gi0/%d", i), fmt.Sprintf(" description %s-%d", tag, i))
		}
		lines = append(lines, fakePEM("RSA PRIVATE KEY", body, 4)...)
		return strings.Join(lines, "\n") + "\n"
	}
	fromCfg, toCfg := build("A", fakeKeyBodyOld), build("B", fakeKeyBodyNew)

	res := assertDiffAgreesWithVersion(t, VendorCisco, fromCfg, toCfg)
	if !res.Truncated {
		t.Fatal("this pair is meant to exercise the degraded block-replace path")
	}
	for _, leak := range []string{fakeKeyBodyOld, fakeKeyBodyNew, "NOTAREALKEYBODYshared"} {
		if strings.Contains(res.Unified, leak) {
			t.Errorf("SECRET LEAK: block replace printed key material (%q)", leak)
		}
	}
}

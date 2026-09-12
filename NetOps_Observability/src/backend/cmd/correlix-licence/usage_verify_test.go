// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package main

// usage_verify_test.go — the offline usage-report check, end to end through the
// command exactly as a customer runs it.
//
// The point of the command is that a customer needs NOTHING from us to check a
// report: not our servers, not our keys, not this repository. So the test
// builds a report the way the api does, writes it to a file, and runs the
// command over it.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/metering"
)

func writeReport(t *testing.T, dir string, mutate func(*metering.Report)) (string, ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("no public half")
	}

	at := time.Date(2026, 9, 5, 1, 0, 0, 0, time.UTC)
	row := metering.DailyRecord{Day: "2026-09-05", TenantID: "acme"}
	row, err := metering.Fold(row, []metering.Reading{
		metering.Unique(metering.MeterMonitoredDevicesUnique, "acme", []string{"d1", "d2", "d3"}),
		metering.Measured(metering.MeterMonitoredDevicesPeak, "acme", 3),
	}, at)
	if err != nil {
		t.Fatalf("fold: %v", err)
	}
	rows := []metering.DailyRecord{row.Seal()}
	rep := metering.Report{
		Scope: metering.ReportScopeTenant, Tenant: "acme",
		GeneratedAt: at, From: "2026-09-05", To: "2026-09-05",
		Licence: metering.ReportLicence{Tier: "team", Devices: 250},
		Meters:  metering.ReportMeters(), Days: rows,
		Totals: metering.Totals{From: "2026-09-05", To: "2026-09-05", Days: 1, Meters: metering.RollUp(rows)},
		Notes:  metering.StandingNotes(),
	}
	if mutate != nil {
		mutate(&rep)
	}
	signed, err := metering.SignReport(rep, priv, at)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	body, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(dir, "usage.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path, pub
}

// capture runs the command with stdout redirected to a temp file and returns
// what it printed. The command writes to an *os.File, so a pipe is the honest
// way to read it rather than changing the signature for a test.
func capture(t *testing.T, args ...string) (string, error) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "out-*.txt")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	defer func() { _ = f.Close() }() // best-effort: the temp file is read back below and dropped with the dir
	runErr := run(args, f)
	raw, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	return string(raw), runErr
}

func TestUsageVerifyAcceptsAGoodReportAndRederivesItsTotals(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeReport(t, dir, nil)

	out, err := capture(t, "usage-verify", path)
	if err != nil {
		t.Fatalf("usage-verify refused a good report: %v\n%s", err, out)
	}
	for _, want := range []string{
		"VERIFIED",
		"2026-09-05 .. 2026-09-05",
		"tenant acme",
		metering.MeterMonitoredDevicesUnique,
		"match the ones re-derived above",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not mention %q:\n%s", want, out)
		}
	}
}

func TestUsageVerifyRefusesATamperedReport(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeReport(t, dir, nil)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	tampered := strings.Replace(string(raw), `"value": 3`, `"value": 300`, 1)
	if tampered == string(raw) {
		t.Fatalf("the tamper did not change the file — the test proves nothing")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := capture(t, "usage-verify", path); err == nil {
		t.Fatalf("usage-verify accepted a report whose numbers were edited")
	}
}

func TestUsageVerifyChecksTheArithmeticSeparatelyFromTheSignature(t *testing.T) {
	dir := t.TempDir()
	// A report SIGNED correctly whose stated totals do not follow from its own
	// daily rows. The signature is fine; the summary is a lie, and the command
	// must say so rather than stopping at "VERIFIED".
	wrong := 999.0
	path, _ := writeReport(t, dir, func(r *metering.Report) {
		r.Totals.Meters = []metering.MeterValue{{
			Meter: metering.MeterMonitoredDevicesUnique, Value: &wrong,
			Unit: metering.UnitDevices, Source: metering.SourceConfiguration,
		}}
	})
	out, err := capture(t, "usage-verify", path)
	if err == nil {
		t.Fatalf("a report whose totals contradict its rows was accepted:\n%s", out)
	}
	if !strings.Contains(out, "do NOT follow from its own daily rows") {
		t.Errorf("the disagreement was not explained:\n%s", out)
	}
}

func TestUsageVerifyAgainstAnOutOfBandKey(t *testing.T) {
	dir := t.TempDir()
	path, pub := writeReport(t, dir, nil)

	good := base64.StdEncoding.EncodeToString(pub)
	if _, err := capture(t, "usage-verify", "--pubkey", good, path); err != nil {
		t.Fatalf("verification against the report's real key failed: %v", err)
	}
	otherSeed := make([]byte, ed25519.SeedSize)
	otherSeed[0] = 42
	otherPub, ok := ed25519.NewKeyFromSeed(otherSeed).Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("no public half")
	}
	if _, err := capture(t, "usage-verify", "--pubkey", base64.StdEncoding.EncodeToString(otherPub), path); err == nil {
		t.Fatalf("verification against the WRONG installation's key succeeded")
	}
}

func TestUsageVerifyNeedsExactlyOneFile(t *testing.T) {
	if _, err := capture(t, "usage-verify"); err == nil {
		t.Errorf("usage-verify accepted no file")
	}
	if _, err := capture(t, "usage-verify", "a.json", "b.json"); err == nil {
		t.Errorf("usage-verify accepted two files")
	}
}

func TestUsageVerifyIsInTheUsageText(t *testing.T) {
	out, err := capture(t, "help")
	if err != nil {
		t.Fatalf("help: %v", err)
	}
	if !strings.Contains(out, "usage-verify") {
		t.Errorf("the command is not documented in the usage text:\n%s", out)
	}
}

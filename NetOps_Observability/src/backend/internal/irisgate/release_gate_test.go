// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisgate

import (
	"os"
	"testing"
)

// TestIrisReleaseGates is the CI step (.github/workflows/backend-ci.yml, job
// iris-gates). It reads the reports the scorers wrote to
// $IRIS_GATE_REPORT_DIR and judges every gate.
//
//	IRIS_RELEASE_GATES=enforce  a failing or missing gate fails (release tags)
//	IRIS_RELEASE_GATES=report   the table is written, nothing fails (PRs)
//	unset                       skipped (an ordinary `go test ./...`)
//
// The verdict table goes to $GITHUB_STEP_SUMMARY when set.
func TestIrisReleaseGates(t *testing.T) {
	mode := os.Getenv("IRIS_RELEASE_GATES")
	if mode == "" {
		t.Skip("IRIS_RELEASE_GATES not set — run by the iris-gates CI job")
	}
	if mode != "enforce" && mode != "report" {
		t.Fatalf("IRIS_RELEASE_GATES=%q: want enforce or report", mode)
	}
	dir := os.Getenv(EnvReportDir)
	if dir == "" {
		t.Fatal(EnvReportDir + " must name the directory the scorers wrote to")
	}
	rs, err := Evaluate(dir)
	if err != nil {
		t.Fatal(err)
	}
	md := Markdown(rs, mode)
	t.Log("\n" + md)
	if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600) // #nosec G304 -- the runner's own summary file
		if err != nil {
			t.Fatal(err)
		}
		_, werr := f.WriteString(md + "\n")
		cerr := f.Close()
		if werr != nil || cerr != nil {
			t.Fatalf("step summary: %v %v", werr, cerr)
		}
	}
	if mode == "enforce" {
		for _, r := range rs {
			switch {
			case r.Missing:
				t.Errorf("gate %s was not measured — a scorer did not run or did not report", r.Bar.Gate)
			case !r.Pass:
				t.Errorf("gate %s failed: %s", r.Bar.Gate, r.Bar.What)
			}
		}
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// captures_test.go — the Captures model: the five parsers, the shape bounds,
// the vendor-default derivation and the collection status the panel renders.
//
// The policy refusal itself is proven at the HTTP boundary
// (tac_captures_isolation_test.go in the root package), because that is where a
// refused line must be reported BY LINE NUMBER — the mapping from the
// validator's index back onto the file's own line is the part that can be wrong.

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"strings"
	"testing"
)

func TestCaptureFormatOf(t *testing.T) {
	for _, tc := range []struct {
		name string
		want CaptureFormat
		ok   bool
	}{
		{"runbook.txt", FormatTXT, true},
		{"RUNBOOK.TXT", FormatTXT, true},
		{"/home/noc/my commands.list", FormatTXT, true},
		{"set.csv", FormatCSV, true},
		{"set.json", FormatJSON, true},
		{"set.yaml", FormatYAML, true},
		{"set.yml", FormatYAML, true},
		{"set.docx", FormatDOCX, true},
		{"set.doc", "", false},
		{"set.xlsx", "", false},
		{"set.sh", "", false},
		{"noextension", "", false},
		{"", "", false},
	} {
		got, ok := CaptureFormatOf(tc.name)
		if ok != tc.ok || got != tc.want {
			t.Errorf("CaptureFormatOf(%q) = %q,%v; want %q,%v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

func TestParseCaptureTXT(t *testing.T) {
	src := "# ACME EOS baseline\n\nshow version\r\n   show ip bgp summary   \n\n# a comment\nshow interfaces status\n"
	got, err := ParseCapture("acme baseline.txt", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Name != "acme baseline" {
		t.Errorf("name = %q, want the file's own basename", got.Name)
	}
	want := []string{"show version", "show ip bgp summary", "show interfaces status"}
	assertCommands(t, got.Commands, want)
	// The line numbers are the FILE's, so an operator can find a refusal in the
	// file they still have open.
	if got.Commands[0].Line != 3 || got.Commands[2].Line != 7 {
		t.Errorf("line numbers = %d,%d; want 3,7 (the file's own lines)", got.Commands[0].Line, got.Commands[2].Line)
	}
}

func TestParseCaptureCSV(t *testing.T) {
	src := "command,note\nshow version,the baseline\n\"show ip bgp neighbors 10.0.0.1\",the peer that flapped\n# skipped\nshow logging,\n"
	got, err := ParseCapture("set.csv", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	assertCommands(t, got.Commands, []string{
		"show version", "show ip bgp neighbors 10.0.0.1", "show logging",
	})
	if got.Commands[0].Note != "the baseline" {
		t.Errorf("note = %q, want the second column", got.Commands[0].Note)
	}
	if got.Commands[2].Note != "" {
		t.Errorf("an empty note column must stay empty, got %q", got.Commands[2].Note)
	}
}

func TestParseCaptureJSON(t *testing.T) {
	src := `{"name":"ACME BGP","commands":["show version",{"command":"show ip bgp summary","note":"the peers"}]}`
	got, err := ParseCapture("set.json", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Name != "ACME BGP" {
		t.Errorf("name = %q, want the file's own name field", got.Name)
	}
	assertCommands(t, got.Commands, []string{"show version", "show ip bgp summary"})
	if got.Commands[1].Note != "the peers" {
		t.Errorf("note = %q", got.Commands[1].Note)
	}
	// A field nobody documented is a refusal, not a silent drop.
	if _, err := ParseCapture("set.json", []byte(`{"name":"x","cmds":["show version"]}`)); err == nil {
		t.Error("an unknown json field was accepted")
	}
}

func TestParseCaptureYAML(t *testing.T) {
	src := "name: ACME OSPF\ncommands:\n  - show version\n  - command: show ip ospf neighbor\n    note: the adjacency\n"
	got, err := ParseCapture("set.yaml", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Name != "ACME OSPF" {
		t.Errorf("name = %q", got.Name)
	}
	assertCommands(t, got.Commands, []string{"show version", "show ip ospf neighbor"})
	if got.Commands[1].Note != "the adjacency" {
		t.Errorf("note = %q", got.Commands[1].Note)
	}
	if _, err := ParseCapture("set.yaml", []byte("name: x\nsteps:\n  - show version\n")); err == nil {
		t.Error("an unknown yaml field was accepted")
	}
}

// TestParseCaptureDOCX builds a REAL minimal .docx with archive/zip in the test
// — the shape Word writes, not a fixture nobody can regenerate — and proves the
// paragraph walk reads both body paragraphs and table cells in document order.
func TestParseCaptureDOCX(t *testing.T) {
	doc := docxFixture(t,
		[]string{"# ACME runbook", "show version", ""},
		[][]string{{"show ip bgp summary", "the peers"}, {"show interfaces status", ""}},
	)
	got, err := ParseCapture("acme.docx", doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	assertCommands(t, got.Commands, []string{
		"show version", "show ip bgp summary", "the peers", "show interfaces status",
	})
	if got.Name != "acme" {
		t.Errorf("name = %q, want the file's basename", got.Name)
	}
	// Anything that is not a docx is refused by name, never guessed at.
	if _, err := ParseCapture("acme.docx", []byte("show version\n")); err == nil {
		t.Error("a non-zip was accepted as a Word file")
	}
	// A zip with no document part is refused too.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("word/other.xml")
	_, _ = w.Write([]byte("<x/>"))
	_ = zw.Close()
	if _, err := ParseCapture("acme.docx", buf.Bytes()); err == nil {
		t.Error("a zip with no word/document.xml was accepted")
	}
}

// TestParseCaptureDOCXJoinsRuns proves the run-splitting Word does to a single
// visible line is undone: one paragraph is one command, however many `w:t`
// fragments it was stored in.
func TestParseCaptureDOCXJoinsRuns(t *testing.T) {
	body := `<w:p><w:r><w:t>show ip </w:t></w:r><w:r><w:t>bgp</w:t></w:r><w:r><w:tab/><w:t>summary</w:t></w:r></w:p>`
	got, err := ParseCapture("split.docx", docxRaw(t, body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	assertCommands(t, got.Commands, []string{"show ip bgp summary"})
}

func TestParseCaptureBounds(t *testing.T) {
	// Over the command ceiling → the WHOLE file is refused, never trimmed.
	many := strings.Repeat("show version\n", MaxCaptureCommands+1)
	if _, err := ParseCapture("big.txt", []byte(many)); !errors.Is(err, ErrCaptureTooMany) {
		t.Errorf("a file over the command ceiling: %v, want ErrCaptureTooMany", err)
	}
	// Exactly at the ceiling is accepted — the bound is a ceiling, not a fence.
	atCap := strings.Repeat("show version\n", MaxCaptureCommands)
	if _, err := ParseCapture("big.txt", []byte(atCap)); err != nil {
		t.Errorf("a file exactly at the ceiling was refused: %v", err)
	}
	// One over-long line refuses the file; it is never truncated into a
	// different command.
	long := "show " + strings.Repeat("x", MaxCaptureCommandBytes) + "\n"
	if _, err := ParseCapture("long.txt", []byte(long)); !errors.Is(err, ErrCaptureLineTooLong) {
		t.Errorf("an over-long command: %v, want ErrCaptureLineTooLong", err)
	}
	// A file with nothing in it is an honest refusal, not an empty capture.
	if _, err := ParseCapture("empty.txt", []byte("# only comments\n\n")); !errors.Is(err, ErrCaptureEmpty) {
		t.Errorf("an empty file: %v, want ErrCaptureEmpty", err)
	}
	if _, err := ParseCapture("set.xlsx", []byte("x")); !errors.Is(err, ErrCaptureFormat) {
		t.Errorf("an unsupported format: %v, want ErrCaptureFormat", err)
	}
}

// TestVendorDefaultCaptureIsBoundStepsOnly — the derivation the customer never
// sees. An unbound intent has no command, so it can never become a line.
func TestVendorDefaultCaptureIsBoundStepsOnly(t *testing.T) {
	if VendorDefaultCapture(nil) != nil {
		t.Fatal("a nil plan must yield no capture — 'none yet' and 'empty' are different facts")
	}
	p := &Plan{
		TenantID: "acme", Dialect: "arista-eos", DialectDisplay: "Arista EOS",
		Steps: []Step{
			{Intent: "a", Title: "Version", Section: SectionBaseline, Bound: true, Command: "show version"},
			{Intent: "b", Title: "Unbound", Section: SectionBaseline, Bound: false},
			{Intent: "c", Title: "Topology", Section: SectionTopology, Bound: true, Command: "not a device command"},
			{Intent: "d", Title: "Peers", Section: SectionDeepDive, Bound: true, Command: "show ip bgp summary"},
		},
	}
	got := VendorDefaultCapture(p)
	if got == nil {
		t.Fatal("no capture derived from a plan with bound steps")
	}
	if got.ID != VendorDefaultCaptureID || got.Source != CaptureVendorDefault {
		t.Errorf("id/source = %q/%q", got.ID, got.Source)
	}
	if got.Name != "Arista EOS default" {
		t.Errorf("name = %q", got.Name)
	}
	assertCommands(t, got.Commands, []string{"show version", "show ip bgp summary"})
	if got.TenantID != "acme" {
		t.Errorf("tenant = %q, want the plan's own", got.TenantID)
	}
}

func TestCaptureFailureReason(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", CaptureReasonNoOutput},
		{"context deadline exceeded", CaptureReasonTimeout},
		{"command timed out after 30s", CaptureReasonTimeout},
		{"output exceeded this command's size cap and was truncated", CaptureReasonTruncated},
		{"protocol-diagnostics collector is not configured on this deployment", CaptureReasonGateway},
		{"dial tcp 10.0.0.1:22: connect: connection refused", CaptureReasonGateway},
		{"% Invalid input detected at '^' marker", CaptureReasonUnknown},
		{"syntax error, expecting <command>", CaptureReasonUnknown},
		{"permission denied", CaptureReasonRefused},
		{"something nobody has seen before", CaptureReasonRefused},
	} {
		if got := captureFailureReason(tc.in); got != tc.want {
			t.Errorf("captureFailureReason(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestCaptureProgressOf — the five states, and the rule that only FAILED
// commands are listed.
func TestCaptureProgressOf(t *testing.T) {
	ok := CommandSummary{Command: "show version", Bytes: 120}
	bad := CommandSummary{Command: "show ip bgp summary", Err: "context deadline exceeded"}
	silent := CommandSummary{Command: "show logging", Bytes: 0}

	t.Run("queued when nothing has run", func(t *testing.T) {
		pr := CaptureProgressOf("c", nil, nil)
		if pr.Status != CaptureQueued || len(pr.Commands) != 0 {
			t.Fatalf("%+v", pr)
		}
	})
	t.Run("running while the job is in flight", func(t *testing.T) {
		pr := CaptureProgressOf("c", &Job{Status: JobRunning, Total: 9}, nil)
		if pr.Status != CaptureRunning || pr.Total != 9 {
			t.Fatalf("%+v", pr)
		}
	})
	t.Run("done lists no command at all", func(t *testing.T) {
		pr := CaptureProgressOf("c", &Job{Status: JobDone}, &CaptureSummary{Commands: []CommandSummary{ok, ok}})
		if pr.Status != CaptureDone {
			t.Fatalf("status = %q", pr.Status)
		}
		if len(pr.Commands) != 0 {
			t.Fatalf("a clean collection rendered %d command rows; successful output belongs in the bundle", len(pr.Commands))
		}
		if pr.Done != 2 || pr.Failed != 0 {
			t.Fatalf("%+v", pr)
		}
	})
	t.Run("partial lists only the failures", func(t *testing.T) {
		pr := CaptureProgressOf("c", &Job{Status: JobDone},
			&CaptureSummary{Commands: []CommandSummary{ok, bad, silent}})
		if pr.Status != CapturePartial {
			t.Fatalf("status = %q", pr.Status)
		}
		if len(pr.Commands) != 2 {
			t.Fatalf("want the two failures only, got %+v", pr.Commands)
		}
		if pr.Commands[0].Command != bad.Command || pr.Commands[0].Reason != CaptureReasonTimeout {
			t.Errorf("%+v", pr.Commands[0])
		}
		if pr.Commands[1].Reason != CaptureReasonNoOutput {
			t.Errorf("a command that returned nothing: %+v", pr.Commands[1])
		}
	})
	t.Run("failed when every command failed", func(t *testing.T) {
		pr := CaptureProgressOf("c", &Job{Status: JobDone}, &CaptureSummary{Commands: []CommandSummary{bad}})
		if pr.Status != CaptureFailed || len(pr.Commands) != 1 {
			t.Fatalf("%+v", pr)
		}
	})
	t.Run("failed before any command carries the job's own reason", func(t *testing.T) {
		pr := CaptureProgressOf("c", &Job{Status: JobFailed, Err: "the gateway is not configured"}, nil)
		if pr.Status != CaptureFailed {
			t.Fatalf("status = %q", pr.Status)
		}
		if len(pr.Commands) != 1 || pr.Commands[0].Reason != CaptureReasonGateway {
			t.Fatalf("%+v", pr.Commands)
		}
	})
}

func TestCaptureFromTemplate(t *testing.T) {
	got := CaptureFromTemplate(Template{
		ID: "tpl-1", TenantID: "acme", Name: "ACME baseline", Dialect: "arista-eos",
		Steps: []TemplateStep{{Command: "show version", Note: "why"}, {Command: "show logging"}},
	})
	if got.Source != CaptureTemplate {
		t.Errorf("source = %q", got.Source)
	}
	assertCommands(t, got.Commands, []string{"show version", "show logging"})
	if got.Commands[0].Note != "why" {
		t.Errorf("note lost: %+v", got.Commands[0])
	}
	if list := got.CommandList(); len(list) != 2 || list[0] != "show version" {
		t.Errorf("CommandList = %v", list)
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func assertCommands(t *testing.T, got []CaptureCommand, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d commands %v, want %d %v", len(got), commandsOfCapture(got), len(want), want)
	}
	for i := range want {
		if got[i].Command != want[i] {
			t.Errorf("command %d = %q, want %q", i, got[i].Command, want[i])
		}
	}
}

// docxRaw wraps a document body in the minimal OPC package Word writes: a zip
// whose `word/document.xml` holds a `w:document`/`w:body`. It is built here
// rather than checked in so the fixture can never drift out of regenerability.
func docxRaw(t *testing.T, body string) []byte {
	t.Helper()
	const ns = `xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"`
	xmlDoc := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:document ` + ns + `><w:body>` + body + `</w:body></w:document>`
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// A real .docx also carries [Content_Types].xml and _rels; the parser reads
	// neither, and writing them here would assert a shape we do not depend on.
	w, err := zw.Create(docxDocumentPart)
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := w.Write([]byte(xmlDoc)); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// docxFixture builds body paragraphs and one table whose cells hold paragraphs
// — the two places a NOC actually writes a command list in Word.
func docxFixture(t *testing.T, paragraphs []string, tableRows [][]string) []byte {
	t.Helper()
	var b strings.Builder
	para := func(s string) string {
		var esc bytes.Buffer
		if err := xml.EscapeText(&esc, []byte(s)); err != nil {
			t.Fatalf("escape: %v", err)
		}
		return `<w:p><w:r><w:t>` + esc.String() + `</w:t></w:r></w:p>`
	}
	for _, p := range paragraphs {
		b.WriteString(para(p))
	}
	if len(tableRows) > 0 {
		b.WriteString(`<w:tbl>`)
		for _, row := range tableRows {
			b.WriteString(`<w:tr>`)
			for _, cell := range row {
				b.WriteString(`<w:tc>` + para(cell) + `</w:tc>`)
			}
			b.WriteString(`</w:tr>`)
		}
		b.WriteString(`</w:tbl>`)
	}
	return docxRaw(t, b.String())
}

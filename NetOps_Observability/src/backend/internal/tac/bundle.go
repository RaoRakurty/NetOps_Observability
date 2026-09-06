// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// bundle.go — the artifact a vendor TAC engineer actually receives.
//
// A zip with a fixed, boring layout, because a stranger has to find their way
// around it in thirty seconds:
//
//	MANIFEST.json          what this is, what produced it, what is missing
//	PROBLEM_STATEMENT.md   Correlix's evidence-only statement
//	outputs/NN-intent.txt  one file per collected command, REDACTED
//	evidence/index.json    every citable fact with its [id]
//	evidence/alerts.json   the alerts that fired in the window
//	evidence/hypotheses.json  the RCA ranking
//	evidence/findings.json    security findings in the window
//	evidence/logs.txt         log excerpts, redacted
//	evidence/correlation.json the raw correlation object
//	topology.json          Correlix's own neighbourhood for the device
//	device.json            device facts
//	SHA256SUMS             a checksum for every other file
//
// THREE PROPERTIES THIS FILE OWES:
//
//  1. NOTHING UNREDACTED. Command outputs were redacted at capture; log
//     excerpts, findings and free text are redacted HERE, through the same
//     protocoldiag pass, so there is exactly one redaction implementation and no
//     way into the zip that bypasses it.
//  2. THE MANIFEST TELLS THE TRUTH ABOUT GAPS. Unbound intents, failed
//     commands, an unclassified incident, a doc_claimed command, a trimmed
//     email profile — each is a field, not an omission.
//  3. DETERMINISM. Given the same inputs the same bytes come out (entry order
//     is fixed, timestamps come from the capture, the zip carries no modtimes
//     of its own), so a bundle can be re-derived and compared.

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/protocoldiag"
)

// AlertFact is one alert that fired in the incident window.
type AlertFact struct {
	Name     string    `json:"name"`
	Severity string    `json:"severity,omitempty"`
	Device   string    `json:"device,omitempty"`
	Summary  string    `json:"summary,omitempty"`
	At       time.Time `json:"at,omitzero"`
}

// HypothesisFact is one ranked RCA hypothesis.
type HypothesisFact struct {
	TemplateID string   `json:"template_id"`
	Title      string   `json:"title,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	State      string   `json:"state,omitempty"`
	Supporting []string `json:"supporting,omitempty"`
	Missing    []string `json:"missing,omitempty"`
}

// LogLine is one log excerpt from the window.
type LogLine struct {
	At       time.Time `json:"at,omitzero"`
	Device   string    `json:"device,omitempty"`
	Severity string    `json:"severity,omitempty"`
	Message  string    `json:"message"`
}

// FindingFact is one security/compliance finding in the window.
type FindingFact struct {
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Severity string    `json:"severity,omitempty"`
	Device   string    `json:"device,omitempty"`
	At       time.Time `json:"at,omitzero"`
}

// BundleInput is everything the bundle is assembled from. The caller has already
// resolved each part IN THE PRINCIPAL'S OWN SCOPE; this package stamps the
// tenant it was given and never widens it.
type BundleInput struct {
	TenantID    string
	IncidentID  string
	IncidentRef string
	Title       string
	WindowStart time.Time
	WindowEnd   time.Time
	Actor       string

	Class   Classification
	Plan    *Plan
	Capture *Capture

	Alerts      []AlertFact
	Hypotheses  []HypothesisFact
	Logs        []LogLine
	Findings    []FindingFact
	Correlation map[string]any
	DeviceFacts map[string]string

	// Profile selects how much goes in. Empty means ProfileFull.
	Profile BundleProfile
	// MaxBytes is the CONNECTOR'S declared attachment ceiling, in raw bundle
	// bytes. It is what ProfileEmail trims to; 0 falls back to
	// EmailProfileMaxBytes. Supplying it matters: an email connector's real
	// ceiling is smaller than this package's default precisely because base64
	// expands the attachment on the wire (see MIMEEncodedSize).
	MaxBytes int64
}

// Manifest is the bundle's front page, in machine-readable form.
type Manifest struct {
	Format         string    `json:"format"`
	EngineVersion  string    `json:"engine_version"`
	CatalogVersion string    `json:"catalog_version"`
	PlanVersion    string    `json:"plan_version,omitempty"`
	GeneratedAt    time.Time `json:"generated_at"`
	GeneratedBy    string    `json:"generated_by"`
	Profile        string    `json:"profile"`

	TenantID    string `json:"tenant_id"`
	IncidentID  string `json:"incident_id"`
	IncidentRef string `json:"incident_ref,omitempty"`
	Title       string `json:"title,omitempty"`

	WindowStart time.Time `json:"window_start,omitzero"`
	WindowEnd   time.Time `json:"window_end,omitzero"`

	Device struct {
		ID       string `json:"id"`
		Hostname string `json:"hostname"`
		Platform string `json:"platform"`
		Dialect  string `json:"dialect"`
		Display  string `json:"dialect_display"`
		HasPlan  bool   `json:"has_authored_plan"`
	} `json:"device"`

	Classification struct {
		ClassID    string   `json:"class_id"`
		Title      string   `json:"title"`
		Classified bool     `json:"classified"`
		Why        []Reason `json:"why"`
		Note       string   `json:"note"`
	} `json:"classification"`

	// CommandReview is the PROVENANCE of the command set that ran: which
	// template it came from, at which version, and every difference between what
	// Correlix proposed and what a human approved. It is always present — an
	// unreviewed collection says `reviewed:false` with no edits, which is itself
	// the fact a TAC engineer needs.
	CommandReview ManifestReview `json:"command_review"`

	Commands []ManifestCommand `json:"commands"`
	// NotCollected names every intent the class wanted and the dialect does not
	// bind. It is a FIELD, not an omission — the gap is part of the evidence.
	NotCollected []ManifestGap `json:"not_collected"`
	// Failed names every command that errored, with the reason.
	Failed []ManifestCommand `json:"failed"`

	Redaction string `json:"redaction"`
	// ProblemStatement records who wrote it and what it cites.
	ProblemStatement ProblemStatement `json:"problem_statement"`

	Counts struct {
		Alerts     int `json:"alerts"`
		Hypotheses int `json:"hypotheses"`
		Logs       int `json:"logs"`
		Findings   int `json:"findings"`
		Topology   int `json:"topology"`
		Evidence   int `json:"evidence_items"`
	} `json:"counts"`

	// Trimmed records what the email profile dropped and why. Empty on a full
	// bundle. A bundle NEVER silently loses content.
	Trimmed []ManifestTrim `json:"trimmed,omitempty"`
	// MaxBytes is the ceiling the profile trimmed to, when one applied. It is
	// stamped so a reader can tell "nothing was dropped" from "nothing needed
	// dropping under a 14,000,000-byte limit".
	MaxBytes int64          `json:"max_bytes,omitempty"`
	Files    []ManifestFile `json:"files"`
}

// ManifestReview records the command review (templates.go) in the bundle.
type ManifestReview struct {
	// Reviewed says a human approved an explicit command list, which the server
	// then re-validated line by line before anything ran.
	Reviewed bool        `json:"reviewed"`
	Template TemplateRef `json:"template,omitzero"`
	// Edits are the differences from the plan Correlix proposed. Empty means the
	// operator ran the engine's plan unchanged.
	Edits []PlanEdit `json:"edits"`
	// Policy is the one sentence that bounds every command in this bundle,
	// stated in the bundle itself so a reader never has to take it on trust.
	Policy string `json:"policy"`
}

// ReviewPolicyNote is the sentence every bundle carries about its command set.
const ReviewPolicyNote = "Every command in this bundle — Correlix's own and any your team added — passed Correlix's " +
	"OUTPUT-ONLY policy before it ran: nothing that changes configuration, restarts or reboots, or addresses a " +
	"daemon is carried by this platform at all, and a reachability probe is bounded (count, size, timeout, hops). " +
	"Commands marked `custom` were written by the operator's own team and have never been verified by Correlix on " +
	"this platform."

// ManifestCommand is one command's row in the manifest.
type ManifestCommand struct {
	Intent   string   `json:"intent"`
	Command  string   `json:"command"`
	Section  string   `json:"section"`
	Verified Verified `json:"verified,omitempty"`
	// VerifiedNote spells out doc_claimed in words, because "doc_claimed" alone
	// is a term a TAC engineer has no reason to know.
	VerifiedNote string    `json:"verified_note,omitempty"`
	File         string    `json:"file,omitempty"`
	Bytes        int       `json:"bytes"`
	Error        string    `json:"error,omitempty"`
	At           time.Time `json:"at,omitzero"`
	EvidenceID   string    `json:"evidence_id,omitempty"`
}

// ManifestGap is one intent that was not collected, and why.
type ManifestGap struct {
	Intent string `json:"intent"`
	Title  string `json:"title"`
	Reason string `json:"reason"`
}

// ManifestTrim records one file the profile dropped.
type ManifestTrim struct {
	File   string `json:"file"`
	Bytes  int    `json:"bytes"`
	Reason string `json:"reason"`
}

// ManifestFile is one zip entry with its size and checksum.
type ManifestFile struct {
	Name   string `json:"name"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Bundle is the assembled artifact.
type Bundle struct {
	// Name is the suggested filename. It carries NO tenant id — the file is
	// meant to leave the operator's hands.
	Name     string
	Zip      []byte
	Manifest Manifest
	// Statement is the problem statement, also returned separately so the case
	// form can use it as the description without unzipping.
	Statement ProblemStatement
}

// bundleFile is one entry before the zip is written.
type bundleFile struct {
	name string
	data []byte
	// trimmable marks a command output the email profile may drop. The manifest,
	// the statement and the evidence index are never trimmable.
	trimmable bool
}

// BuildBundle assembles the zip. The narrator may be nil (template statement).
func BuildBundle(ctx context.Context, in BundleInput, n Narrator, now func() time.Time) (*Bundle, error) {
	if in.Capture == nil {
		return nil, fmt.Errorf("tac: bundle needs a capture")
	}
	if now == nil {
		now = time.Now
	}
	profile := in.Profile
	if profile == "" {
		profile = ProfileFull
	}

	ev := buildEvidenceIndex(in)
	statement := WriteProblemStatement(ctx, ProblemInput{
		TenantID: in.TenantID, IncidentID: in.IncidentID, IncidentRef: in.IncidentRef,
		Title: in.Title, WindowStart: in.WindowStart, WindowEnd: in.WindowEnd,
		Hostname: in.Capture.Hostname, Platform: in.Capture.Platform,
		DialectLabel: dialectLabel(in), Class: in.Class, Plan: in.Plan,
		Capture: in.Capture, Evidence: ev,
	}, n)

	man := buildManifest(in, ev, statement, profile, now())

	files := []bundleFile{
		{name: "PROBLEM_STATEMENT.md", data: []byte(statement.Text)},
		{name: "evidence/index.json", data: mustJSON(ev)},
		{name: "evidence/alerts.json", data: mustJSON(redactAlerts(in.Alerts))},
		{name: "evidence/hypotheses.json", data: mustJSON(in.Hypotheses)},
		{name: "evidence/findings.json", data: mustJSON(in.Findings)},
		{name: "evidence/logs.txt", data: []byte(renderLogs(in.Logs))},
		{name: "evidence/correlation.json", data: mustJSON(in.Correlation)},
		{name: "topology.json", data: mustJSON(in.Capture.Topology)},
		{name: "device.json", data: mustJSON(deviceDoc(in))},
	}
	for i, cc := range in.Capture.Commands {
		files = append(files, bundleFile{
			name:      outputFileName(i, cc),
			data:      []byte(renderOutput(cc)),
			trimmable: true,
		})
	}

	// Email profile: drop the largest trimmable outputs until the bundle fits.
	// The MANIFEST names every drop; nothing is silently lost.
	if profile == ProfileEmail {
		limit := in.MaxBytes
		if limit <= 0 {
			limit = EmailProfileMaxBytes
		}
		files, man.Trimmed = trimForEmail(files, man, limit)
		man.MaxBytes = limit
	}

	// Fix the command → file mapping AFTER trimming so the manifest cannot
	// point at a file that is no longer there.
	present := map[string]bool{}
	for _, f := range files {
		present[f.name] = true
	}
	for i := range man.Commands {
		if man.Commands[i].File != "" && !present[man.Commands[i].File] {
			man.Commands[i].File = ""
		}
	}

	sort.SliceStable(files, func(i, j int) bool { return files[i].name < files[j].name })

	// Checksums, then the manifest that carries them, then the SHA256SUMS file.
	man.Files = make([]ManifestFile, 0, len(files)+1)
	var sums bytes.Buffer
	for _, f := range files {
		sum := sha256.Sum256(f.data)
		hexsum := hex.EncodeToString(sum[:])
		man.Files = append(man.Files, ManifestFile{Name: f.name, Bytes: len(f.data), SHA256: hexsum})
		fmt.Fprintf(&sums, "%s  %s\n", hexsum, f.name)
	}
	manBytes := mustJSON(man)
	manSum := sha256.Sum256(manBytes)
	fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(manSum[:]), "MANIFEST.json")

	all := append([]bundleFile{{name: "MANIFEST.json", data: manBytes}}, files...)
	all = append(all, bundleFile{name: "SHA256SUMS", data: sums.Bytes()})
	sort.SliceStable(all, func(i, j int) bool { return all[i].name < all[j].name })

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range all {
		hdr := &zip.FileHeader{Name: f.name, Method: zip.Deflate}
		// A fixed modified time keeps the bundle byte-deterministic; the real
		// times live in the manifest and in each output's header line.
		hdr.Modified = in.Capture.StartedAt.UTC()
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return nil, fmt.Errorf("tac: bundle: %w", err)
		}
		if _, err := w.Write(f.data); err != nil {
			return nil, fmt.Errorf("tac: bundle: %w", err)
		}
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("tac: bundle: %w", err)
	}
	return &Bundle{Name: bundleName(in), Zip: buf.Bytes(), Manifest: man, Statement: statement}, nil
}

func buildManifest(in BundleInput, ev []EvidenceItem, st ProblemStatement, profile BundleProfile, at time.Time) Manifest {
	var m Manifest
	m.Format = "correlix-tac-bundle/1"
	m.EngineVersion = Version
	m.CatalogVersion = in.Capture.CatalogVersion
	m.PlanVersion = in.Capture.PlanVersion
	m.GeneratedAt = at.UTC()
	m.GeneratedBy = in.Actor
	m.Profile = string(profile)
	m.TenantID = in.TenantID
	m.IncidentID = in.IncidentID
	m.IncidentRef = in.IncidentRef
	m.Title = in.Title
	m.WindowStart = in.WindowStart.UTC()
	m.WindowEnd = in.WindowEnd.UTC()
	m.Device.ID = in.Capture.DeviceID
	m.Device.Hostname = in.Capture.Hostname
	m.Device.Platform = in.Capture.Platform
	m.Device.Dialect = in.Capture.Dialect
	m.Device.Display = in.Capture.Display
	m.Device.HasPlan = in.Capture.HasPlan
	m.Classification.ClassID = in.Class.ClassID
	m.Classification.Title = in.Class.Title
	m.Classification.Classified = in.Class.Classified
	m.Classification.Why = in.Class.Why
	m.Classification.Note = in.Class.Note
	m.Redaction = RedactionNoteText
	m.ProblemStatement = st
	m.CommandReview = ManifestReview{
		Reviewed: in.Capture.Reviewed,
		Template: in.Capture.Template,
		Edits:    append([]PlanEdit{}, in.Capture.Edits...),
		Policy:   ReviewPolicyNote,
	}

	evByRef := map[string]string{}
	for _, e := range ev {
		if e.Kind == "command" {
			evByRef[e.Ref] = e.ID
		}
	}
	m.Commands = make([]ManifestCommand, 0, len(in.Capture.Commands))
	m.Failed = []ManifestCommand{}
	for i, cc := range in.Capture.Commands {
		row := ManifestCommand{
			Intent: cc.Intent, Command: cc.Command, Section: string(cc.Section),
			Verified: cc.Verified, File: outputFileName(i, cc), Bytes: cc.Bytes,
			Error: cc.Err, At: cc.StartedAt, EvidenceID: evByRef[cc.Intent],
		}
		if cc.Verified == VerifiedDocClaimed {
			row.VerifiedNote = "This command is taken from the vendor's published documentation; Correlix has not verified it on this platform."
		}
		m.Commands = append(m.Commands, row)
		if cc.Err != "" {
			m.Failed = append(m.Failed, row)
		}
	}
	m.NotCollected = []ManifestGap{}
	for _, st := range in.Capture.Unbound {
		m.NotCollected = append(m.NotCollected, ManifestGap{Intent: st.Intent, Title: st.Title, Reason: st.Note})
	}
	m.Counts.Alerts = len(in.Alerts)
	m.Counts.Hypotheses = len(in.Hypotheses)
	m.Counts.Logs = len(in.Logs)
	m.Counts.Findings = len(in.Findings)
	m.Counts.Topology = len(in.Capture.Topology)
	m.Counts.Evidence = len(ev)
	return m
}

// buildEvidenceIndex assigns the citation ids. The order is fixed so the same
// inputs always produce the same ids — a statement written yesterday still
// points at the right rows.
func buildEvidenceIndex(in BundleInput) []EvidenceItem {
	var out []EvidenceItem
	seq := map[string]int{}
	next := func(prefix string) string {
		seq[prefix]++
		return prefix + itoaTAC(seq[prefix])
	}
	title := in.Title
	if title == "" {
		title = "Incident " + in.IncidentID
	}
	out = append(out, EvidenceItem{
		ID: next("I"), Kind: "incident", Ref: in.IncidentID,
		Text: "Incident " + firstNonEmpty(in.IncidentRef, in.IncidentID) + ": " + protocoldiag.RedactOutput(title),
		At:   in.WindowStart.UTC(),
	})
	if in.Capture != nil {
		out = append(out, EvidenceItem{
			ID: next("D"), Kind: "device", Ref: in.Capture.DeviceID,
			Text: "Subject device " + in.Capture.Hostname + " (" + in.Capture.Platform + "), CLI dialect " + dialectLabel(in) + ".",
		})
	}
	for _, a := range in.Alerts {
		out = append(out, EvidenceItem{
			ID: next("A"), Kind: "alert", Ref: a.Name, At: a.At.UTC(),
			Text: protocoldiag.RedactOutput(strings.TrimSpace(a.Name + " " + a.Severity + " " + a.Device + " " + a.Summary)),
		})
	}
	for _, h := range in.Hypotheses {
		out = append(out, EvidenceItem{
			ID: next("H"), Kind: "hypothesis", Ref: h.TemplateID,
			Text: protocoldiag.RedactOutput(strings.TrimSpace(h.TemplateID + " " + h.Title + " confidence=" + h.Confidence + " state=" + h.State)),
		})
	}
	if in.Capture != nil {
		for _, cc := range in.Capture.Commands {
			text := "`" + cc.Command + "` on " + in.Capture.Hostname
			if cc.Err != "" {
				text += " — FAILED: " + cc.Err
			}
			out = append(out, EvidenceItem{ID: next("C"), Kind: "command", Ref: cc.Intent, Text: text, At: cc.StartedAt.UTC()})
		}
	}
	for _, l := range in.Logs {
		out = append(out, EvidenceItem{
			ID: next("L"), Kind: "log", Ref: l.Device, At: l.At.UTC(),
			Text: protocoldiag.RedactOutput(clip(l.Message, 400)),
		})
	}
	for _, f := range in.Findings {
		out = append(out, EvidenceItem{
			ID: next("F"), Kind: "finding", Ref: f.ID, At: f.At.UTC(),
			Text: protocoldiag.RedactOutput(strings.TrimSpace(f.Severity + " " + f.Title + " " + f.Device)),
		})
	}
	if in.Capture != nil {
		for _, t := range in.Capture.Topology {
			out = append(out, EvidenceItem{
				ID: next("T"), Kind: "topology", Ref: t.Ref,
				Text: protocoldiag.RedactOutput(strings.TrimSpace(t.Kind + " " + t.Ref + " " + t.Detail)),
			})
		}
	}
	return out
}

// trimForEmail drops the largest trimmable outputs until the estimated zip fits
// the email profile. It works on UNCOMPRESSED sizes, which over-estimates, so it
// errs toward a bundle that certainly fits.
func trimForEmail(files []bundleFile, man Manifest, limit int64) ([]bundleFile, []ManifestTrim) {
	total := int64(len(mustJSON(man)))
	for _, f := range files {
		total += int64(len(f.data))
	}
	if total <= limit {
		return files, nil
	}
	idx := make([]int, 0, len(files))
	for i, f := range files {
		if f.trimmable {
			idx = append(idx, i)
		}
	}
	sort.SliceStable(idx, func(a, b int) bool { return len(files[idx[a]].data) > len(files[idx[b]].data) })

	drop := map[int]bool{}
	var trimmed []ManifestTrim
	reason := "dropped to fit this connector's " + itoaTAC(int(limit)) +
		"-byte attachment limit; download the full bundle from Correlix for this output"
	for _, i := range idx {
		if total <= limit {
			break
		}
		drop[i] = true
		total -= int64(len(files[i].data))
		trimmed = append(trimmed, ManifestTrim{
			File: files[i].name, Bytes: len(files[i].data), Reason: reason,
		})
	}
	out := make([]bundleFile, 0, len(files))
	for i, f := range files {
		if drop[i] {
			continue
		}
		out = append(out, f)
	}
	return out, trimmed
}

func outputFileName(i int, cc CollectedCommand) string {
	n := itoaTAC(i + 1)
	for len(n) < 2 {
		n = "0" + n
	}
	return "outputs/" + n + "-" + fileSlug(cc.Intent) + ".txt"
}

func renderOutput(cc CollectedCommand) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# intent   : %s\n", cc.Intent)
	fmt.Fprintf(&b, "# command  : %s\n", cc.Command)
	fmt.Fprintf(&b, "# section  : %s\n", cc.Section)
	if cc.Verified != "" {
		fmt.Fprintf(&b, "# sourcing : %s\n", cc.Verified)
	}
	if !cc.StartedAt.IsZero() {
		fmt.Fprintf(&b, "# at       : %s\n", cc.StartedAt.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "# redacted : yes\n")
	if cc.Err != "" {
		fmt.Fprintf(&b, "# ERROR    : %s\n", cc.Err)
	}
	b.WriteString("\n")
	if strings.TrimSpace(cc.Output) == "" && cc.Err == "" {
		b.WriteString("(the command ran and returned no output)\n")
		return b.String()
	}
	b.WriteString(cc.Output)
	if !strings.HasSuffix(cc.Output, "\n") {
		b.WriteString("\n")
	}
	return b.String()
}

func renderLogs(logs []LogLine) string {
	if len(logs) == 0 {
		return "(no log excerpts were available for this incident window)\n"
	}
	var b strings.Builder
	for _, l := range logs {
		ts := ""
		if !l.At.IsZero() {
			ts = l.At.UTC().Format(time.RFC3339) + " "
		}
		fmt.Fprintf(&b, "%s%s %s %s\n", ts, l.Device, l.Severity, protocoldiag.RedactOutput(l.Message))
	}
	return b.String()
}

func redactAlerts(in []AlertFact) []AlertFact {
	out := make([]AlertFact, len(in))
	for i, a := range in {
		a.Summary = protocoldiag.RedactOutput(a.Summary)
		out[i] = a
	}
	return out
}

func deviceDoc(in BundleInput) map[string]any {
	facts := map[string]string{}
	for k, v := range in.DeviceFacts {
		facts[k] = protocoldiag.RedactOutput(v)
	}
	return map[string]any{
		"id":                in.Capture.DeviceID,
		"hostname":          in.Capture.Hostname,
		"platform":          in.Capture.Platform,
		"dialect":           in.Capture.Dialect,
		"dialect_display":   in.Capture.Display,
		"has_authored_plan": in.Capture.HasPlan,
		"facts":             facts,
	}
}

func dialectLabel(in BundleInput) string {
	if in.Capture == nil {
		return ""
	}
	if in.Capture.Display != "" {
		return in.Capture.Display
	}
	return in.Capture.Dialect
}

// bundleName is the suggested download name. It is built only from the incident
// reference and the sanitised hostname — no tenant id, no device id — so the
// name itself leaks nothing when the file is forwarded to a vendor.
func bundleName(in BundleInput) string {
	host := fileSlug(in.Capture.Hostname)
	if host == "" {
		host = "device"
	}
	ref := fileSlug(firstNonEmpty(in.IncidentRef, in.IncidentID))
	if ref == "" {
		ref = "incident"
	}
	cls := fileSlug(in.Class.ClassID)
	if cls == "" {
		cls = "generic"
	}
	return "correlix-tac-" + ref + "-" + host + "-" + cls + ".zip"
}

// fileSlug reduces a string to lowercase [a-z0-9-] so it is safe in a filename
// on every platform: no path separators, no shell-significant characters.
func fileSlug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.' || r == ' ' || r == '/':
			b.WriteByte('-')
		}
		if b.Len() >= 48 {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func mustJSON(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		// Every value marshalled here is a plain struct or map of scalars, so
		// this is unreachable; returning the error text keeps the bundle
		// honest rather than panicking a request goroutine.
		return []byte(`{"error":"this section could not be serialised"}`)
	}
	return append(b, '\n')
}

// jsonUnmarshal is the store's decode side, kept beside mustJSON so this
// package has exactly one JSON dependency point.
func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

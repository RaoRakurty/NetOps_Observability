// SPDX-License-Identifier: Apache-2.0
//
// Presentation contract for the embedded wizard page. The UI is a single
// hand-written file with no build step and no framework, so the things that
// silently break it — a type size below the NOC-admin floor, an asset that
// reaches for the network on an air-gapped appliance, an element the script
// addresses by id that a re-skin quietly renamed — get pinned here rather than
// discovered on a customer's install.
package main

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// uiParts returns the whole page, the markup (everything before the script
// block) and the script block. The wizard is one file by design; splitting it
// here is what lets the id inventory below be derived from the script instead
// of hand-maintained.
func uiParts(t *testing.T) (page, markup, script string) {
	t.Helper()
	b, err := os.ReadFile("ui.html")
	if err != nil {
		t.Fatalf("ui.html: %v", err)
	}
	page = string(b)
	i := strings.Index(page, "<script>")
	if i < 0 {
		t.Fatal("ui.html has no <script> block")
	}
	j := strings.LastIndex(page, "</script>")
	if j < i {
		t.Fatal("ui.html has an unterminated <script> block")
	}
	return page, page[:i], page[i+len("<script>") : j]
}

// dataURIRE matches the inlined assets (mesh, noise, brand mark, brand eye).
// Their base64 payload is arbitrary text that would otherwise produce phantom
// hits for every scan below, so it is blanked before scanning.
var dataURIRE = regexp.MustCompile(`data:[a-z/+.-]+;base64,[A-Za-z0-9+/=]+`)

// TestWizardTypeIsNeverSmallerThan14px enforces the NOC-admin UI standard's
// floor (owner, 2026-09-06: fonts >= 14px). A 12px "hint" is the usual way this
// regresses — the operator reading it is standing in a server room.
func TestWizardTypeIsNeverSmallerThan14px(t *testing.T) {
	page, _, _ := uiParts(t)
	css := dataURIRE.ReplaceAllString(page, "DATA")

	sizeRE := regexp.MustCompile(`font-size:\s*([0-9.]+)px`)
	for _, m := range sizeRE.FindAllStringSubmatch(css, -1) {
		px, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			t.Fatalf("unparseable font-size %q", m[0])
		}
		if px < 14 {
			t.Errorf("%s — the NOC-admin UI standard floors text at 14px", m[0])
		}
	}
	// The `font:` shorthand hides a size from the scan above; the stylesheet
	// states sizes explicitly so that the floor stays checkable.
	shorthandRE := regexp.MustCompile(`font:\s*[^;{}]*[0-9.]+px`)
	for _, m := range shorthandRE.FindAllString(css, -1) {
		t.Errorf("font shorthand carries a size (%q) — spell out font-size so the "+
			"14px floor stays machine-checkable", strings.TrimSpace(m))
	}
}

// TestWizardLoadsNothingFromTheNetwork: the appliance host is offline by
// design. A webfont link or a CDN script renders a blank, unstyled wizard on an
// air-gapped install — and the served CSP (default-src 'none', img-src data:)
// would block it anyway, failing silently.
func TestWizardLoadsNothingFromTheNetwork(t *testing.T) {
	page, _, _ := uiParts(t)
	scan := dataURIRE.ReplaceAllString(page, "DATA")

	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']\s*(?:https?:)?//`),
		regexp.MustCompile(`(?i)url\(\s*["']?\s*(?:https?:)?//`),
		regexp.MustCompile(`(?i)@import`),
	} {
		if m := re.FindString(scan); m != "" {
			t.Errorf("ui.html reaches for the network (%q) — every asset must be "+
				"inline; the installer runs air-gapped", strings.TrimSpace(m))
		}
	}
	for _, host := range []string{"fonts.googleapis.com", "fonts.gstatic.com", "cdnjs", "jsdelivr", "unpkg"} {
		if strings.Contains(scan, host) {
			t.Errorf("ui.html references %s — no CDNs, no webfonts", host)
		}
	}
}

// TestWizardCarriesEveryElementTheScriptAddresses derives the required element
// inventory FROM the script, so the two cannot drift: every $('id') the wizard
// looks up must exist in the markup. A re-skin that renames one turns the whole
// step into a silent no-op (the handler throws on a null element and the button
// simply stops working).
func TestWizardCarriesEveryElementTheScriptAddresses(t *testing.T) {
	_, markup, script := uiParts(t)

	lookupRE := regexp.MustCompile(`\$\('([a-zA-Z0-9_-]+)'\)`)
	want := map[string]bool{}
	for _, m := range lookupRE.FindAllStringSubmatch(script, -1) {
		want[m[1]] = true
	}
	if len(want) < 30 {
		t.Fatalf("only %d element lookups found — the parser has drifted", len(want))
	}
	for id := range want {
		if !strings.Contains(markup, `id="`+id+`"`) {
			t.Errorf("the script addresses #%s but the markup has no such element", id)
		}
	}
	// The stage sections the script shows/hides by convention (st-<step>).
	for _, step := range []string{"ready", "prepare", "deploy", "disc", "size", "sec", "review", "install", "done"} {
		if !strings.Contains(markup, `id="st-`+step+`"`) {
			t.Errorf("stage section #st-%s is missing — show() could never reveal it", step)
		}
		if step == "done" {
			continue
		}
		if !strings.Contains(markup, `data-s="`+step+`"`) {
			t.Errorf("step strip has no item for %q — the wizard loses that navigation", step)
		}
	}
	// Selector-addressed contracts: the radio groups, the navigation classes and
	// the data-attribute buttons the script binds to.
	for _, sel := range []string{
		`class="stage"`, `class="rs"`, `name="preset"`, `name="tls"`,
		`data-next=`, `data-back=`, `class="s `, `class="f"`,
	} {
		if !strings.Contains(markup, sel) {
			t.Errorf("markup no longer carries %q, which the script binds to", sel)
		}
	}
	if !strings.Contains(markup, `data-s="install" disabled`) {
		t.Error("the Install step must start disabled — startInstall() enables it")
	}
}

// TestWizardPulsesWorkInProgress: an item that is running shows a blinking
// light (owner, 2026-09-14). CSS-only, indigo, and silenced for operators who
// asked for reduced motion.
func TestWizardPulsesWorkInProgress(t *testing.T) {
	page, markup, script := uiParts(t)
	for _, want := range []string{"@keyframes cxpulse", ".s.run{animation:cxpulse"} {
		if !strings.Contains(page, want) {
			t.Errorf("ui.html is missing %q — a running task must blink", want)
		}
	}
	if !strings.Contains(page, "@media (prefers-reduced-motion:reduce){.s.run{animation:none}}") {
		t.Error("the pulse must stop for prefers-reduced-motion, leaving a static indigo dot")
	}
	if !strings.Contains(script, "run:'◆'") {
		t.Error("fact() has no 'run' state — the readiness rows cannot pulse")
	}
	if !strings.Contains(markup, `id="prep-run"`) {
		t.Error("the Prepare step has no running row to pulse while sudo work runs")
	}
	// renderStages() maps a STARTED stage to .s.run — that is what pulses — and
	// anything not started/ok/failed to the grey .s.dim. A pending stage wearing
	// the running indigo is the regression this pins (second pass, 2026-09-14).
	if !strings.Contains(script, `(s.status==='start'?'run':'dim')`) {
		t.Error("renderStages must mark only the started stage 'run' and leave " +
			"pending stages on the grey 'dim' dot")
	}
}

// TestWizardKeepsTheOldJargonOut: the plain-language pass (owner's NOC-admin UI
// standard) is only worth anything if the old phrasing cannot creep back in
// through a JS-generated string, where it is invisible to a glance at the
// markup. Every phrase below was on this page before 2026-09-14.
func TestWizardKeepsTheOldJargonOut(t *testing.T) {
	page, _, _ := uiParts(t)
	scan := dataURIRE.ReplaceAllString(page, "DATA")
	for _, phrase := range []string{
		"IN USE",         // "Port 8000 IN USE"      -> "Port 8000 is already in use"
		"daemon healthy", //                         -> "running"
		"daemon unreachable",
		"mTLS mesh",      // "full mTLS mesh"        -> "Encrypted (all services)"
		"Host preflight", //                         -> "Checking the server"
		"TLS enablement", // ":8000 -> https after TLS enablement"
		"idempotently",   // "retry resumes idempotently"
		"AUTO",           // the uppercase sizing chip
		"Watchdog installed",
		"Show technical log",
	} {
		if strings.Contains(scan, phrase) {
			t.Errorf("ui.html still says %q — plain words lead, with the technical "+
				"name only as a muted <small> where an admin must quote it", phrase)
		}
	}
}

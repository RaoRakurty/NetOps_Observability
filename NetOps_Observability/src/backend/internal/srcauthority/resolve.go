// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package srcauthority

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"netops/backend/models"
)

// Fact is a descriptive device fact the resolver decides. Closed set: name and
// address are identity/collection plumbing (a controller's system-ip and the
// SNMP management address are different addresses, not a disagreement), `os`
// carries the raw sysDescr on SNMP rows and is never comparable, and the site
// has its own owner rule (a manually assigned site wins, 2026-10-18).
type Fact string

const (
	FactVendor          Fact = "vendor"
	FactModel           Fact = "model"
	FactSoftwareVersion Fact = "software_version"
	FactSerial          Fact = "serial"
)

// Facts lists the resolved facts in render order.
func Facts() []Fact {
	return []Fact{FactVendor, FactModel, FactSoftwareVersion, FactSerial}
}

// FactLabel is the operator wording of a fact.
func FactLabel(f Fact) string {
	switch f {
	case FactVendor:
		return "vendor"
	case FactModel:
		return "model"
	case FactSoftwareVersion:
		return "software version"
	case FactSerial:
		return "serial number"
	}
	return string(f)
}

// Claim is one source's value for one fact.
type Claim struct {
	Class    Class     `json:"class"`
	Source   string    `json:"source"`    // the raw provenance: "api:vmanage", "snmp", "manual"…
	RecordID string    `json:"record_id"` // the per-source inventory record it came from
	Value    string    `json:"value"`
	At       time.Time `json:"at,omitzero"` // when the source learned it (zero = unknown)
}

// Resolution is the decision for one fact.
type Resolution struct {
	Fact  Fact   `json:"fact"`
	Value string `json:"value"`
	// Winner is the claim the value came from.
	Winner Claim `json:"winner"`
	// Considered is every claim, best-ranked first.
	Considered []Claim `json:"considered"`
	// Disagreements are the claims whose value differs from the winner's.
	Disagreements []Claim `json:"disagreements,omitempty"`
	// TieBroken is true when two claims of the winner's own class disagreed
	// and recency / name decided between them — authority alone could not.
	TieBroken bool `json:"tie_broken,omitempty"`
}

// Disagreed reports whether any source contradicted the winner.
func (r Resolution) Disagreed() bool { return len(r.Disagreements) > 0 }

// Resolve decides one fact under order. Claims with an empty value are not
// claims (the source did not report the fact) and are dropped. ok=false when
// no source reported the fact. An invalid order is replaced by the platform
// default — the resolver is default-closed, never undefined.
func Resolve(order []Class, fact Fact, claims []Claim) (Resolution, bool) {
	if ValidateOrder(order) != nil {
		order = DefaultOrder()
	}
	cs := make([]Claim, 0, len(claims))
	for _, c := range claims {
		c.Value = strings.TrimSpace(c.Value)
		if c.Value == "" {
			continue
		}
		cs = append(cs, c)
	}
	if len(cs) == 0 {
		return Resolution{Fact: fact}, false
	}
	sort.SliceStable(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		if ra, rb := rank(order, a.Class), rank(order, b.Class); ra != rb {
			return ra < rb
		}
		if !a.At.Equal(b.At) {
			return a.At.After(b.At) // the more recent reading first
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.RecordID < b.RecordID
	})
	win := cs[0]
	res := Resolution{Fact: fact, Value: win.Value, Winner: win, Considered: cs}
	wn := Normalize(fact, win.Value)
	for _, c := range cs[1:] {
		if Normalize(fact, c.Value) == wn {
			continue
		}
		res.Disagreements = append(res.Disagreements, c)
		if rank(order, c.Class) == rank(order, win.Class) {
			res.TieBroken = true
		}
	}
	return res, true
}

// ClaimsOf extracts every fact's claims from a device's per-source records
// (the records the inventory merged into one device). The version and serial
// are classified by their OWN provenance when the record carries one, so an
// operator-typed version on an SNMP row is manual, not discovered.
func ClaimsOf(records []models.Device) map[Fact][]Claim {
	out := make(map[Fact][]Claim, len(Facts()))
	for _, d := range records {
		rc := ClassOfRecord(d.Source)
		src := strings.ToLower(strings.TrimSpace(d.Source))
		add := func(f Fact, cl Class, source, v string, at time.Time) {
			if strings.TrimSpace(v) == "" {
				return
			}
			out[f] = append(out[f], Claim{Class: cl, Source: source, RecordID: d.ID, Value: v, At: at})
		}
		add(FactVendor, rc, src, d.Vendor, d.LastSeen)
		add(FactModel, rc, src, d.Model, d.LastSeen)
		if d.OSVersion != "" {
			add(FactSoftwareVersion, fieldClass(rc, d.OSVersionSource), fieldSource(src, d.OSVersionSource), d.OSVersion, firstTime(d.OSVersionAt, d.LastSeen))
		}
		switch {
		case d.SerialNumber != "":
			add(FactSerial, fieldClass(rc, d.SerialSource), fieldSource(src, d.SerialSource), d.SerialNumber, firstTime(d.SerialAt, d.LastSeen))
		case d.Labels["serial"] != "":
			// The importer's / controller's serial label: the record's own class.
			add(FactSerial, rc, src, d.Labels["serial"], d.LastSeen)
		}
	}
	return out
}

// fieldClass is the class of a version/serial: its own provenance when it has
// one; an empty provenance is manual — EXCEPT on a controller or NetBox record,
// whose fields that source itself wrote. On a NetBox record "manual" is the
// importer's own stamp (models.Device: "an operator, an inventory file or an
// importer"), so it stays declared.
func fieldClass(record Class, fieldSrc string) Class {
	s := strings.ToLower(strings.TrimSpace(fieldSrc))
	if record == ClassDeclared && (s == "" || s == "manual") {
		return ClassDeclared
	}
	if s == "" && record == ClassController {
		return ClassController
	}
	return ClassOfField(fieldSrc)
}

func fieldSource(recordSrc, fieldSrc string) string {
	if s := strings.ToLower(strings.TrimSpace(fieldSrc)); s != "" {
		return s
	}
	return recordSrc
}

func firstTime(ts ...time.Time) time.Time {
	for _, t := range ts {
		if !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

// ResolveDevice decides every fact of one device. Facts no source reported
// are absent.
func ResolveDevice(order []Class, records []models.Device) []Resolution {
	claims := ClaimsOf(records)
	out := make([]Resolution, 0, len(Facts()))
	for _, f := range Facts() {
		if r, ok := Resolve(order, f, claims[f]); ok {
			out = append(out, r)
		}
	}
	return out
}

// ── normalisation: agreement is not noise ────────────────────────────────────

// vendorNoise are corporate suffixes that do not change who the vendor is.
var vendorNoise = map[string]bool{
	"inc": true, "incorporated": true, "corp": true, "corporation": true, "co": true, "company": true,
	"ltd": true, "limited": true, "llc": true, "gmbh": true, "ag": true, "sa": true, "plc": true,
	"systems": true, "networks": true, "networking": true, "technologies": true, "technology": true,
}

// Normalize maps a value to the form two sources must share to AGREE: case and
// punctuation never make a disagreement; for the vendor, corporate suffixes
// ("Cisco Systems, Inc." = "cisco"); for the version, leading zeros and
// trailing zero components ("17.03.04.0" = "17.3.4").
func Normalize(f Fact, v string) string {
	toks := tokens(v)
	switch f {
	case FactVendor:
		kept := toks[:0:0]
		for _, t := range toks {
			if !vendorNoise[t] {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			kept = toks
		}
		return strings.Join(kept, "")
	case FactSoftwareVersion:
		for i, t := range toks {
			if trimmed := strings.TrimLeft(t, "0"); trimmed != t && isDigits(t) {
				if trimmed == "" {
					trimmed = "0"
				}
				toks[i] = trimmed
			}
		}
		for len(toks) > 1 && toks[len(toks)-1] == "0" {
			toks = toks[:len(toks)-1]
		}
		return strings.Join(toks, ".")
	}
	return strings.Join(toks, "")
}

// tokens lower-cases v and splits it on everything that is not a letter or a
// digit.
func tokens(v string) []string {
	return strings.FieldsFunc(strings.ToLower(v), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// ── rendering: plain text, untrusted values made inert ───────────────────────

// MaxValueRunes caps one rendered value.
const MaxValueRunes = 64

// Clean makes a device-supplied value safe to put in an answer: control and
// invisible format characters (bidi overrides, zero-width) are dropped,
// whitespace is collapsed, and the value is capped at max runes. The result is
// plain text — the SPA renders it escaped (§15), never as markup.
func Clean(v string, max int) string {
	out := make([]rune, 0, len(v))
	space := false
	for _, r := range v {
		if r == utf8.RuneError || unicode.Is(unicode.Cf, r) || (unicode.IsControl(r) && !unicode.IsSpace(r)) {
			continue
		}
		if unicode.IsSpace(r) {
			space = len(out) > 0
			continue
		}
		if space {
			out = append(out, ' ')
			space = false
		}
		out = append(out, r)
	}
	if max > 0 && len(out) > max {
		return strings.TrimRight(string(out[:max]), " ") + "…"
	}
	return string(out)
}

// FactText is one fact for the inventory line: "software version 20.6.1
// (from the controller (vmanage))".
func FactText(r Resolution) string {
	return fmt.Sprintf("%s %s (from %s)", FactLabel(r.Fact), Clean(r.Value, MaxValueRunes), SourceText(r.Winner))
}

// ContestedValues are the cleaned values of every fact the sources disagree on
// — winners and losers. An answer that states one of them must also state the
// disagreement (ai.EnsureDisagreementStated).
func ContestedValues(rs []Resolution) []string {
	var out []string
	for _, r := range rs {
		if !r.Disagreed() {
			continue
		}
		out = append(out, Clean(r.Value, MaxValueRunes))
		for _, c := range r.Disagreements {
			out = append(out, Clean(c.Value, MaxValueRunes))
		}
	}
	return out
}

// DisagreementText explains one disagreeing fact — which source won, by which
// order, and what every other source said. "" when the sources agreed.
func DisagreementText(r Resolution, order []Class, customized bool) string {
	if !r.Disagreed() {
		return ""
	}
	var others []string
	for _, c := range r.Disagreements {
		others = append(others, fmt.Sprintf("%s reports %s", SourceText(c), Clean(c.Value, MaxValueRunes)))
	}
	whose := "the platform default source order"
	if customized {
		whose = "this workspace's source order"
	}
	why := fmt.Sprintf("%s ranks first under %s (%s)", SourceText(r.Winner), whose, OrderText(order))
	if r.TieBroken {
		why += "; two sources of the same rank disagreed, so the more recent reading was used"
	}
	return fmt.Sprintf("Sources disagree on the %s: using %s from %s — %s; %s.",
		FactLabel(r.Fact), Clean(r.Value, MaxValueRunes), SourceText(r.Winner), why, strings.Join(others, "; "))
}

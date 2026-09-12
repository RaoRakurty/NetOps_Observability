// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package vuln owns the vulnerability advisory feed (build-order #13): loading
// the operator-provisioned CSV and matching a device's OS (vendor, product,
// version) against it. The HTTP surface (/api/vulns) stays in package main;
// this package is the data and the matching logic only.
//
// The feed follows the Geo IP pattern (#8): we cannot bundle or auto-download
// vulnerability data (offline-first stack, no phoning home), so the operator
// runs scripts/vuln-feed-prepare.py against NVD JSON (+ optionally the CISA
// KEV catalog) which writes a compact CSV under data/vuln/ — mounted into
// this container at /data/vuln/advisories.csv (VULN_FEED_PATH). The feed
// lazy-loads on first request and hot-reloads when the file's mtime changes,
// so re-running the script lights the board up on its next refresh — no
// restarts. Until the file exists, /api/vulns answers {"vuln_enabled":false}
// and the UI renders onboarding guidance instead of a false "no findings".
package vuln

import (
	"encoding/csv"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Entry is one applicability row: a CVE × (vendor, product) × version
// constraint. Version fields mirror NVD cpeMatch semantics: either Exact is
// set (a single affected version) or any subset of the four range bounds.
type Entry struct {
	Vendor    string  `json:"vendor"`
	Product   string  `json:"product"`
	CVE       string  `json:"cve"`
	Severity  string  `json:"severity"` // critical|high|medium|low|none
	CVSS      float64 `json:"cvss"`
	Exact     string  `json:"-"`
	StartIncl string  `json:"-"`
	StartExcl string  `json:"-"`
	EndIncl   string  `json:"-"`
	EndExcl   string  `json:"-"`
	KEV       bool    `json:"kev"` // listed in CISA Known Exploited Vulnerabilities
	Published string  `json:"published"`
	Summary   string  `json:"summary"`
}

const (
	maxEntries = 500_000 // hard cap on feed rows (bounded memory, §9)
	maxSummary = 280     // summary chars kept per row
)

// Logf is an injected structured-log sink (the internal/vault.Warnf idiom):
// this package reports load failures and truncation without knowing how the
// platform logs. nil is tolerated and means discard.
type Logf func(msg string, fields map[string]any)

// Feed owns the loaded advisory data. All access goes through Match()/
// Info(); Ensure() re-reads the CSV when the file changes underneath us.
type Feed struct {
	path string
	warn Logf
	info Logf

	mu      sync.RWMutex
	mtime   time.Time
	loaded  bool
	entries int
	kev     int
	byKey   map[string][]Entry // "vendor/normalized-product" → entries
}

func NewFeed(path string, warn, info Logf) *Feed {
	discard := func(string, map[string]any) {}
	if warn == nil {
		warn = discard
	}
	if info == nil {
		info = discard
	}
	return &Feed{path: path, warn: warn, info: info}
}

// Ensure returns true when a feed file is present and parsed (reloading it if
// its mtime moved). A missing/unreadable file means "not provisioned yet" —
// callers surface onboarding, never an empty result.
func (f *Feed) Ensure() bool {
	st, err := os.Stat(f.path)
	if err != nil {
		f.mu.Lock()
		f.loaded, f.byKey = false, nil
		f.mu.Unlock()
		return false
	}
	f.mu.RLock()
	fresh := f.loaded && st.ModTime().Equal(f.mtime)
	f.mu.RUnlock()
	if fresh {
		return true
	}
	byKey, total, kev, err := f.loadCSV()
	if err != nil {
		f.warn("vuln feed unreadable", map[string]any{"path": f.path, "err": err.Error()})
		return false
	}
	f.mu.Lock()
	f.mtime, f.loaded, f.byKey, f.entries, f.kev = st.ModTime(), true, byKey, total, kev
	f.mu.Unlock()
	f.info("vuln feed loaded", map[string]any{"path": f.path, "entries": total, "kev": kev})
	return true
}

func (f *Feed) Info() (entries, kev int, updated time.Time) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.entries, f.kev, f.mtime
}

// Match returns the advisories applying to one (vendor, product, version).
func (f *Feed) Match(vendor, product, version string) []Entry {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var out []Entry
	for _, e := range f.byKey[vendor+"/"+NormProduct(product)] {
		if versionMatches(version, e) {
			out = append(out, e)
		}
	}
	return out
}

// loadCSV parses the prepared feed. Header (written by
// scripts/vuln-feed-prepare.py):
//
//	vendor,product,cve,severity,cvss,ver_start_incl,ver_start_excl,ver_end_incl,ver_end_excl,ver_exact,kev,published,summary
//
// Operator-supplied, but still untrusted input (§3): rows are validated,
// bounded, and anything malformed is skipped rather than trusted.
func (f *Feed) loadCSV() (map[string][]Entry, int, int, error) {
	fh, err := os.Open(f.path)
	if err != nil {
		return nil, 0, 0, err
	}
	defer fh.Close()
	rd := csv.NewReader(fh)
	rd.FieldsPerRecord = 13
	if _, err := rd.Read(); err != nil { // header
		return nil, 0, 0, err
	}
	byKey := make(map[string][]Entry)
	total, kev := 0, 0
	for {
		rec, err := rd.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, 0, 0, err
		}
		if total >= maxEntries {
			f.warn("vuln feed truncated at cap", map[string]any{"cap": maxEntries})
			break
		}
		e := Entry{
			Vendor: strings.ToLower(strings.TrimSpace(rec[0])), Product: strings.TrimSpace(rec[1]),
			CVE: strings.TrimSpace(rec[2]), Severity: strings.ToLower(strings.TrimSpace(rec[3])),
			StartIncl: rec[5], StartExcl: rec[6], EndIncl: rec[7], EndExcl: rec[8], Exact: rec[9],
			Published: rec[11], Summary: rec[12],
		}
		if e.Vendor == "" || e.Product == "" || !strings.HasPrefix(e.CVE, "CVE-") {
			continue
		}
		e.CVSS, _ = strconv.ParseFloat(rec[4], 64) // best-effort: malformed CVSS parses as 0
		e.KEV = rec[10] == "1" || rec[10] == "true"
		if len(e.Summary) > maxSummary {
			e.Summary = e.Summary[:maxSummary] + "…"
		}
		key := e.Vendor + "/" + NormProduct(e.Product)
		byKey[key] = append(byKey[key], e)
		total++
		if e.KEV {
			kev++
		}
	}
	return byKey, total, kev, nil
}

// productAlias folds CPE product names whose normalized form still differs
// from what ParseOS emits (most differences are punctuation-only and vanish
// under NormProduct).
var productAlias = map[string]string{
	"adaptivesecurityappliancesoftware": "asa",
	"sr_os":                             "sros",
	"timos":                             "sros",
}

// NormProduct lowercases and strips non-alphanumerics so ios-xe / ios_xe /
// "IOS XE" all key identically, then applies the alias fold.
func NormProduct(p string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(p) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	n := b.String()
	if a, ok := productAlias[n]; ok {
		return a
	}
	if a, ok := productAlias[strings.ToLower(p)]; ok {
		return a
	}
	return n
}

// ── version comparison ───────────────────────────────────────────────────────
// Network-OS versions are not semver: "15.2(4)E10", "21.4R3-S4.9", "4.33.1F".
// We tokenize into digit/letter runs and compare element-wise — numeric runs
// numerically, letter runs lexically — the same heuristic RPM/dpkg use, which
// orders every real release train we carry correctly.

func versionTokens(v string) []string {
	v = strings.ToLower(v)
	var toks []string
	var cur strings.Builder
	var curDigit bool
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			if cur.Len() > 0 && !curDigit {
				flush()
			}
			curDigit = true
			cur.WriteRune(r)
		case r >= 'a' && r <= 'z':
			if cur.Len() > 0 && curDigit {
				flush()
			}
			curDigit = false
			cur.WriteRune(r)
		default: // separators: . - ( ) _ space …
			flush()
		}
	}
	flush()
	return toks
}

// CompareVersions returns -1/0/1. Fewer tokens with an equal prefix sorts
// lower (4.33 < 4.33.1); a numeric token sorts below a letter token at the
// same position (15.2 < 15.2e — a lettered train extends the base release).
func CompareVersions(a, b string) int {
	at, bt := versionTokens(a), versionTokens(b)
	for i := 0; i < len(at) && i < len(bt); i++ {
		x, y := at[i], bt[i]
		xn, xerr := strconv.Atoi(x)
		yn, yerr := strconv.Atoi(y)
		switch {
		case xerr == nil && yerr == nil:
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
		case xerr == nil: // number vs letters
			return -1
		case yerr == nil:
			return 1
		default:
			if x != y {
				if x < y {
					return -1
				}
				return 1
			}
		}
	}
	switch {
	case len(at) < len(bt):
		return -1
	case len(at) > len(bt):
		return 1
	}
	return 0
}

// versionMatches applies one entry's constraint to a device version. Exact
// matches tolerate a trailing *numeric* build suffix on the device (JunOS
// "21.4R3-S4.9" is a build of the advisory's "21.4r3-s4") but never a lettered
// one ("17.9.4a" is NOT the advisory's "17.9.4" — it's a separate rebuild).
func versionMatches(v string, e Entry) bool {
	if v == "" {
		return false
	}
	if e.Exact != "" {
		return exactWithBuildSuffix(v, e.Exact)
	}
	if e.StartIncl == "" && e.StartExcl == "" && e.EndIncl == "" && e.EndExcl == "" {
		return false // a row with no constraint matches nothing, not everything
	}
	if e.StartIncl != "" && CompareVersions(v, e.StartIncl) < 0 {
		return false
	}
	if e.StartExcl != "" && CompareVersions(v, e.StartExcl) <= 0 {
		return false
	}
	if e.EndIncl != "" && CompareVersions(v, e.EndIncl) > 0 {
		return false
	}
	if e.EndExcl != "" && CompareVersions(v, e.EndExcl) >= 0 {
		return false
	}
	return true
}

func exactWithBuildSuffix(device, advisory string) bool {
	dt, at := versionTokens(device), versionTokens(advisory)
	if len(dt) < len(at) {
		return false
	}
	for i := range at {
		if dt[i] != at[i] {
			return false
		}
	}
	for _, extra := range dt[len(at):] {
		if _, err := strconv.Atoi(extra); err != nil {
			return false
		}
	}
	return true
}

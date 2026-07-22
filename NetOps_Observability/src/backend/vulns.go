package main

import (
	"encoding/csv"
	"errors"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"netops/backend/collectors"
)

// vulns.go — Vulnerability Management (build-order #13): match each device's
// OS (vendor from sysObjectID, product+version parsed from sysDescr by
// collectors.ParseOS) against an operator-provisioned advisory feed.
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

// vulnEntry is one applicability row: a CVE × (vendor, product) × version
// constraint. Version fields mirror NVD cpeMatch semantics: either Exact is
// set (a single affected version) or any subset of the four range bounds.
type vulnEntry struct {
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
	vulnMaxEntries = 500_000 // hard cap on feed rows (bounded memory, §9)
	vulnMaxSummary = 280     // summary chars kept per row
)

// vulnFeed owns the loaded advisory data. All access goes through match()/
// info(); ensure() re-reads the CSV when the file changes underneath us.
type vulnFeed struct {
	path string

	mu      sync.RWMutex
	mtime   time.Time
	loaded  bool
	entries int
	kev     int
	byKey   map[string][]vulnEntry // "vendor/normalized-product" → entries
}

func newVulnFeed(path string) *vulnFeed { return &vulnFeed{path: path} }

// ensure returns true when a feed file is present and parsed (reloading it if
// its mtime moved). A missing/unreadable file means "not provisioned yet" —
// callers surface onboarding, never an empty result.
func (f *vulnFeed) ensure() bool {
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
	byKey, total, kev, err := loadVulnCSV(f.path)
	if err != nil {
		logWarn("vulns", "vuln feed unreadable", map[string]any{"path": f.path, "err": err.Error()})
		return false
	}
	f.mu.Lock()
	f.mtime, f.loaded, f.byKey, f.entries, f.kev = st.ModTime(), true, byKey, total, kev
	f.mu.Unlock()
	logInfo("vulns", "vuln feed loaded", map[string]any{"path": f.path, "entries": total, "kev": kev})
	return true
}

func (f *vulnFeed) info() (entries, kev int, updated time.Time) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.entries, f.kev, f.mtime
}

// match returns the advisories applying to one (vendor, product, version).
func (f *vulnFeed) match(vendor, product, version string) []vulnEntry {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var out []vulnEntry
	for _, e := range f.byKey[vendor+"/"+normProduct(product)] {
		if versionMatches(version, e) {
			out = append(out, e)
		}
	}
	return out
}

// loadVulnCSV parses the prepared feed. Header (written by
// scripts/vuln-feed-prepare.py):
//
//	vendor,product,cve,severity,cvss,ver_start_incl,ver_start_excl,ver_end_incl,ver_end_excl,ver_exact,kev,published,summary
//
// Operator-supplied, but still untrusted input (§3): rows are validated,
// bounded, and anything malformed is skipped rather than trusted.
func loadVulnCSV(path string) (map[string][]vulnEntry, int, int, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, 0, 0, err
	}
	defer fh.Close()
	rd := csv.NewReader(fh)
	rd.FieldsPerRecord = 13
	if _, err := rd.Read(); err != nil { // header
		return nil, 0, 0, err
	}
	byKey := make(map[string][]vulnEntry)
	total, kev := 0, 0
	for {
		rec, err := rd.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, 0, 0, err
		}
		if total >= vulnMaxEntries {
			logWarn("vulns", "vuln feed truncated at cap", map[string]any{"cap": vulnMaxEntries})
			break
		}
		e := vulnEntry{
			Vendor: strings.ToLower(strings.TrimSpace(rec[0])), Product: strings.TrimSpace(rec[1]),
			CVE: strings.TrimSpace(rec[2]), Severity: strings.ToLower(strings.TrimSpace(rec[3])),
			StartIncl: rec[5], StartExcl: rec[6], EndIncl: rec[7], EndExcl: rec[8], Exact: rec[9],
			Published: rec[11], Summary: rec[12],
		}
		if e.Vendor == "" || e.Product == "" || !strings.HasPrefix(e.CVE, "CVE-") {
			continue
		}
		e.CVSS, _ = strconv.ParseFloat(rec[4], 64)
		e.KEV = rec[10] == "1" || rec[10] == "true"
		if len(e.Summary) > vulnMaxSummary {
			e.Summary = e.Summary[:vulnMaxSummary] + "…"
		}
		key := e.Vendor + "/" + normProduct(e.Product)
		byKey[key] = append(byKey[key], e)
		total++
		if e.KEV {
			kev++
		}
	}
	return byKey, total, kev, nil
}

// vulnProductAlias folds CPE product names whose normalized form still differs
// from what ParseOS emits (most differences are punctuation-only and vanish
// under normProduct).
var vulnProductAlias = map[string]string{
	"adaptivesecurityappliancesoftware": "asa",
	"sr_os":                             "sros",
	"timos":                             "sros",
}

// normProduct lowercases and strips non-alphanumerics so ios-xe / ios_xe /
// "IOS XE" all key identically, then applies the alias fold.
func normProduct(p string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(p) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	n := b.String()
	if a, ok := vulnProductAlias[n]; ok {
		return a
	}
	if a, ok := vulnProductAlias[strings.ToLower(p)]; ok {
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

// compareVersions returns -1/0/1. Fewer tokens with an equal prefix sorts
// lower (4.33 < 4.33.1); a numeric token sorts below a letter token at the
// same position (15.2 < 15.2e — a lettered train extends the base release).
func compareVersions(a, b string) int {
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
func versionMatches(v string, e vulnEntry) bool {
	if v == "" {
		return false
	}
	if e.Exact != "" {
		return exactWithBuildSuffix(v, e.Exact)
	}
	if e.StartIncl == "" && e.StartExcl == "" && e.EndIncl == "" && e.EndExcl == "" {
		return false // a row with no constraint matches nothing, not everything
	}
	if e.StartIncl != "" && compareVersions(v, e.StartIncl) < 0 {
		return false
	}
	if e.StartExcl != "" && compareVersions(v, e.StartExcl) <= 0 {
		return false
	}
	if e.EndIncl != "" && compareVersions(v, e.EndIncl) > 0 {
		return false
	}
	if e.EndExcl != "" && compareVersions(v, e.EndExcl) >= 0 {
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

// ── HTTP ─────────────────────────────────────────────────────────────────────

type vulnFinding struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	Vendor     string `json:"vendor"`
	Product    string `json:"product"`
	Version    string `json:"version"`
	vulnEntry
}

type vulnUnassessed struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	Vendor     string `json:"vendor,omitempty"`
	Reason     string `json:"reason"`
}

var sevRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

// handleVulns — GET /api/vulns. Tenant-scoped (visibleDevices) fleet
// assessment against the loaded feed.
func (s *server) handleVulns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	if !s.vulns.ensure() {
		writeJSON(w, http.StatusOK, map[string]any{"vuln_enabled": false})
		return
	}
	// F-79: the read used to be limit-only with a hard ceiling of 2,000 and no
	// offset, so with 7,560 findings live, 5,560 of them were unreachable at ANY
	// limit — teams triaged 6.6% of fleet exposure believing it was all of it.
	// `offset` makes every finding reachable; the true total was already in
	// summary.findings and is now also on the headers/envelope alongside an
	// explicit `complete`. `unassessed` was fully unbounded — it is paged by the
	// same window and reports its own true total.
	if err := rejectUnknownQuery(r); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	page, err := parsePage(r, 500, 2000)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	devices := visibleDevices(s.discovery.Devices(), claims)
	// Stable device order → stable `unassessed` order → an offset walk that
	// reaches every row exactly once (the aggregator is map-backed).
	sort.Slice(devices, func(i, j int) bool { return devices[i].ID < devices[j].ID })
	findings := make([]vulnFinding, 0, 16)
	unassessed := make([]vulnUnassessed, 0, 8)
	assessed, affected := 0, 0
	critical, kevHits := 0, 0
	for _, d := range devices {
		if d.Vendor == "" {
			unassessed = append(unassessed, vulnUnassessed{DeviceID: d.ID, DeviceName: d.Name, Reason: "vendor unknown (SNMP unreachable or unrecognized sysObjectID)"})
			continue
		}
		osi := collectors.ParseOS(d.Vendor, d.OS)
		if osi.Product == "" || osi.Version == "" {
			unassessed = append(unassessed, vulnUnassessed{DeviceID: d.ID, DeviceName: d.Name, Vendor: d.Vendor, Reason: "OS version not present in sysDescr"})
			continue
		}
		assessed++
		hits := s.vulns.match(d.Vendor, osi.Product, osi.Version)
		if len(hits) == 0 {
			continue
		}
		affected++
		for _, e := range hits {
			if e.Severity == "critical" {
				critical++
			}
			if e.KEV {
				kevHits++
			}
			findings = append(findings, vulnFinding{
				DeviceID: d.ID, DeviceName: d.Name, Vendor: d.Vendor,
				Product: osi.Product, Version: osi.Version, vulnEntry: e,
			})
		}
	}
	// Worst first: KEV > severity > CVSS > newest CVE id.
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.KEV != b.KEV {
			return a.KEV
		}
		if sevRank[a.Severity] != sevRank[b.Severity] {
			return sevRank[a.Severity] > sevRank[b.Severity]
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		if a.CVE != b.CVE {
			return a.CVE > b.CVE
		}
		// F-79 total tiebreak: sort.Slice is NOT stable, so two findings equal on
		// (KEV, severity, CVSS, CVE) — the same CVE on two devices — could swap
		// order between two calls, and a client walking offsets would see one
		// twice and the other never. device_id makes the order total.
		return a.DeviceID < b.DeviceID
	})
	totalFindings := len(findings)
	totalUnassessed := len(unassessed)
	findings = pageSliceOf(findings, page)
	unassessed = pageSliceOf(unassessed, page)
	logTruncatedPage("/api/vulns", page, len(findings), totalFindings)
	entries, kevEntries, updated := s.vulns.info()
	writePageHeaders(w, page, len(findings), totalFindings)
	writeJSON(w, http.StatusOK, map[string]any{
		"vuln_enabled": true,
		"feed":         map[string]any{"entries": entries, "kev_entries": kevEntries, "updated_at": updated.UTC().Format(time.RFC3339)},
		"summary": map[string]any{
			"devices": len(devices), "assessed": assessed, "affected": affected,
			"findings": totalFindings, "critical": critical, "kev": kevHits,
		},
		"findings":   findings,
		"unassessed": unassessed,
		// The bounded-read contract, in-body (this endpoint has always been an
		// object, so it can carry it without an ?envelope=1 opt-in). `complete`
		// is the bit that used to be missing: 500 of 7,560 rows looked exactly
		// like "there are 500".
		"page": map[string]any{
			"limit": page.Limit, "offset": page.Offset, "max_limit": page.Max,
			"returned": len(findings), "total": totalFindings,
			"complete":           pageComplete(page, len(findings), totalFindings),
			"unassessed_total":   totalUnassessed,
			"unassessed_partial": !pageComplete(page, len(unassessed), totalUnassessed),
		},
	})
}

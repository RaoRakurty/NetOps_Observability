package backend

// vulns_http.go — the HTTP surface of Vulnerability Management (#13). The feed
// and all matching logic live in internal/vuln; this file is the tenant-scoped
// handler only (§2: the entrypoint package keeps wiring and HTTP).

import (
	"errors"
	"net/http"
	"sort"
	"time"

	"netops/backend/collectors"
	"netops/backend/internal/vuln"

	"netops/backend/internal/httppage"
)

type vulnFinding struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	Vendor     string `json:"vendor"`
	Product    string `json:"product"`
	Version    string `json:"version"`
	vuln.Entry
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
	if !s.vulns.Ensure() {
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
	if err := httppage.RejectUnknownQuery(r); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	page, err := httppage.Parse(r, 500, 2000)
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
		// Tracker 231: the version may come from the sysDescr OR from the row's
		// own os_version leaf, for a device whose version was learned over a
		// transport SNMP could not reach. One resolver, so this read and the
		// security lane's advisory findings can never disagree about a version.
		osi := collectors.ResolveDeviceOS(d.Vendor, d.OS, d.OSVersion)
		if osi.Product == "" || osi.Version == "" {
			unassessed = append(unassessed, vulnUnassessed{DeviceID: d.ID, DeviceName: d.Name, Vendor: d.Vendor,
				Reason: "OS version not present in sysDescr or os_version"})
			continue
		}
		assessed++
		hits := s.vulns.Match(d.Vendor, osi.Product, osi.Version)
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
				Product: osi.Product, Version: osi.Version, Entry: e,
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
	findings = httppage.SliceOf(findings, page)
	unassessed = httppage.SliceOf(unassessed, page)
	httppage.LogTruncated("/api/vulns", page, len(findings), totalFindings)
	entries, kevEntries, updated := s.vulns.Info()
	httppage.WriteHeaders(w, page, len(findings), totalFindings)
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
			"complete":           httppage.Complete(page, len(findings), totalFindings),
			"unassessed_total":   totalUnassessed,
			"unassessed_partial": !httppage.Complete(page, len(unassessed), totalUnassessed),
		},
	})
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// vulns_http.go — the HTTP surface of Vulnerability Management (#13). The feed
// and all matching logic live in internal/vuln; this file is the tenant-scoped
// handler only (§2: the entrypoint package keeps wiring and HTTP).

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"netops/backend/collectors"
	"netops/backend/internal/configstore"
	"netops/backend/internal/osprobe"
	"netops/backend/internal/vendorprofile"
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

// ─── OS-VERSION SOURCE LADDER (internal/osprobe) ─────────────────────────────
//
// This is the INPUT side of everything above. `/api/vulns` can only assess a
// device it has a version for, and until now the only version source was the
// SNMP sysDescr — so a device that answers no SNMP was reported UNASSESSED
// forever however reachable it was by other means (the reference lab's two SR
// Linux spines, which run no SNMP agent, are the worked example). The ladder
// asks every transport the platform ALREADY has credentials for, in a fixed
// order, and stamps the row with which one answered.
//
// The wiring lives beside the reader it serves, and it is deliberately thin:
// every rung is an adapter over a transport that already exists elsewhere in
// this binary, and a rung whose transport is not configured reports itself
// UNAVAILABLE rather than being silently absent.

// osProbeSysDescr adapts the SNMP identity read to the ladder's top rung. The
// community is read at PROBE time, not captured at boot, so an operator who
// changes it does not have to restart the process for the rung to follow.
func osProbeSysDescr(ctx context.Context, addr string) (string, string) {
	community := os.Getenv("SNMP_COMMUNITY")
	if community == "" {
		community = "public"
	}
	return collectors.DetectVendor(ctx, addr, community)
}

// osProbeSSHRunner adapts the config-capture SSH gateway — the SAME vendored
// client, the SAME pinned-host-key custody and the SAME least-privilege
// read-only account the config backup uses — to the ladder's CLI rung.
//
// It deliberately does NOT get its own credential path: a second read-only
// device account would be a second thing to rotate and a second thing to audit,
// and this rung runs strictly less than config capture already does (one
// `show version` instead of a whole running-config).
type osProbeSSHRunner struct {
	gw *configstore.SSHGateway
}

// Run implements osprobe.CommandRunner.
func (r osProbeSSHRunner) Run(ctx context.Context, t osprobe.Target, command string) (string, error) {
	if r.gw == nil {
		return "", osprobe.ErrNotConfigured
	}
	// An unset capture account is NOT a probe failure: the deployment simply has
	// no CLI rung. Reporting it as an error would put every device in the fleet
	// on the error counter and in the log once per cool-down, which is the noise
	// that makes a real failure invisible.
	if strings.TrimSpace(os.Getenv(configstore.EnvSSHUser)) == "" {
		return "", fmt.Errorf("%w: no config-capture SSH account configured", osprobe.ErrNotConfigured)
	}
	return r.gw.Run(ctx, configstore.Device{
		ID: t.DeviceID, Name: t.Name, Address: t.Address,
		Vendor: t.Vendor, OS: t.OSText, TenantID: t.TenantID,
		Port: envInt(configstore.EnvSSHPort, 22),
	}, command, osProbeMaxCommandBytes)
}

// osProbeMaxCommandBytes bounds ONE `show version` (§9). A version banner is
// kilobytes at most; this is headroom, not a target.
const osProbeMaxCommandBytes = 64 << 10

// buildOSVersionLadder constructs the ladder and hands it to discovery, which
// runs it on its own enrichment tick. A construction failure disables the
// FEATURE, not the process — the ladder is additive — but it is logged rather
// than swallowed, so an operator is never left wondering why no device ever
// learns a version (§10).
func (s *server) buildOSVersionLadder() {
	if s.discovery == nil {
		return
	}
	reg := vendorprofile.Default()
	ladder, err := osprobe.NewLadder(
		func(msg string, fields map[string]any) { logWarn("osprobe", msg, fields) },
		osprobe.NewSNMPSource(osProbeSysDescr),
		// The gNMI rung is DECLARED with no client. Correlix speaks gNMI through
		// the gnmic sidecar, which SUBSCRIBES and remote-writes samples to
		// VictoriaMetrics; it is not a Get client, and a Get client is gRPC +
		// protobuf, which the dependency rule (§6) does not admit today. Wiring
		// the rung anyway is the honest state: it reports itself UNAVAILABLE on
		// the metric for every device, so an operator can SEE that the ladder
		// has a rung nobody has connected, instead of the rung being invisible.
		// The profile data (paths + extraction patterns) is authored and tested,
		// so connecting a client is the only thing left.
		osprobe.NewGNMISource(nil, reg),
		osprobe.NewSSHSource(osProbeSSHRunner{gw: s.configGateway()}, reg),
	)
	if err != nil {
		logWarn("osprobe", "os-version ladder not wired", map[string]any{"error": err.Error()})
		return
	}
	s.discovery.SetOSVersionLadder(ladder)
}

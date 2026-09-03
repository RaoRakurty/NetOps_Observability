package hardening

// benchmark.go — PUBLISHED DEVICE-HARDENING BENCHMARK REFERENCES.
//
// WHY THIS FILE EXISTS (owner direction, 2026-09-03). The rules used to carry
// control tags of the form `CIS-NET-5.1` … `CIS-NET-9.3` alongside their 800-53
// ids. Those strings were neither controls nor framework ids: they were invented
// section numbers in a made-up "CIS-NET" namespace. Because the Compliance page
// builds its framework list from the distinct standards tags on findings, every
// one of them rendered as its own "framework" — a page listing thirty-odd CIS
// versions that do not exist, while HIPAA (a real projection, never a tag) never
// appeared at all.
//
// They are gone. A rule now carries ONLY canonical 800-53 control ids in
// Controls (frameworks are computed by PROJECTING those through
// internal/compliancemodel, so which frameworks a tenant sees is that tenant's
// choice — not a hard-coded tag), and its benchmark provenance lives here as an
// explicit, VERSIONED reference into a real published benchmark.
//
// WHAT IS VERIFIED (2026-09-03, cisecurity.org benchmark catalogue + benchmark
// PDF tables of contents):
//
//   - The current Cisco benchmarks are CIS Cisco IOS 17.x v2.0.0, CIS Cisco IOS
//     XE 17.x v2.2.1 (shipped August 2025), CIS Cisco IOS 16 v2.0.0, CIS Cisco
//     IOS XE 16.x v2.2.0, CIS Cisco NX-OS v1.2.0. There is NO current CIS Cisco
//     IOS 15 benchmark — v4.1.0 (2021-02-16) was the last and is archived.
//   - CIS Arista EOS Benchmark exists, at v1.0.0.
//   - The Juniper benchmark's modern title is CIS Juniper OS Benchmark, v2.1.0.
//     CIS announced in its August 2025 update an intent to ARCHIVE the Juniper
//     benchmarks (no SME support); the catalogue still lists v2.1.0, so the fact
//     is recorded rather than acted on.
//   - The Cisco IOS / IOS-XE section taxonomy is three planes and never exceeds
//     top-level 3 — which is the proof the old `CIS-NET-5.1` / `CIS-NET-9.3`
//     tags could not have been Cisco IOS sections. The subsection titles below
//     were read out of the benchmark PDFs' tables of contents.
//   - The Arista EOS and Cisco NX-OS section taxonomies could NOT be obtained
//     from a public document. They are therefore recorded UNVERIFIED and NO rule
//     claims a section in them — an unverified section number is exactly the
//     invention this file exists to remove.
//
// NOTHING HERE REDISTRIBUTES BENCHMARK TEXT. A reference is an id, a version and
// a published section heading — the citation, not the content.

import "sort"

// Benchmark is one published, versioned device-hardening benchmark.
type Benchmark struct {
	// ID is the stable slug used to reference this benchmark from a rule.
	ID string
	// Title is the benchmark's published title.
	Title string
	// Version is the current published version, e.g. "v2.2.1".
	Version string
	// Platform is the operating system family the benchmark governs.
	Platform string
	// SectionsVerified reports whether this benchmark's section taxonomy was
	// read from a published document. When false NO rule may cite a section of
	// it, and the UI says the benchmark is listed but not cited.
	SectionsVerified bool
	// Note carries provenance or a caveat an operator should know (an announced
	// archival, an unobtainable table of contents). Never marketing text.
	Note string
}

// Label renders the benchmark as an operator-readable citation prefix,
// e.g. "CIS Cisco IOS XE 17.x Benchmark v2.2.1".
func (b Benchmark) Label() string { return b.Title + " " + b.Version }

// SectionRef is one rule's citation INTO a benchmark: which benchmark, which
// published section, and that section's published heading. It is deliberately a
// SECTION and not a recommendation id — a recommendation id changes between
// benchmark versions, and citing one we have not read out of the exact version
// we pin would be the same invention the CIS-NET tags were.
type SectionRef struct {
	BenchmarkID string
	Section     string
	Title       string
}

// Benchmark ids.
const (
	BenchmarkCiscoIOS17   = "cis-cisco-ios-17"
	BenchmarkCiscoIOSXE17 = "cis-cisco-ios-xe-17"
	BenchmarkCiscoNXOS    = "cis-cisco-nx-os"
	BenchmarkAristaEOS    = "cis-arista-eos"
	BenchmarkJuniperOS    = "cis-juniper-os"
)

// Benchmarks returns the benchmark catalogue, id-ordered. Fresh slice per call
// (no package-level mutable state, §5).
func Benchmarks() []Benchmark {
	out := []Benchmark{
		{
			ID: BenchmarkCiscoIOSXE17, Title: "CIS Cisco IOS XE 17.x Benchmark", Version: "v2.2.1",
			Platform: "Cisco IOS-XE 17.x", SectionsVerified: true,
			Note: "Current as of 2026-09-03; v2.2.1 shipped in the CIS August 2025 update. Section headings read from the published table of contents.",
		},
		{
			ID: BenchmarkCiscoIOS17, Title: "CIS Cisco IOS 17.x Benchmark", Version: "v2.0.0",
			Platform: "Cisco IOS 17.x", SectionsVerified: true,
			Note: "Current as of 2026-09-03. Shares the three-plane section taxonomy with the IOS-XE benchmark. The CIS Cisco IOS 15 benchmark (v4.1.0, 2021) is archived and is not referenced.",
		},
		{
			ID: BenchmarkCiscoNXOS, Title: "CIS Cisco NX-OS Benchmark", Version: "v1.2.0",
			Platform: "Cisco NX-OS", SectionsVerified: false,
			Note: "Version current as of 2026-09-03; the section taxonomy could not be read from a published document, so no rule cites a section of it.",
		},
		{
			ID: BenchmarkAristaEOS, Title: "CIS Arista EOS Benchmark", Version: "v1.0.0",
			Platform: "Arista EOS", SectionsVerified: false,
			Note: "The only Arista benchmark CIS publishes; version current as of 2026-09-03. Its section taxonomy could not be read from a published document, so no rule cites a section of it.",
		},
		{
			ID: BenchmarkJuniperOS, Title: "CIS Juniper OS Benchmark", Version: "v2.1.0",
			Platform: "Juniper Junos", SectionsVerified: false,
			Note: "Version current as of 2026-09-03. CIS announced (August 2025) an intent to archive the Juniper benchmarks for lack of maintainer support; the catalogue still lists v2.1.0. No rule cites a section of it.",
		},
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ciscoIOSSections are the published Cisco IOS / IOS-XE benchmark sections the
// rules cite, keyed by section number. Both Cisco benchmarks share the taxonomy,
// so one table serves both.
var ciscoIOSSectionTitles = map[string]string{
	"1.1": "Local Authentication, Authorization and Accounting (AAA) Rules",
	"1.2": "Access Rules",
	"1.3": "Banner Rules",
	"1.4": "Password Rules",
	"1.5": "SNMP Rules",
	"1.6": "Login Enhancements",
	"2.1": "Global Service Rules",
	"2.2": "Logging Rules",
	"2.3": "NTP Rules",
	"2.4": "Loopback Rules",
	"3.1": "Routing Rules",
	"3.2": "Border Router Filtering",
	"3.3": "Neighbor Authentication",
}

// ruleBenchmarkSections maps a rule id onto the benchmark sections it evidences.
//
// A rule ABSENT from this table cites nothing, and that is a statement, not an
// omission: the concept has no section in a benchmark whose taxonomy we have
// read. Control-plane policing, model-driven-API TLS, mutual-TLS profiles and
// the EOS/SR Linux credential rules are all in that position — they map to
// 800-53 controls and to nothing else.
var ruleBenchmarkSections = map[string][]string{
	// ── 1 Management Plane ──────────────────────────────────────────────────
	"no-aaa-new-model":               {"1.1"},
	"telnet-vty-enabled":             {"1.2"},
	"ssh-not-v2":                     {"1.2"},
	"vty-no-access-class":            {"1.2"},
	"http-server-nontls":             {"1.2"},
	"http-no-source-acl":             {"1.2"},
	"no-service-password-encryption": {"1.4"},
	"weak-enable-password":           {"1.4"},
	"snmp-v1v2c-community":           {"1.5"},
	"snmp-default-community":         {"1.5"},
	"snmp-no-source-acl":             {"1.5"},
	// ── 2 Control Plane ─────────────────────────────────────────────────────
	"ftp-server-enabled":    {"2.1"},
	"tftp-server-enabled":   {"2.1"},
	"tcp-small-servers":     {"2.1"},
	"udp-small-servers":     {"2.1"},
	"finger-service":        {"2.1"},
	"bootp-server":          {"2.1"},
	"pad-service":           {"2.1"},
	"cdp-run-global":        {"2.1"},
	"no-central-logging":    {"2.2"},
	"ntp-no-authentication": {"2.3"},
	"no-ntp-server":         {"2.3"},
	// ── seam-aware exposure probes (same management-plane sections) ──────────
	"exposure-telnet": {"1.2"},
	"exposure-ssh":    {"1.2"},
	"exposure-http":   {"1.2"},
	"exposure-snmp":   {"1.5"},
}

// BenchmarkSections returns the published benchmark sections a rule or probe
// cites, in benchmark-id then section order. An unknown rule id, or one with no
// benchmark section, returns nil — never a placeholder.
//
// Both Cisco benchmarks share the taxonomy, so a cited section resolves against
// each of them; the caller renders whichever matches the device's platform.
func BenchmarkSections(ruleID string) []SectionRef {
	secs, ok := ruleBenchmarkSections[ruleID]
	if !ok || len(secs) == 0 {
		return nil
	}
	out := make([]SectionRef, 0, len(secs)*2)
	for _, bench := range []string{BenchmarkCiscoIOS17, BenchmarkCiscoIOSXE17} {
		for _, sec := range secs {
			title, known := ciscoIOSSectionTitles[sec]
			if !known {
				// A section number with no published heading is not cited: that
				// is precisely the invented reference this file removes.
				continue
			}
			out = append(out, SectionRef{BenchmarkID: bench, Section: sec, Title: title})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].BenchmarkID != out[j].BenchmarkID {
			return out[i].BenchmarkID < out[j].BenchmarkID
		}
		return out[i].Section < out[j].Section
	})
	return out
}

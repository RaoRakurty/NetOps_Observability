package threatlane

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"time"

	"netops/backend/internal/secfindings"
)

// DetectResult is the outcome of running one rule's detection. Tripped=true means
// the suspicious condition is present (the rule fires). Evidence is a short,
// operator-facing note describing WHAT tripped it — it becomes the finding's
// Observed field. It carries NO raw payload or secret (§3a/LLM06): a redacted
// summary only.
type DetectResult struct {
	Tripped  bool
	Evidence string
}

// LogRule is one hand-authored device-log detection: a single match over one
// normalized LogEvent, MITRE ATT&CK-tagged, that emits a "signal" finding when
// it fires. Rules are low-false-positive by construction — they key on vendor
// mnemonics and specific config-delta phrasing, not broad keywords.
type LogRule struct {
	// ID is the stable canonical rule id (also Finding.RawRuleID). It never
	// changes for a concept so historical findings stay joinable.
	ID string
	// Title is the human-facing detection name.
	Title string
	// Technique is the MITRE ATT&CK technique id (e.g. "T1562.001"); TechniqueName
	// is its human name. Together they populate ControlID/Standards/Detail.
	Technique     string
	TechniqueName string
	// Severity is one of the secfindings.Severity* constants — the weight of a
	// firing detection.
	Severity string
	// Verdict is the StatusID a firing detection emits (StatusFail for the
	// deterministic device-log matches; behavioral rules use StatusWarning).
	Verdict secfindings.StatusID
	// Controls are extra standards tags beyond the ATT&CK tag (e.g. a mapped
	// NIST 800-53 control). Optional.
	Controls []string
	// Intended is the vendor-neutral secure/expected state (Finding.Intended).
	Intended string
	// Remediation is the "what to do" guidance (Finding.Remediation).
	Remediation string
	// Detect runs the match over one normalized event. It NEVER panics on a
	// well-formed LogEvent and treats all fields as untrusted read-only input.
	Detect func(ev LogEvent) DetectResult
}

// Conversation is every flow between one (Src → Dst) pair, ordered by Start. It
// is the unit a PairRule (beaconing / exfil) reasons over.
type Conversation struct {
	Src      string
	Dst      string
	DeviceID string
	Hostname string
	TenantID string
	Flows    []FlowRecord // sorted ascending by Start
}

// SourceView is every flow originating from one Src (across all destinations). It
// is the unit a SourceRule (scan fan-out) reasons over.
type SourceView struct {
	Src      string
	DeviceID string
	Hostname string
	TenantID string
	Flows    []FlowRecord
}

// PairRule is a flow-behavioral detection over one Conversation. Its Detect
// closure captures the tuned Params at catalog-build time (no params threaded at
// call time, no package-level mutable state).
type PairRule struct {
	ID            string
	Title         string
	Technique     string
	TechniqueName string
	Severity      string
	Verdict       secfindings.StatusID
	Controls      []string
	Intended      string
	Remediation   string
	Detect        func(c Conversation) DetectResult
}

// SourceRule is a flow-behavioral detection over one SourceView.
type SourceRule struct {
	ID            string
	Title         string
	Technique     string
	TechniqueName string
	Severity      string
	Verdict       secfindings.StatusID
	Controls      []string
	Intended      string
	Remediation   string
	Detect        func(v SourceView) DetectResult
}

// Params tunes the behavioral detections and the off-hours window. It is passed
// once to NewCatalog and captured in the rule closures, so a deployment can tune
// thresholds without touching the engine and tests can pin exact values.
type Params struct {
	// ── off-hours config-change window ───────────────────────────────────────
	Location          *time.Location        // interpret event time in this zone
	BusinessStartHour int                   // inclusive [0,23]
	BusinessEndHour   int                   // exclusive (start,24]
	BusinessDays      map[time.Weekday]bool // days considered in-hours

	// ── beaconing ────────────────────────────────────────────────────────────
	BeaconMinSamples      int           // min flows in a conversation to assess
	BeaconMaxCV           float64       // max coefficient-of-variation of intervals
	BeaconMaxMeanInterval time.Duration // ignore conversations slower than this
	BeaconMaxBytesPerFlow uint64        // beacons are small; cap avg bytes/flow

	// ── exfil ────────────────────────────────────────────────────────────────
	ExfilMinBytes uint64 // min total egress to a single external peer to flag

	// ── scan fan-out ─────────────────────────────────────────────────────────
	ScanDistinctHosts int // >= this many distinct dst hosts → horizontal scan
	ScanDistinctPorts int // >= this many distinct dst ports → vertical scan
}

// DefaultParams returns conservative, low-false-positive defaults. They are the
// floor, tunable per deployment (memory: industry baselines are the floor).
func DefaultParams() Params {
	return Params{
		Location:          time.UTC,
		BusinessStartHour: 8,
		BusinessEndHour:   18,
		BusinessDays: map[time.Weekday]bool{
			time.Monday: true, time.Tuesday: true, time.Wednesday: true,
			time.Thursday: true, time.Friday: true,
		},
		BeaconMinSamples:      6,
		BeaconMaxCV:           0.10,
		BeaconMaxMeanInterval: 30 * time.Minute,
		BeaconMaxBytesPerFlow: 8192,
		ExfilMinBytes:         500 * 1024 * 1024, // 500 MiB to one external peer
		ScanDistinctHosts:     100,
		ScanDistinctPorts:     50,
	}
}

// normalize fills any zero-value Params field with its default, so a partially
// specified Params (common in tests and wiring) is always complete and the rule
// closures never divide by zero or read a nil map/location.
func (p Params) normalize() Params {
	d := DefaultParams()
	if p.Location == nil {
		p.Location = d.Location
	}
	if p.BusinessStartHour == 0 && p.BusinessEndHour == 0 {
		p.BusinessStartHour = d.BusinessStartHour
		p.BusinessEndHour = d.BusinessEndHour
	}
	if len(p.BusinessDays) == 0 {
		p.BusinessDays = d.BusinessDays
	}
	if p.BeaconMinSamples <= 0 {
		p.BeaconMinSamples = d.BeaconMinSamples
	}
	if p.BeaconMaxCV <= 0 {
		p.BeaconMaxCV = d.BeaconMaxCV
	}
	if p.BeaconMaxMeanInterval <= 0 {
		p.BeaconMaxMeanInterval = d.BeaconMaxMeanInterval
	}
	if p.BeaconMaxBytesPerFlow == 0 {
		p.BeaconMaxBytesPerFlow = d.BeaconMaxBytesPerFlow
	}
	if p.ExfilMinBytes == 0 {
		p.ExfilMinBytes = d.ExfilMinBytes
	}
	if p.ScanDistinctHosts <= 0 {
		p.ScanDistinctHosts = d.ScanDistinctHosts
	}
	if p.ScanDistinctPorts <= 0 {
		p.ScanDistinctPorts = d.ScanDistinctPorts
	}
	return p
}

// offHours reports whether t falls OUTSIDE the configured business window. A
// non-business day is entirely off-hours; on a business day, hours outside
// [BusinessStartHour, BusinessEndHour) are off-hours.
func (p Params) offHours(t time.Time) bool {
	lt := t.In(p.Location)
	if !p.BusinessDays[lt.Weekday()] {
		return true
	}
	h := lt.Hour()
	return h < p.BusinessStartHour || h >= p.BusinessEndHour
}

// Catalog is the immutable set of device-log rules + flow-behavioral rules. It is
// built fresh by NewCatalog/DefaultCatalog (no package-level mutable state, §5).
type Catalog struct {
	logRules    []LogRule
	pairRules   []PairRule
	sourceRules []SourceRule
}

// DefaultCatalog builds the standard catalog with DefaultParams.
func DefaultCatalog() *Catalog { return NewCatalog(DefaultParams()) }

// LogRules returns the device-log rules in authored order (defensive copy).
func (c *Catalog) LogRules() []LogRule {
	out := make([]LogRule, len(c.logRules))
	copy(out, c.logRules)
	return out
}

// PairRules returns the pair (conversation) behavioral rules (defensive copy).
func (c *Catalog) PairRules() []PairRule {
	out := make([]PairRule, len(c.pairRules))
	copy(out, c.pairRules)
	return out
}

// SourceRules returns the source-view behavioral rules (defensive copy).
func (c *Catalog) SourceRules() []SourceRule {
	out := make([]SourceRule, len(c.sourceRules))
	copy(out, c.sourceRules)
	return out
}

// Len reports the total number of rules across both families.
func (c *Catalog) Len() int {
	return len(c.logRules) + len(c.pairRules) + len(c.sourceRules)
}

// ─────────────────────────────────────────────────────────────────────────────
// Detection builders — each compiles its regexp ONCE at catalog-build time and
// returns a closure that captures it, so regexps are not package-level globals
// (§5 no-globals). A *regexp.Regexp is immutable and safe for concurrent use.
// ─────────────────────────────────────────────────────────────────────────────

// msgMatch trips when the normalized (mnemonic+message) text matches re.
func msgMatch(pattern string) func(LogEvent) DetectResult {
	re := regexp.MustCompile(pattern)
	return func(ev LogEvent) DetectResult {
		if re.MatchString(ev.normalized()) {
			return DetectResult{Tripped: true, Evidence: summarize(ev)}
		}
		return DetectResult{Tripped: false}
	}
}

// summarize renders a short, redacted one-line evidence string for a log event.
func summarize(ev LogEvent) string {
	msg := ev.Message
	if len(msg) > 240 {
		msg = msg[:240] + "…"
	}
	if ev.Mnemonic != "" {
		return ev.Mnemonic + ": " + msg
	}
	return msg
}

// NewCatalog builds the catalog with tuned params. The params are normalized and
// captured in the behavioral closures.
func NewCatalog(params Params) *Catalog {
	p := params.normalize()

	// ── device-log rules (hand-authored, low-FP, MITRE-tagged) ───────────────
	logRules := []LogRule{
		{
			ID: "log-logging-disabled", Title: "Logging disabled or redirected away",
			Technique: "T1562.001", TechniqueName: "Impair Defenses: Disable or Modify Tools",
			Severity: secfindings.SeverityHigh, Verdict: secfindings.StatusFail,
			Intended:    "Device logging to the central collector stays enabled at all times.",
			Remediation: "Re-enable logging (logging on / logging host <collector> / logging trap) and investigate who disabled it.",
			// Targets an ACTIVE disable of centralized logging. Deliberately does
			// NOT match "no logging console" (a hardening best-practice, not a
			// tamper) to keep the false-positive rate low.
			Detect: msgMatch(`\bno logging\s+(on|host|buffered|trap|monitor|server)\b|\blogging\b[^\n]*\bdisabled\b`),
		},
		{
			ID: "log-buffer-cleared", Title: "Log buffer cleared",
			Technique: "T1070", TechniqueName: "Indicator Removal",
			Severity: secfindings.SeverityMedium, Verdict: secfindings.StatusFail,
			Intended:    "Operators do not clear the on-box log buffer; retention is centralized.",
			Remediation: "Confirm the clear was authorized; ensure logs are shipped off-box so a local clear loses no evidence.",
			Detect:      msgMatch(`\bclear logging\b|\blogging (buffer )?(has been )?cleared\b`),
		},
		{
			ID: "log-offhours-config-change", Title: "Configuration change outside the change window",
			Technique: "T1059.008", TechniqueName: "Command and Scripting Interpreter: Network Device CLI",
			Severity: secfindings.SeverityMedium, Verdict: secfindings.StatusFail,
			Intended:    "Configuration changes occur only during the approved change window.",
			Remediation: "Correlate the change with an approved change ticket; if none exists, treat the session as suspect and review the actor.",
			Detect:      offHoursConfigChange(p),
		},
		{
			ID: "log-new-local-user", Title: "New local user account created",
			Technique: "T1136.001", TechniqueName: "Create Account: Local Account",
			Severity: secfindings.SeverityHigh, Verdict: secfindings.StatusFail,
			Intended:    "Local accounts are managed centrally (TACACS+/RADIUS); ad-hoc local users are not added.",
			Remediation: "Verify the account is authorized; remove unexpected local users and prefer centralized AAA.",
			Detect:      msgMatch(`\busername\s+\S+[^\n]*\b(secret|password)\b`),
		},
		{
			ID: "log-privilege-escalation", Title: "Privilege level elevated",
			Technique: "T1098", TechniqueName: "Account Manipulation",
			Severity: secfindings.SeverityHigh, Verdict: secfindings.StatusFail,
			Intended:    "Privilege-15 access is granted only to designated administrators.",
			Remediation: "Confirm the elevation is authorized; revoke unexpected privilege-15 grants.",
			Detect:      msgMatch(`\bprivilege\s+1[5-9]\b|\bprivilege level[^\n]*\bchanged\b`),
		},
		{
			ID: "log-gre-tunnel", Title: "GRE/tunnel interface created",
			Technique: "T1572", TechniqueName: "Protocol Tunneling",
			Severity: secfindings.SeverityHigh, Verdict: secfindings.StatusFail,
			Intended:    "Tunnel interfaces exist only where an approved design calls for them.",
			Remediation: "Verify the tunnel against the approved topology; an unexpected tunnel can exfiltrate traffic past controls — remove it.",
			Detect:      msgMatch(`\binterface\s+tunnel\d+\b|\btunnel\s+mode\s+gre\b`),
		},
		{
			ID: "log-aaa-tampering", Title: "Authentication weakened or bypassed",
			Technique: "T1556", TechniqueName: "Modify Authentication Process",
			Severity: secfindings.SeverityHigh, Verdict: secfindings.StatusFail,
			Intended:    "AAA enforces authentication on every access method; no login method is set to none.",
			Remediation: "Restore an authenticating AAA method list; never leave 'authentication ... none' on a reachable line.",
			Detect:      msgMatch(`\baaa authentication\b[^\n]*\bnone\b|\bno aaa authentication\b|\bauthentication\b[^\n]*\b(bypass|disabled)\b`),
		},
		{
			ID: "log-boot-image-change", Title: "Boot image / system image changed",
			Technique: "T1601", TechniqueName: "Modify System Image",
			Severity: secfindings.SeverityHigh, Verdict: secfindings.StatusFail,
			Intended:    "The boot image is pinned and changes only through the approved upgrade process.",
			Remediation: "Verify the image hash against the approved release; an unexpected boot-image change can be a persistent implant.",
			Detect:      msgMatch(`\bboot system\b|\bboot\b[^\n]*\bflash[^\n]*\.bin\b`),
		},
	}

	// ── flow-behavioral rules (heuristic → Warning, a triage signal) ─────────
	pairRules := []PairRule{
		{
			ID: "flow-beaconing", Title: "Periodic low-variance beaconing",
			Technique: "T1071", TechniqueName: "Application Layer Protocol",
			Severity: secfindings.SeverityMedium, Verdict: secfindings.StatusWarning,
			Intended:    "Internal hosts do not maintain clockwork periodic connections to a single external peer.",
			Remediation: "Investigate the internal host for C2 beaconing; correlate the peer against threat intel and block if malicious.",
			Detect:      beaconing(p),
		},
		{
			ID: "flow-exfil-egress", Title: "Volumetric egress to a rare external peer",
			Technique: "T1048", TechniqueName: "Exfiltration Over Alternative Protocol",
			Severity: secfindings.SeverityHigh, Verdict: secfindings.StatusWarning,
			Intended:    "Bulk data does not leave the network to unmanaged external destinations.",
			Remediation: "Verify the transfer is sanctioned; if not, contain the source host and block the destination.",
			Detect:      exfil(p),
		},
	}
	sourceRules := []SourceRule{
		{
			ID: "flow-scan-fanout", Title: "Host/port scan fan-out",
			Technique: "T1046", TechniqueName: "Network Service Discovery",
			Severity: secfindings.SeverityMedium, Verdict: secfindings.StatusWarning,
			Intended:    "A single source does not sweep many hosts or ports in a short window.",
			Remediation: "Identify the scanning source; if unsanctioned, isolate it and review what it reached.",
			Detect:      scanFanout(p),
		},
	}

	return &Catalog{logRules: logRules, pairRules: pairRules, sourceRules: sourceRules}
}

// offHoursConfigChange builds the off-hours config-change detection: it trips
// when the event is a configuration-change event AND its time is outside the
// business window. It compiles its config-change matcher once and captures p.
func offHoursConfigChange(p Params) func(LogEvent) DetectResult {
	re := regexp.MustCompile(`\bconfig_i\b|\bcfglog_loggedcmd\b|\bconfigured from\b|\bconfigured by\b`)
	return func(ev LogEvent) DetectResult {
		if !re.MatchString(ev.normalized()) {
			return DetectResult{Tripped: false}
		}
		if ev.Time.IsZero() || !p.offHours(ev.Time) {
			return DetectResult{Tripped: false}
		}
		return DetectResult{
			Tripped:  true,
			Evidence: fmt.Sprintf("%s (at %s, outside change window)", summarize(ev), ev.Time.In(p.Location).Format(time.RFC3339)),
		}
	}
}

// beaconing builds the periodic-beaconing detection over a conversation.
func beaconing(p Params) func(Conversation) DetectResult {
	return func(c Conversation) DetectResult {
		n := len(c.Flows)
		if n < p.BeaconMinSamples {
			return DetectResult{Tripped: false}
		}
		// Inter-arrival intervals (seconds) between consecutive flow starts.
		intervals := make([]float64, 0, n-1)
		var totalBytes uint64
		for i := 1; i < n; i++ {
			dt := c.Flows[i].Start.Sub(c.Flows[i-1].Start).Seconds()
			if dt < 0 {
				dt = 0 // non-decreasing by construction; guard anyway
			}
			intervals = append(intervals, dt)
		}
		for _, f := range c.Flows {
			totalBytes += f.Bytes
		}
		mean := meanOf(intervals)
		if mean <= 0 || time.Duration(mean*float64(time.Second)) > p.BeaconMaxMeanInterval {
			return DetectResult{Tripped: false}
		}
		cv := stddevOf(intervals, mean) / mean
		avgBytes := totalBytes / uint64(n)
		if cv <= p.BeaconMaxCV && avgBytes <= p.BeaconMaxBytesPerFlow {
			return DetectResult{
				Tripped: true,
				Evidence: fmt.Sprintf("%d flows %s→%s every ~%.0fs (CV=%.2f, avg %d bytes/flow)",
					n, c.Src, c.Dst, mean, cv, avgBytes),
			}
		}
		return DetectResult{Tripped: false}
	}
}

// exfil builds the volumetric-egress detection over a conversation: an internal
// source sending a large total volume to a single external destination.
func exfil(p Params) func(Conversation) DetectResult {
	return func(c Conversation) DetectResult {
		if !isInternalIP(c.Src) || !isExternalIP(c.Dst) {
			return DetectResult{Tripped: false}
		}
		var total uint64
		for _, f := range c.Flows {
			total += f.Bytes
		}
		if total >= p.ExfilMinBytes {
			return DetectResult{
				Tripped: true,
				Evidence: fmt.Sprintf("%d bytes egress %s→%s (external) across %d flows",
					total, c.Src, c.Dst, len(c.Flows)),
			}
		}
		return DetectResult{Tripped: false}
	}
}

// scanFanout builds the host/port scan detection over one source's flows.
func scanFanout(p Params) func(SourceView) DetectResult {
	return func(v SourceView) DetectResult {
		hosts := map[string]struct{}{}
		ports := map[int]struct{}{}
		for _, f := range v.Flows {
			hosts[f.DstAddr] = struct{}{}
			ports[f.DstPort] = struct{}{}
		}
		nh, np := len(hosts), len(ports)
		switch {
		case nh >= p.ScanDistinctHosts:
			return DetectResult{
				Tripped:  true,
				Evidence: fmt.Sprintf("source %s reached %d distinct hosts (horizontal scan)", v.Src, nh),
			}
		case np >= p.ScanDistinctPorts:
			return DetectResult{
				Tripped:  true,
				Evidence: fmt.Sprintf("source %s reached %d distinct ports (vertical scan)", v.Src, np),
			}
		default:
			return DetectResult{Tripped: false}
		}
	}
}

// meanOf returns the arithmetic mean of xs (0 for an empty slice).
func meanOf(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	return sum / float64(len(xs))
}

// stddevOf returns the population standard deviation of xs given its mean.
func stddevOf(xs []float64, mean float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var acc float64
	for _, x := range xs {
		d := x - mean
		acc += d * d
	}
	return math.Sqrt(acc / float64(len(xs)))
}

// sortedTechniques returns the sorted set of MITRE techniques the catalog covers
// (helper for tests and any coverage surface). Deterministic.
func (c *Catalog) sortedTechniques() []string {
	seen := map[string]struct{}{}
	for _, r := range c.logRules {
		seen[r.Technique] = struct{}{}
	}
	for _, r := range c.pairRules {
		seen[r.Technique] = struct{}{}
	}
	for _, r := range c.sourceRules {
		seen[r.Technique] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

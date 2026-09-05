// Package pipedebug is the shared model of the pipeline debugger
// (`correlix-debug`, docs/design/PIPELINE_DEBUGGER_2026-09-04.md).
//
// It holds the things the HOST-SIDE CLI (internal/pipedebug/cli, built as
// cmd/correlix-debug) and the SERVER-SIDE debug routes (registered by package
// backend inside the DEBUG-ROUTES markers in main.go) must agree on, and
// nothing else:
//
//   - the closed grammars — verb kinds, stage names, module names, the marker
//     shape, the TTL/window caps. They are CLOSED sets on purpose: every one of
//     them arrives from an untrusted caller (a CLI flag or an HTTP request) and
//     is then used to name a container, a topic, an index or a file (§3).
//   - the stage ORDER and the one-log-file-per-module mapping the design's §3
//     layout requires, so the CLI and the API cannot disagree about which file
//     a stage's evidence belongs in;
//   - the timeline/verdict vocabulary, including the honest third verdict
//     ("stage not observable, because …") that keeps an unobservable stage from
//     reading like a silent success (§10 — no silent failures).
//
// It deliberately owns NO transport: no HTTP client, no docker exec, no store
// query. Those live in the two consumers, over injected seams, so this package
// stays pure and unit-testable.
package pipedebug

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ── kinds ───────────────────────────────────────────────────────────────────

// Kind is the telemetry class a trace injects and follows.
//
// THREE OF THE FOUR ARE INJECTABLE and one is not, and the difference is a
// SAFETY rule rather than an implementation gap: syslog, trap and flow all have
// a wire form that can be sent to the STACK's own ingress socket, while gNMI is
// a dial-IN subscription served by the DEVICE. The only way to "inject" a gNMI
// update would be to write a leaf on a real router, so gNMI is passive-only
// (design §2) and PassiveOnly below is what enforces it in code.
type Kind string

const (
	KindSyslog Kind = "syslog"
	KindTrap   Kind = "trap"
	// KindFlow is a NetFlow v5 record sent to the stack's own goflow2 listener.
	// A flow record has NO free-text field, so the marker cannot travel inside
	// it as a string the way it does for syslog and trap; it travels instead as
	// a deterministic FLOW FINGERPRINT in RFC 5737 documentation address space
	// (see FlowFingerprint). That is a real difference in evidence quality and
	// the stage reasons say so rather than papering over it.
	KindFlow Kind = "flow"
	// KindGNMI follows REAL gNMI updates. It is never injected.
	KindGNMI Kind = "gnmi"
)

// Kinds is the CLOSED set of kinds this build accepts.
var Kinds = []Kind{KindSyslog, KindTrap, KindFlow, KindGNMI}

// PassiveOnly reports whether a kind can ONLY be followed passively.
//
// gNMI is the one such kind: a gNMI update originates on the device, so the
// only way to mint one would be to CONFIGURE a device — which the debugger
// never does (design §5, "no device is written to"). A `--passive` follow of
// real traffic is therefore not a degraded fallback for gNMI, it is the only
// correct mode, and the reverse (silently injecting when the caller asked for
// passive) is the failure this pair of predicates exists to make impossible.
func PassiveOnly(k Kind) bool { return k == KindGNMI }

// Injectable reports whether a kind has a wire form the debugger may send into
// the stack's own ingress.
func Injectable(k Kind) bool {
	switch k {
	case KindSyslog, KindTrap, KindFlow:
		return true
	default:
		return false
	}
}

// PassiveReason explains, for a kind that does NOT support passive following,
// why an exact marker is better evidence than passive matching would be.
func PassiveReason(k Kind) string {
	return fmt.Sprintf(
		"--passive is supported for gnmi only. A %s record carries an exact per-record marker, and matching real %s traffic by device alone could never prove that ONE record crossed a hop — it would prove only that SOME record did, which is a weaker claim reported in the same words. Run without --passive to follow a marked record end to end",
		k, k)
}

// ParseKind validates an untrusted kind string against the closed set.
func ParseKind(s string) (Kind, error) {
	k := Kind(strings.ToLower(strings.TrimSpace(s)))
	for _, want := range Kinds {
		if k == want {
			return k, nil
		}
	}
	return "", fmt.Errorf("unknown kind %q (this build traces %s)", s, joinKinds(Kinds))
}

func joinKinds(ks []Kind) string {
	parts := make([]string, 0, len(ks))
	for _, k := range ks {
		parts = append(parts, string(k))
	}
	return strings.Join(parts, "|")
}

// ── stages ──────────────────────────────────────────────────────────────────

// Stage is one hop of the pipeline. The value is ALSO the module log file's
// base name (design §3: one file per module), so there is exactly one mapping
// and no way for the CLI's file names to drift from the API's stage names.
type Stage string

const (
	StageIngress     Stage = "ingress"
	StageParser      Stage = "parser"
	StageKafka       Stage = "kafka"
	StageRouter      Stage = "router"
	StageOpenSearch  Stage = "opensearch"
	StageVictoria    Stage = "victoria"
	StageClickHouse  Stage = "clickhouse"
	StageCorrelation Stage = "correlation"
	StageAPI         Stage = "api"
	StageUI          Stage = "ui"
)

// Stages is the ORDERED pipeline (design §2, stages 1…8 — storage fans into
// three module files, so ten files for eight stages). The order is what
// timeline latencies are computed against; do not sort it.
var Stages = []Stage{
	StageIngress, StageParser, StageKafka, StageRouter,
	StageOpenSearch, StageVictoria, StageClickHouse,
	StageCorrelation, StageAPI, StageUI,
}

// ServerStages are the stages whose evidence the API gathers (the CLI cannot
// reach the stores or the bus from the host). The rest are host-side: docker
// logs and the Vector API tap.
var ServerStages = []Stage{
	StageKafka, StageOpenSearch, StageVictoria,
	StageClickHouse, StageCorrelation, StageAPI,
}

// ParseStage validates an untrusted stage string against the closed set.
func ParseStage(s string) (Stage, error) {
	st := Stage(strings.ToLower(strings.TrimSpace(s)))
	for _, want := range Stages {
		if st == want {
			return st, nil
		}
	}
	return "", fmt.Errorf("unknown stage %q", s)
}

// HybridStages are served by the API on DEMAND but are not polled by the async
// follow, because each one is only half the story:
//
//   - `parser` — the API holds the GO collectors' decision lines; the Vector
//     half comes from the host-side tap, and the CLI merges the two into one
//     parser.log and one timeline entry.
//   - `ui` — the UI-query contract needs the caller's *http.Request to resolve
//     the SAME tenant/visibility scope the real handler resolves (logsScope),
//     and the follow goroutine has no request. Running it on demand is not a
//     limitation: unlike a store write, the UI query answers the moment the
//     record is in the store, so there is nothing to poll for.
var HybridStages = []Stage{StageParser, StageUI}

// IsServerStage reports whether the API serves this stage's evidence.
func IsServerStage(s Stage) bool {
	for _, want := range ServerStages {
		if s == want {
			return true
		}
	}
	return false
}

// IsHybridStage reports whether the API answers this stage on demand.
func IsHybridStage(s Stage) bool {
	for _, want := range HybridStages {
		if s == want {
			return true
		}
	}
	return false
}

// LogFile is the per-module file name inside a session directory (design §3).
func (s Stage) LogFile() string { return string(s) + ".log" }

// StageIndex is the 1-based position of a stage in the pipeline, or 0 when the
// stage is unknown.
func StageIndex(s Stage) int {
	for i, want := range Stages {
		if s == want {
			return i + 1
		}
	}
	return 0
}

// ── modules (the `logs` verb) ───────────────────────────────────────────────

// Module names a runnable unit whose log stream the `logs` verb tails and whose
// level the `loglevel` route may raise. It is a CLOSED set because the name is
// used to select a container and to address a runtime-control endpoint.
type Module string

const (
	ModuleAPI         Module = "api"
	ModuleCorrelation Module = "correlation"
	ModuleVector      Module = "vector"
	ModuleRouter      Module = "router"
	ModuleIngress     Module = "ingress"
)

// Modules is the closed set the CLI and the loglevel route accept.
var Modules = []Module{ModuleAPI, ModuleCorrelation, ModuleVector, ModuleRouter, ModuleIngress}

// ParseModule validates an untrusted module string against the closed set.
func ParseModule(s string) (Module, error) {
	m := Module(strings.ToLower(strings.TrimSpace(s)))
	for _, want := range Modules {
		if m == want {
			return m, nil
		}
	}
	names := make([]string, 0, len(Modules))
	for _, want := range Modules {
		names = append(names, string(want))
	}
	return "", fmt.Errorf("unknown module %q (known: %s)", s, strings.Join(names, ", "))
}

// ParseModules splits and validates a comma-separated module list, rejecting
// duplicates so a caller cannot double-raise (and double-revert) one module.
func ParseModules(csv string) ([]Module, error) {
	parts := strings.Split(csv, ",")
	out := make([]Module, 0, len(parts))
	seen := map[Module]bool{}
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			continue
		}
		m, err := ParseModule(p)
		if err != nil {
			return nil, err
		}
		if seen[m] {
			return nil, fmt.Errorf("module %q listed twice", m)
		}
		seen[m] = true
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, errors.New("no modules given")
	}
	return out, nil
}

// ComposeService is the docker-compose service name that runs a module. The
// mapping is here, next to the closed set, so the CLI can never interpolate an
// operator string into a `docker` argv (§8: exec takes an argv list built from
// values that came out of THIS table, never from raw input).
func ComposeService(m Module) (string, bool) {
	switch m {
	case ModuleAPI:
		return "api", true
	case ModuleCorrelation:
		return "correlation", true
	case ModuleVector:
		return "vector-aggregator", true
	case ModuleRouter:
		return "vector-router", true
	case ModuleIngress:
		return "syslog-ng", true
	default:
		return "", false
	}
}

// ModuleStage maps a module onto the session log file it writes into, so the
// `logs` verb and the `trace` verb produce the SAME §3 layout — one file per
// module, with the same names, whichever verb created the session.
func ModuleStage(m Module) Stage {
	switch m {
	case ModuleAPI:
		return StageAPI
	case ModuleCorrelation:
		return StageCorrelation
	case ModuleVector:
		return StageParser
	case ModuleRouter:
		return StageRouter
	case ModuleIngress:
		return StageIngress
	default:
		return StageAPI
	}
}

// ── log levels ──────────────────────────────────────────────────────────────

// Level is the runtime log level a module may be moved to for a bounded window.
// Only two values exist: "debug" (raise) and "info" (the shipped default, i.e.
// revert). A wider ladder would invite a caller to LOWER a module below its
// operational level, which is a way to hide an incident, not to debug one.
type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
)

// ParseLevel validates an untrusted level string.
func ParseLevel(s string) (Level, error) {
	switch Level(strings.ToLower(strings.TrimSpace(s))) {
	case LevelDebug:
		return LevelDebug, nil
	case LevelInfo:
		return LevelInfo, nil
	default:
		return "", fmt.Errorf("unknown level %q (debug|info)", s)
	}
}

// ── bounds ──────────────────────────────────────────────────────────────────

const (
	// MaxWindow is the hard cap on any debug window: a raised log level and a
	// `logs` tail both auto-revert at or before this (design §4). It is a CAP,
	// not a default — the CLI's default is much shorter.
	MaxWindow = 30 * time.Minute
	// DefaultWindow is the `logs` verb's default tail/raise window.
	DefaultWindow = 5 * time.Minute
	// MaxTraceTTL bounds how long a trace waits for its marker to appear.
	MaxTraceTTL = 5 * time.Minute
	// DefaultTraceTTL is the per-stage wait a trace uses when none is given.
	DefaultTraceTTL = 60 * time.Second
	// MaxPassiveSince bounds how far back a `--passive` trace may look.
	MaxPassiveSince = 24 * time.Hour
)

// ClampWindow bounds a requested debug window into (0, MaxWindow]. A
// non-positive request becomes DefaultWindow rather than "forever": the one
// outcome this feature must never produce is a module left at debug (design §5).
func ClampWindow(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultWindow
	}
	if d > MaxWindow {
		return MaxWindow
	}
	return d
}

// ClampTraceTTL bounds a requested trace TTL into (0, MaxTraceTTL].
func ClampTraceTTL(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultTraceTTL
	}
	if d > MaxTraceTTL {
		return MaxTraceTTL
	}
	return d
}

// ── the marker ──────────────────────────────────────────────────────────────

// MarkerField is the key the marker is carried under, inside whatever free-text
// field the record's kind naturally has (design §2).
const MarkerField = "cx_debug"

// SyntheticField tags an injected record so customer-facing views can exclude
// it (design §4). It is a RESERVED token: a real device log containing it will
// also be hidden from the UI, which is the safe direction.
const SyntheticField = "cx_synthetic"

// SyntheticTag is the exact substring stamped into every injected record and
// filtered out of the UI-facing log queries.
const SyntheticTag = SyntheticField + "=true"

// markerAlphabet is Crockford base32 in LOWER case. Lower case because the
// marker travels inside an OpenSearch `text` field whose standard analyzer
// lower-cases every token — matching what is stored removes a whole class of
// "the record is there but the query does not find it" confusion.
const markerAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"

// MarkerLen is the ULID length in characters.
const MarkerLen = 26

// NewMarker mints a ULID-shaped marker: 10 characters of millisecond timestamp
// followed by 16 characters of crypto-random entropy, Crockford base32, lower
// case. Time-ordered so a session directory sorts chronologically.
func NewMarker(now time.Time) string {
	ms := uint64(now.UTC().UnixMilli()) // #nosec G115 -- wall clock is positive; a pre-1970 clock yields a valid-shaped marker, not a security decision
	b := make([]byte, MarkerLen)
	for i := 9; i >= 0; i-- {
		b[i] = markerAlphabet[ms%32]
		ms /= 32
	}
	rnd := make([]byte, MarkerLen-10)
	_, _ = rand.Read(rnd) // best-effort: crypto/rand.Read cannot fail (Go 1.24+ aborts the process instead), so there is no error path to report
	for i, v := range rnd {
		b[10+i] = markerAlphabet[int(v)%32]
	}
	return string(b)
}

// ValidMarker reports whether s is a well-formed marker. It is the ONLY gate a
// marker passes before being interpolated into a query, a file name or a
// container argv — the grammar is what makes those interpolations safe.
func ValidMarker(s string) bool {
	if len(s) != MarkerLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune(markerAlphabet, rune(s[i])) {
			return false
		}
	}
	return true
}

// NormalizeMarker lower-cases a marker and validates it, so an operator who
// pasted the canonical upper-case ULID still gets a usable value.
func NormalizeMarker(s string) (string, error) {
	m := strings.ToLower(strings.TrimSpace(s))
	if !ValidMarker(m) {
		return "", fmt.Errorf("marker must be %d Crockford base32 characters", MarkerLen)
	}
	return m, nil
}

// MarkerTag is the exact token embedded in an injected record's text.
func MarkerTag(marker string) string { return MarkerField + "=" + marker }

// ── verdicts ────────────────────────────────────────────────────────────────

// Verdict is a stage's honest outcome. There are exactly three, and the third
// exists so "we could not look" is never rendered as "it was not there".
type Verdict string

const (
	// VerdictSeen — the marker was observed at this stage.
	VerdictSeen Verdict = "seen"
	// VerdictNotSeen — the stage WAS observable and the marker was not there.
	VerdictNotSeen Verdict = "not_seen"
	// VerdictNotObservable — the stage could not be inspected at all. Always
	// carries a Reason.
	VerdictNotObservable Verdict = "not_observable"
)

// Entry is one stage of the timeline (design §2).
type Entry struct {
	Stage  Stage  `json:"stage"`
	Index  int    `json:"index"`
	Module string `json:"module"`
	Seen   bool   `json:"seen"`
	// FirstSeen is the stage's own timestamp for the record (zero when unseen).
	FirstSeen time.Time `json:"t_first_seen,omitempty"`
	// LatencyFromPrevMS is the wall-clock delta from the previous SEEN stage.
	// Nil (absent) when there is no previous seen stage to measure from — an
	// absent latency is honest, a zero would read as "instant".
	LatencyFromPrevMS *int64 `json:"latency_from_prev_ms,omitempty"`
	// EvidenceRef points at the module log file and, where the evidence has an
	// address, the row/offset that carries it.
	EvidenceRef string  `json:"evidence_ref,omitempty"`
	Verdict     Verdict `json:"verdict"`
	Reason      string  `json:"reason,omitempty"`
	// Query is the exact query/command used to look, verbatim, so a reader can
	// re-run it by hand. Never elided.
	Query string `json:"query,omitempty"`
	// Detail is the stage's own evidence payload (the store row, the peek
	// record's address, the retained API lines) — already redacted by the
	// producer. It is written into the module log file, not into summary.txt.
	Detail map[string]any `json:"detail,omitempty"`
}

// Timeline is the ordered stage record written to timeline.json.
type Timeline struct {
	Marker  string    `json:"marker"`
	Kind    Kind      `json:"kind"`
	Device  string    `json:"device"`
	Tenant  string    `json:"tenant"`
	Started time.Time `json:"started"`
	Entries []Entry   `json:"entries"`
}

// BuildTimeline orders entries by pipeline position, stamps the 1-based index,
// and computes each seen stage's latency from the previous SEEN stage.
//
// It is deliberately tolerant of missing stages (a kind that skips one) and of
// out-of-order arrival (server and host stages complete concurrently): ordering
// is by the Stages table, never by completion time.
func BuildTimeline(marker string, kind Kind, device, tenant string, started time.Time, entries []Entry) Timeline {
	byStage := map[Stage]Entry{}
	for _, e := range entries {
		byStage[e.Stage] = e
	}
	out := make([]Entry, 0, len(Stages))
	var prevSeen time.Time
	for i, st := range Stages {
		e, ok := byStage[st]
		if !ok {
			continue
		}
		e.Stage = st
		e.Index = i + 1
		if e.Module == "" {
			e.Module = string(st)
		}
		if e.EvidenceRef == "" {
			e.EvidenceRef = st.LogFile()
		}
		e.Seen = e.Verdict == VerdictSeen
		if e.Seen && !e.FirstSeen.IsZero() {
			if !prevSeen.IsZero() {
				ms := e.FirstSeen.Sub(prevSeen).Milliseconds()
				e.LatencyFromPrevMS = &ms
			}
			prevSeen = e.FirstSeen
		}
		out = append(out, e)
	}
	return Timeline{
		Marker: marker, Kind: kind, Device: device, Tenant: tenant,
		Started: started.UTC(), Entries: out,
	}
}

// Reached reports whether the timeline recorded the marker as SEEN at stage st.
func (t Timeline) Reached(st Stage) bool {
	for _, e := range t.Entries {
		if e.Stage == st {
			return e.Seen
		}
	}
	return false
}

// ExitCode is 0 only when the record reached the UI-facing API (design §1): a
// trace that lost the record anywhere before that must fail the shell, so a
// scripted caller cannot mistake a broken pipeline for a healthy one.
func (t Timeline) ExitCode() int {
	if t.Reached(StageAPI) {
		return 0
	}
	return 1
}

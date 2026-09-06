// Package seclane is the SECURITY EVIDENCE PRODUCER runtime (Project 3,
// P3-EMIT). It is the wiring that turns the four inert security packages —
// internal/secbus (T2), internal/advisory (T3), internal/hardening (T5) and
// internal/threatlane (T6), all built, gate-clean and until now emitting
// nothing — into a live, per-tenant, bounded background lane that publishes
// secfindings.Finding objects onto the netops.security topic. From there the
// router already persists them into netops-secfindings-<seg>-*
// (SECURITY_FINDINGS_STORE_DECISION 2026-08-28) and, later, T2b grounds them in
// the correlation engine with ZERO security-specific code.
//
// ── REMOVAL RULE (the removable-module constraint) ──────────────────────────
// The security PRODUCER stays REMOVABLE. Exactly four units in the compiled
// tree depend on internal/{secbus,hardening,threatlane,advisory}:
//
//  1. THIS PACKAGE (internal/seclane) — the producer runtime
//  2. secapi/rules.go               — the catalog the read API serves
//  3. internal/configdrift          — the config-drift producer: it emits its
//     verdict as a secfindings.Finding through internal/secbus and adapts the
//     sealed config store to internal/hardening's ConfigSource
//  4. enterprise/dialects           — the COMMERCIAL hardening dialects beyond
//     the core one (the `security_dialects` entitlement). It plugs in as DATA
//     through hardening.DialectPack and reaches this package only as
//     Deps.Dialects, which the assembly layer fills in. Core never imports it
//
// To remove the security producer feature entirely:
//
//	rm -r internal/seclane internal/secbus internal/hardening \
//	      internal/threatlane internal/advisory internal/configdrift \
//	      enterprise/dialects
//	rm secapi/rules.go secapi/rules_test.go
//	rm security_lane_isolation_test.go security_lane_removability_test.go
//	delete every main.go line between a `SECURITY-LANE-BEGIN` marker and its
//	matching `SECURITY-LANE-END` (the import, the server field, the worker start,
//	the route registration, the metrics write, and the
//	securityLaneDeps/registerSecurityLaneRoutes wiring — the enterprise/dialects
//	import and the Deps.Dialects line sit INSIDE those blocks, so they go with it)
//
// enterprise/dialects is ALSO removable on its own, and that is the LICENSING
// boundary rather than the feature one: delete src/backend/enterprise and the
// two ENTERPRISE-ASSEMBLY-marked lines that name it, and the lane keeps running
// on the Apache-2.0 core dialect, reporting every other platform NotApplicable.
//
// internal/configdrift is deliberately NOT inside those markers — it is wired to
// FEATURE_CONFIG_BACKUP, not FEATURE_SECURITY_LANE — so its removal is a named
// step of its own: drop main.go's configdrift import, the s.configDrift field,
// the drift construction inside buildConfigBackup (leave OnCapture/OnFailure
// unset and call configstore.NewAPI(mgr, nil) — all three seams are already
// nil-safe), the /api/config/drift route, configDriftStore/configDriftAuthz and
// configHardeningSource; then delete the drift cases from
// config_backup_isolation_test.go. Config BACKUP itself (capture, versioning,
// diff, retention) keeps working: only the security/RCA consumption goes.
//
// …and `go build ./...` is green again. internal/secfindings deliberately STAYS:
// it is the finding MODEL the secapi READ API serves, not producer code.
// security_lane_removability_test.go (package backend, importing nothing
// security-specific so it survives its own recipe) enforces both halves —
// the import allowlist and the marker discipline — mechanically.
//
// ── DESIGN ──────────────────────────────────────────────────────────────────
//   - §5 / §4: every external dependency is INJECTED through Deps. This package
//     opens no socket, reads no env var and holds no ambient authority; it is
//     unit-testable end to end with no OpenSearch, ClickHouse, bus or tenant
//     store present.
//   - §3a: a run is scoped to ONE tenant from the tenant repo. Findings are
//     stamped with that tenant from the DEVICE / telemetry record (never a
//     request body), the bus record's partition KEY is the tenant id — the same
//     keying syslog and flows use, so the engine's tenant-keyed partition
//     assignment holds — and rule enablement is read per tenant, so tenant B's
//     disabled rule can never change what tenant A assesses.
//   - §9: bounded ticker with full jitter, TryLock so runs never overlap, a
//     bounded manual-trigger queue, a per-run findings cap with a truncation
//     counter, and retry-with-backoff+jitter (secbus.Producer) into a
//     dead-letter ladder.
//   - §10: no silent failure. A batch that exhausts its retries is DEAD-LETTERED
//     onto netops.deadletter, then to a local spool; only if BOTH also fail does
//     `lost_total` move — `lost` is reserved for evidence with no durable copy
//     anywhere (the 189 persist contract).
//   - §5g honesty: an unassessable check emits an UNASSESSED verdict
//     (StatusUnknown), never a Pass. Config capture (P3-CFG) now EXISTS: the
//     integrator supplies Deps.ConfigSource from internal/configdrift's
//     HardeningSource (main.go's configHardeningSource), so a device with a
//     sealed backup is assessed against its real running-config. The empty
//     source remains the honest DEFAULT, not a fallback that guesses: with
//     FEATURE_CONFIG_BACKUP off — or for a device that has never been captured —
//     Deps.ConfigSource is nil / yields nothing and every §5e rule reports
//     "running-config unavailable — control not assessed (fail-closed)". That is
//     deliberate: a clean security page must never be the same shape as an unrun
//     one.
package seclane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/advisory"
	"netops/backend/internal/hardening"
	"netops/backend/internal/secbus"
	"netops/backend/internal/secfindings"
	"netops/backend/internal/threatlane"
	"netops/backend/internal/vuln"
	"netops/backend/secapi"
)

// ── configuration contract (the integrator reads the env; this package does not) ──

const (
	// EnvFeatureFlag gates the whole lane. Default FALSE: the producer never
	// runs unasked, and with the flag off NOTHING is constructed or routed.
	EnvFeatureFlag = "FEATURE_SECURITY_LANE"
	// EnvScanInterval is the bounded scan cadence (a Go duration).
	EnvScanInterval = "SECURITY_SCAN_INTERVAL"
	// EnvMaxFindings caps how many findings ONE tenant's run may emit.
	EnvMaxFindings = "SECURITY_MAX_FINDINGS_PER_TENANT"
	// EnvDeadLetterFile is the local durable spool, used only when the bus
	// dead-letter topic is itself unreachable.
	EnvDeadLetterFile = "SECURITY_DEADLETTER_FILE"
)

const (
	// DefaultScanInterval is the shipped cadence for EnvScanInterval.
	DefaultScanInterval = 15 * time.Minute
	// DefaultMaxFindings is the shipped per-tenant per-run emission cap.
	DefaultMaxFindings = 5000
	// DefaultDeadLetterFile is the shipped local spool path.
	DefaultDeadLetterFile = "/data/security_deadletter.jsonl"

	// scanJitterFrac is the ±fraction of full jitter applied to every interval,
	// so N replicas never scan in lockstep (§9).
	scanJitterFrac = 0.10
	// emitBatch bounds one bus-bridge POST (§9 bounded IO).
	emitBatch = 500
	// LogScanMax bounds one syslog window read per tenant.
	LogScanMax = 2000
	// FlowScanMax bounds one ClickHouse flow read per tenant.
	FlowScanMax = 20000
	// scanQueueDepth bounds the manual-trigger queue.
	scanQueueDepth = 8
	// statusErrorsMax bounds the errors carried on a status row.
	statusErrorsMax = 8
	// DeadLetterMaxBytes bounds the local spool file.
	DeadLetterMaxBytes = 64 << 20
)

// Scan outcomes — the closed `outcome` label vocabulary (bounded cardinality).
const (
	OutcomeOK      = "ok"      // every lane assessed, everything emitted
	OutcomePartial = "partial" // emitted, but a lane, a batch or the cap degraded it
	OutcomeError   = "error"   // nothing could be emitted
	OutcomeSkipped = "skipped" // a run was already in flight for the tenant
)

// evidenceClasses is the closed class vocabulary the emitted-findings counter
// labels on.
var evidenceClasses = []string{
	secfindings.EvidencePosture, secfindings.EvidenceExposure, secfindings.EvidenceSignal,
}

// DeadLetterTopic is the shared dead-letter lane (vector-router consumes it into
// netops-deadletter-*).
const DeadLetterTopic = "netops.deadletter"

// ── injected collaborators ──────────────────────────────────────────────────

// Device is the minimal device projection the lane assesses. It is this
// package's OWN type (the hardening/threatlane precedent) so the producer never
// depends on the core inventory model — §4 plugin isolation, and the reason
// deleting this package touches nothing else.
type Device struct {
	ID      string
	Name    string
	Address string
	Vendor  string
	OS      string
	// OSVersion is the inventory row's explicit software-version leaf — the
	// second source ParseSoftware consults when OS carries no version
	// (tracker 231). Empty on a device that never reported one.
	OSVersion string
	Model     string
	TenantID  string // the owning tenant, from the inventory row (§3a)
}

// Platform renders the free-form platform token the hardening and advisory
// vendor normalizers read.
func (d Device) Platform() string {
	return strings.TrimSpace(strings.Join(strings.Fields(d.Vendor+" "+d.OS+" "+d.Model), " "))
}

// Record is one bus record from the lane's point of view: a partition Key and a
// JSON-serializable Value. It mirrors secbus.Record WITHOUT making the
// integrator import a security package — the wiring layer adapts
// []seclane.Record → its own transport type in one loop, which is what keeps
// main.go's only security import this package.
type Record struct {
	Key   string
	Value any
}

// SeamRow is one active seam as the exposure evaluator needs it: which device
// it lands on, which interface faces it, and its canonical type.
type SeamRow struct {
	SeamID    string
	SeamType  string
	OnPrem    string // the device id/name/address the seam attaches to
	Interface string
}

// Deps are the lane's injected collaborators (§5 interfaces for all external
// dependencies). Every field is REQUIRED unless its comment says otherwise; New
// refuses a Deps that cannot produce, rather than running a lane that silently
// emits nothing.
type Deps struct {
	// Now is the clock (tests pin it). Required.
	Now func() time.Time
	// Tenants lists the tenant ids to scan, in a stable order. Required.
	Tenants func() []string
	// Devices returns ONE tenant's own devices. Required (§3a: the caller
	// applies the tenant filter; this package never widens it).
	Devices func(tenant string) []Device
	// RuleStates returns the tenant's stored rule enable/disable overrides.
	// Required — a failure here fails the run CLOSED (assessing under an unknown
	// enablement set would run rules a tenant disabled).
	RuleStates func(ctx context.Context, tenant string) (map[string]bool, error)
	// Publish is the bus transport. Required.
	Publish func(ctx context.Context, topic string, recs []Record) (int, error)
	// Search is the OpenSearch client used by the device-log source. Required.
	Search func(method, path string, body any) (*http.Response, error)
	// CHQuery is the tenant-scoped ClickHouse reader used by the flow source
	// (scope → the DB row policies). Required.
	CHQuery func(ctx context.Context, scope, sql string) ([]map[string]any, error)
	// Seams returns the tenant's ACTIVE seam inventory. Required; an error means
	// the seam model is unreadable and exposure verdicts fail closed.
	Seams func(ctx context.Context, tenant string) ([]SeamRow, error)
	// Advisory is the vendor-advisory provider. Optional: nil (and no
	// AdvisoryFeed) disables the advisory lane entirely. Tests inject a mock;
	// production leaves it nil and passes AdvisoryFeed instead, so the
	// integrator never imports internal/advisory.
	Advisory advisory.VendorAdvisoryProvider
	// AdvisoryFeed is the platform's offline CSV advisory feed. When Advisory is
	// nil and this is not, the lane wraps it in the OFFLINE provider — the
	// credential-free, air-gap-canonical path (§5g).
	AdvisoryFeed *vuln.Feed
	// ParseSoftware splits a device's software identity into the (product,
	// version) pair the advisory query needs. It takes BOTH strings the device
	// row can carry — the OS/sysDescr text and the row's explicit os_version
	// leaf (tracker 231) — because a device whose row was authored by hand or
	// by an importer carries a product label with no version in OS, and the
	// version arrives separately from whatever transport could reach it.
	// Optional: nil uses a conservative two-token split. Production binds the
	// platform's vendor-profile resolver, collectors.ResolveDeviceOS.
	ParseSoftware func(vendor, osStr, osVersion string) (product, version string)
	// ConfigSource yields device running-configs. Optional: nil means "config
	// capture is not built", and every hardening rule reports UNASSESSED.
	ConfigSource hardening.ConfigSource
	// LICENCE-BEGIN
	// DialectAllowed gates which hardening vendor dialects this deployment may
	// evaluate. Optional: nil allows every dialect, which is what every test and
	// every build without the licence wiring gets. The lane knows nothing about
	// licensing — it just forwards this to the engine, which reports an
	// unlicensed dialect honestly rather than skipping the device.
	DialectAllowed func(hardening.Vendor) bool
	// Dialects are the hardening DIALECT PACKS this deployment evaluates beyond
	// the core one. Optional: nil means the core dialect only, which is what an
	// Apache-2.0-only build (enterprise/ deleted) runs — every other platform is
	// then reported NotApplicable, never a false Pass. The lane knows nothing
	// about where a pack comes from; the assembly layer supplies them.
	Dialects []hardening.DialectPack
	// LICENCE-END

	// Authz resolves the caller for the HTTP surface. Required.
	Authz func(w http.ResponseWriter, r *http.Request, gate secapi.Gate) (secapi.Principal, bool)
	// Audit records an accepted control-plane write. Optional.
	Audit func(r *http.Request, tenant, action string, detail map[string]any)
	// WriteJSON / WriteError are the platform's response writers. Required.
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)
	// LogWarn / LogError are the structured loggers (§10). Required.
	LogWarn  func(msg string, fields map[string]any)
	LogError func(msg string, fields map[string]any)
	// Spool is the local durable dead-letter fallback. Optional: nil means the
	// ladder ends at the dead-letter topic.
	Spool func(tenant string, recs []Record, cause error) error
	// Scrub sanitizes an untrusted string before it reaches a log or a status
	// row (§8 log hygiene). Required.
	Scrub func(string) string
	// TenantSeg renders a tenant id as the storage/metric segment token.
	// Required (it must match the ingest derivation exactly).
	TenantSeg func(tenant string) string

	// Interval is the bounded scan cadence; <= 0 falls back to
	// DefaultScanInterval.
	Interval time.Duration
	// MaxFindings caps one tenant's per-run emission; <= 0 falls back to
	// DefaultMaxFindings.
	MaxFindings int
	// GlobalTenant is the platform tenant id, which is never scanned (a finding
	// with no owning tenant has no one to attribute it to).
	GlobalTenant string
}

func (d Deps) validate() error {
	missing := make([]string, 0, 4)
	check := func(name string, ok bool) {
		if !ok {
			missing = append(missing, name)
		}
	}
	check("Now", d.Now != nil)
	check("Tenants", d.Tenants != nil)
	check("Devices", d.Devices != nil)
	check("RuleStates", d.RuleStates != nil)
	check("Publish", d.Publish != nil)
	check("Search", d.Search != nil)
	check("CHQuery", d.CHQuery != nil)
	check("Seams", d.Seams != nil)
	check("Authz", d.Authz != nil)
	check("WriteJSON", d.WriteJSON != nil)
	check("WriteError", d.WriteError != nil)
	check("LogWarn", d.LogWarn != nil)
	check("LogError", d.LogError != nil)
	check("Scrub", d.Scrub != nil)
	check("TenantSeg", d.TenantSeg != nil)
	if len(missing) > 0 {
		return fmt.Errorf("seclane: Deps missing required fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

// ── the lane ────────────────────────────────────────────────────────────────

var (
	// ErrScanInFlight is the 429 condition: a scan for this tenant is already
	// queued or running (or the bounded queue is full).
	ErrScanInFlight = errors.New("a security scan is already queued or running for this tenant")
	// ErrScanNoTenant is the 400 condition: a cross-tenant caller must scope
	// into a tenant before triggering a scan.
	ErrScanNoTenant = errors.New("scope into a tenant before triggering a security scan")
)

// Lane is the per-tenant security evidence producer.
type Lane struct {
	deps     Deps
	producer *secbus.Producer
	metrics  *Metrics

	// passMu is the TryLock non-overlap guard: at most one pass at a time,
	// ticker or manual. A loser YIELDS (the running pass is doing the same work)
	// rather than queueing a redundant pass behind it.
	passMu sync.Mutex

	// inflight is the queued-or-running claim set the 429 reads.
	inflightMu sync.Mutex
	inflight   map[string]bool
	queue      chan string

	statusMu sync.Mutex
	status   map[string]ScanStatus

	interval    time.Duration
	maxFindings int
}

// New builds a Lane over the injected Deps. It fails CLOSED on an incomplete
// Deps rather than returning a lane that produces nothing.
func New(d Deps) (*Lane, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	interval := d.Interval
	if interval <= 0 {
		interval = DefaultScanInterval
	}
	maxFindings := d.MaxFindings
	if maxFindings <= 0 {
		maxFindings = DefaultMaxFindings
	}
	pub := secbus.PublisherFunc(func(ctx context.Context, topic string, recs []secbus.Record) (int, error) {
		return d.Publish(ctx, topic, toRecords(recs))
	})
	prod, err := secbus.NewProducer(pub, secbus.WithRetry(4, 500*time.Millisecond, 10*time.Second))
	if err != nil {
		return nil, fmt.Errorf("seclane: %w", err)
	}
	if d.Advisory == nil && d.AdvisoryFeed != nil {
		d.Advisory = advisory.NewOfflineProvider(d.AdvisoryFeed)
	}
	return &Lane{
		deps:        d,
		producer:    prod,
		metrics:     NewMetrics(),
		inflight:    map[string]bool{},
		queue:       make(chan string, scanQueueDepth),
		status:      map[string]ScanStatus{},
		interval:    interval,
		maxFindings: maxFindings,
	}, nil
}

// Metrics exposes the lane's Prometheus surface for the platform's /metrics.
func (l *Lane) Metrics() *Metrics { return l.metrics }

// Run drives the lane until ctx is cancelled: a jittered ticker pass over every
// tenant, plus the bounded manual-trigger queue. A pass failure is recorded and
// retried next tick — never a silent task death (§10).
func (l *Lane) Run(ctx context.Context) {
	timer := time.NewTimer(l.jittered())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case tenant := <-l.queue:
			l.scanOne(ctx, tenant, "manual")
			l.release(tenant)
		case <-timer.C:
			l.ScanAll(ctx)
			timer.Reset(l.jittered())
		}
	}
}

// jittered applies full ± jitter to the configured interval.
func (l *Lane) jittered() time.Duration {
	return jitter(l.interval, scanJitterFrac)
}

// ScanAll runs one bounded pass over every tenant. TryLock: if a pass is already
// running the tick YIELDS rather than stacking a second one.
func (l *Lane) ScanAll(ctx context.Context) {
	if !l.passMu.TryLock() {
		l.deps.LogWarn("security scan tick skipped — a pass is still running", nil)
		return
	}
	defer l.passMu.Unlock()
	for _, tenant := range l.deps.Tenants() {
		if ctx.Err() != nil {
			return
		}
		if !l.claim(tenant) {
			l.noteSkipped(tenant, "ticker")
			continue
		}
		l.runScan(ctx, tenant, "ticker")
		l.release(tenant)
	}
}

// ScanTenant runs ONE tenant's scan under the non-overlap guard. Exported for
// the manual path and for tests; the caller owns the inflight claim.
func (l *Lane) ScanTenant(ctx context.Context, tenant, trigger string) {
	l.scanOne(ctx, tenant, trigger)
}

func (l *Lane) scanOne(ctx context.Context, tenant, trigger string) {
	if !l.passMu.TryLock() {
		l.noteSkipped(tenant, trigger)
		return
	}
	defer l.passMu.Unlock()
	l.runScan(ctx, tenant, trigger)
}

func (l *Lane) noteSkipped(tenant, trigger string) {
	seg := l.deps.TenantSeg(tenant)
	now := l.deps.Now()
	l.record(ScanStatus{TenantID: tenant, TenantSeg: seg, Outcome: OutcomeSkipped, Trigger: trigger, At: now})
	l.metrics.RecordRun(seg, OutcomeSkipped, now, 0)
}

// claim marks a tenant queued-or-running. It is the state the 429 reads.
func (l *Lane) claim(tenant string) bool {
	l.inflightMu.Lock()
	defer l.inflightMu.Unlock()
	if l.inflight[tenant] {
		return false
	}
	l.inflight[tenant] = true
	return true
}

func (l *Lane) release(tenant string) {
	l.inflightMu.Lock()
	defer l.inflightMu.Unlock()
	delete(l.inflight, tenant)
}

// Enqueue accepts a manual scan for one tenant. Bounded queue: an already
// queued-or-running tenant, or a full queue, is refused so a caller can never
// stack work (§9).
func (l *Lane) Enqueue(tenant string) error {
	if !l.claim(tenant) {
		return ErrScanInFlight
	}
	select {
	case l.queue <- tenant:
		return nil
	default:
		l.release(tenant)
		return ErrScanInFlight
	}
}

// ── status ──────────────────────────────────────────────────────────────────

// ScanStatus is one tenant's last-run summary, as the status endpoint serves it.
type ScanStatus struct {
	TenantID   string    `json:"tenant_id"`
	TenantSeg  string    `json:"tenant_seg"`
	ScanID     string    `json:"last_scan_id"`
	At         time.Time `json:"last_scan_at"`
	Outcome    string    `json:"outcome"`
	Trigger    string    `json:"trigger"` // ticker | manual
	DurationMS int64     `json:"duration_ms"`
	Emitted    int       `json:"findings_emitted"`
	Truncated  int       `json:"findings_truncated"`
	Devices    int       `json:"devices_assessed"`
	Errors     []string  `json:"errors,omitempty"`
}

func (l *Lane) record(st ScanStatus) {
	l.statusMu.Lock()
	defer l.statusMu.Unlock()
	if prev, ok := l.status[st.TenantID]; ok && st.Outcome == OutcomeSkipped {
		// A skipped run must not erase the last REAL result — an operator would
		// read the blank row as "never scanned", which is a different claim.
		prev.Outcome = OutcomeSkipped
		prev.Trigger = st.Trigger
		l.status[st.TenantID] = prev
		return
	}
	l.status[st.TenantID] = st
}

// StatusFor returns the status rows a principal may see. §3a: own-only unless
// the caller is the cross-tenant platform admin — a tenant must never learn that
// another tenant exists from a status page.
func (l *Lane) StatusFor(tenant string, cross bool) []ScanStatus {
	l.statusMu.Lock()
	defer l.statusMu.Unlock()
	want := strings.ToLower(strings.TrimSpace(tenant))
	out := make([]ScanStatus, 0, len(l.status))
	for id, st := range l.status {
		if !cross && strings.ToLower(strings.TrimSpace(id)) != want {
			continue
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TenantID < out[j].TenantID })
	return out
}

// ── one tenant's scan ───────────────────────────────────────────────────────

// runScan assesses ONE tenant across the three lanes and emits the result. It
// never returns an error: every degradation is recorded on the status row, in
// the metrics and in the log, because a producer that fails silently is exactly
// the failure mode this design exists to prevent (§10).
func (l *Lane) runScan(ctx context.Context, tenant, trigger string) {
	start := l.deps.Now()
	seg := l.deps.TenantSeg(tenant)
	scanID := ScanID(seg, start)
	st := ScanStatus{TenantID: tenant, TenantSeg: seg, ScanID: scanID, At: start, Trigger: trigger}

	addErr := func(what string, err error) {
		if err == nil {
			return
		}
		if len(st.Errors) < statusErrorsMax {
			st.Errors = append(st.Errors, what+": "+l.deps.Scrub(err.Error()))
		}
		l.deps.LogWarn("security lane degraded — the affected checks report UNASSESSED, never clear",
			map[string]any{"tenant_seg": seg, "scan_id": scanID, "lane": what, "err": err.Error()})
	}

	enabled, err := l.ruleEnablement(ctx, tenant)
	if err != nil {
		// Fail CLOSED on the control plane: assessing under an unknown
		// enablement set would either run rules the tenant disabled or hide ones
		// it enabled, and both are worse than an honest "not assessed".
		addErr("rule-state", err)
		st.Outcome = OutcomeError
		l.finish(&st, start)
		return
	}

	devices := l.deps.Devices(tenant)
	st.Devices = len(devices)

	findings := make([]secfindings.Finding, 0, 128)
	findings = append(findings, l.hardeningFindings(ctx, tenant, scanID, devices, enabled, addErr)...)
	findings = append(findings, l.advisoryFindings(ctx, scanID, devices, enabled)...)
	findings = append(findings, l.threatFindings(ctx, tenant, scanID, devices, enabled, addErr)...)

	// Bound the run (§9). The cap is applied AFTER a deterministic sort, so a
	// truncated run keeps the same prefix from one scan to the next instead of
	// oscillating between arbitrary subsets.
	sortFindings(findings)
	if len(findings) > l.maxFindings {
		st.Truncated = len(findings) - l.maxFindings
		findings = findings[:l.maxFindings]
		l.metrics.AddTruncated(int64(st.Truncated))
		l.deps.LogWarn("security scan truncated at the per-tenant cap — some findings were NOT emitted this run",
			map[string]any{"tenant_seg": seg, "scan_id": scanID, "cap": l.maxFindings, "dropped": st.Truncated})
	}

	emitted, emitErr := l.emit(ctx, tenant, findings)
	st.Emitted = emitted
	addErr("emit", emitErr)

	switch {
	case emitErr != nil && emitted == 0 && len(findings) > 0:
		st.Outcome = OutcomeError
	case len(st.Errors) > 0 || st.Truncated > 0:
		st.Outcome = OutcomePartial
	default:
		st.Outcome = OutcomeOK
	}
	l.finish(&st, start)
}

func (l *Lane) finish(st *ScanStatus, start time.Time) {
	end := l.deps.Now()
	st.DurationMS = end.Sub(start).Milliseconds()
	l.record(*st)
	l.metrics.RecordRun(st.TenantSeg, st.Outcome, end, end.Sub(start))
}

// ScanID mints the assessment-run id. It is stamped on every finding, rides the
// bus as attrs.scan_id, and the router uses hash(native_id|scan_id) as the
// OpenSearch _id — so it must be UNIQUE per run and STABLE within one.
//
// It is deliberately NOT part of native_id (L-01, 2026-09-03): native_id is the
// identity of the FINDING and has to stay stable across scans so `current=true`
// and the compliance scorecards can collapse a rule's history onto its newest
// verdict. The scan run is the VERDICT's identity, and it reaches storage
// through the _id — which is why uniqueness per run still matters here.
func ScanID(seg string, at time.Time) string {
	return "scan-" + seg + "-" + at.UTC().Format("20060102T150405.000Z")
}

// ruleEnablement resolves the tenant's rule catalog state: rule id → enabled.
// Overrides are overlaid onto the SHIPPED catalog, so a rule with no stored row
// defaults to ON (§5g: "no row" must never read as "not assessed").
func (l *Lane) ruleEnablement(ctx context.Context, tenant string) (map[string]bool, error) {
	states, err := l.deps.RuleStates(ctx, tenant)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, 64)
	for _, r := range secapi.Apply(secapi.Catalog(), states) {
		out[r.RuleID] = r.Enabled
	}
	return out, nil
}

// ruleOn reports whether a rule id is enabled. An id the catalog does not know
// is treated as ENABLED — it cannot have been disabled, and a new rule ships on.
func ruleOn(enabled map[string]bool, id string) bool {
	if v, ok := enabled[id]; ok {
		return v
	}
	return true
}

// ── lane 1: hardening (posture + seam-aware exposure) ───────────────────────

func (l *Lane) hardeningFindings(ctx context.Context, tenant, scanID string,
	devices []Device, enabled map[string]bool, addErr func(string, error)) []secfindings.Finding {

	cfgSrc := l.deps.ConfigSource
	if cfgSrc == nil {
		// Config capture (T-config) is not built. An EMPTY source is the honest
		// input: every rule then reports "running-config unavailable — control
		// not assessed (fail-closed)" instead of a false clear.
		cfgSrc = hardening.MemConfigSource{}
	}
	out := make([]secfindings.Finding, 0, len(devices)*8)
	if len(devices) == 0 {
		return out
	}
	seams := l.seamResolver(ctx, tenant)
	// LICENCE-BEGIN — WithDialectGate is nil-safe: a nil DialectAllowed allows
	// every dialect, so this call is a no-op unless the integrator wired one.
	eng := hardening.NewEngine(hardening.DefaultCatalog(l.deps.Dialects...), cfgSrc, seams,
		hardening.WithClock(l.deps.Now), hardening.WithDialectGate(l.deps.DialectAllowed))
	// LICENCE-END
	for _, d := range devices {
		if ctx.Err() != nil {
			return out
		}
		fs, err := eng.Evaluate(ctx, hardening.Device{
			ID:       d.ID,
			Hostname: d.Name,
			Platform: d.Platform(),
			TenantID: d.TenantID, // §3a: stamped from the inventory row, never a body
		})
		if err != nil {
			addErr("hardening", fmt.Errorf("device %s: %w", d.ID, err))
			continue
		}
		for _, f := range fs {
			if !ruleOn(enabled, f.RawRuleID) {
				continue
			}
			f.ScanID = scanID
			out = append(out, f)
		}
	}
	return out
}

// ── lane 2: vendor advisory (exposure) ──────────────────────────────────────

// advisoryFindings runs the VendorAdvisoryProvider over the device inventory. A
// device that cannot be assessed (no vendor, no parsed version, an unprovisioned
// feed) yields an explicit UNASSESSED finding — never silence, which a UI would
// render as "clear" (§5g).
func (l *Lane) advisoryFindings(ctx context.Context, scanID string,
	devices []Device, enabled map[string]bool) []secfindings.Finding {

	if l.deps.Advisory == nil || !ruleOn(enabled, l.deps.Advisory.Name()) {
		return nil
	}
	parse := l.deps.ParseSoftware
	if parse == nil {
		parse = defaultParseSoftware
	}
	out := make([]secfindings.Finding, 0, len(devices))
	for _, d := range devices {
		if ctx.Err() != nil {
			return out
		}
		res := secfindings.Resource{
			DeviceID: d.ID, DeviceName: d.Name, Hostname: d.Name, Address: d.Address,
			Kind: secfindings.KindNetworkDevice, Platform: d.Platform(),
		}.ResolvePlatform() // T9: one canonical platform identity on every finding
		product, version := parse(d.Vendor, d.OS, d.OSVersion)
		switch {
		case strings.TrimSpace(d.Vendor) == "":
			out = append(out, unassessedAdvisory(d.TenantID, scanID, res, l.deps.Now(),
				"vendor unknown (SNMP unreachable or unrecognized sysObjectID) — advisory exposure not assessed"))
			continue
		case product == "" || version == "":
			out = append(out, unassessedAdvisory(d.TenantID, scanID, res, l.deps.Now(),
				"OS product/version not present in sysDescr or os_version — advisory exposure not assessed"))
			continue
		}
		fs, err := advisory.FindingsFor(ctx, l.deps.Advisory,
			advisory.Device{Vendor: d.Vendor, Product: product, Version: version, Resource: res},
			advisory.EmitOptions{TenantID: d.TenantID, ScanID: scanID, Now: l.deps.Now()})
		if err != nil {
			out = append(out, unassessedAdvisory(d.TenantID, scanID, res, l.deps.Now(),
				"advisory provider could not assess this device: "+l.deps.Scrub(err.Error())))
			continue
		}
		out = append(out, fs...)
	}
	return out
}

// defaultParseSoftware is the fallback (vendor, os) → (product, version) split
// when the integrator injects no richer parser. It is deliberately conservative
// and NEVER invents a version — an unparseable OS string yields ("", ""), which
// the advisory lane reports as UNASSESSED rather than as "no CVEs apply".
func defaultParseSoftware(_, osStr, osVersion string) (product, version string) {
	fields := strings.Fields(strings.TrimSpace(osStr))
	if len(fields) >= 2 {
		return fields[0], fields[len(fields)-1]
	}
	// One token in OS (the "SR Linux"-shaped row) — take the product from it and
	// the version from the row's explicit leaf, if it has one. Still never
	// invents: no leaf, no version, and the caller reports UNASSESSED.
	if len(fields) == 1 {
		if v := strings.Fields(strings.TrimSpace(osVersion)); len(v) > 0 {
			return fields[0], v[len(v)-1]
		}
	}
	return "", ""
}

// unassessedAdvisory builds the honest non-verdict for one device.
func unassessedAdvisory(tenant, scanID string, res secfindings.Resource, now time.Time, why string) secfindings.Finding {
	f := secfindings.Finding{
		ID:            "advisory-unassessed",
		Source:        secfindings.SourceVendorAPI,
		ScanID:        scanID,
		Time:          now,
		TenantID:      tenant,
		EvidenceClass: secfindings.EvidenceExposure,
		ControlID:     "advisory-unassessed",
		ControlTitle:  "Vendor advisory exposure not assessed",
		Category:      "vulnerability",
		Severity:      secfindings.SeverityInfo,
		Resource:      res,
		Intended:      "Every device's running version is checked against the vendor advisory feed.",
		Detail:        why,
		Remediation:   "Provision the offline advisory feed (VULN_FEED_PATH) or complete device vendor/version discovery.",
		RawRuleID:     "advisory-unassessed",
	}
	f.SetStatus(secfindings.StatusUnknown)
	return f
}

// ── lane 3: threat detection (signal) ───────────────────────────────────────

// threatFindings runs the device-log detections over the tenant's syslog window
// and the flow-behavioral detections over its ClickHouse flows. The two families
// run as SEPARATE Detect passes on purpose: threatlane's engine fails closed on
// either source, so a ClickHouse outage must not take the syslog detections down
// with it.
func (l *Lane) threatFindings(ctx context.Context, tenant, scanID string,
	devices []Device, enabled map[string]bool, addErr func(string, error)) []secfindings.Finding {

	cat := threatlane.DefaultCatalog()
	until := l.deps.Now()
	since := until.Add(-l.interval)
	out := make([]secfindings.Finding, 0, 32)

	logEng := threatlane.NewEngine(cat, l.LogSource(tenant, devices, since, until), threatlane.MemFlowSource(nil),
		threatlane.WithClock(l.deps.Now), threatlane.WithScanID(scanID))
	if fs, err := logEng.Detect(ctx); err != nil {
		addErr("threat-device-log", err)
	} else {
		out = append(out, fs...)
	}

	flowEng := threatlane.NewEngine(cat, threatlane.MemLogSource(nil), l.FlowSource(tenant, devices, l.interval),
		threatlane.WithClock(l.deps.Now), threatlane.WithScanID(scanID))
	if fs, err := flowEng.Detect(ctx); err != nil {
		addErr("threat-flow", err)
	} else {
		out = append(out, fs...)
	}

	kept := out[:0]
	for _, f := range out {
		if !ruleOn(enabled, f.RawRuleID) {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// ── emit ────────────────────────────────────────────────────────────────────

// emit publishes the findings in bounded batches, keyed by tenant. It returns
// the number published; a batch that exhausts the producer's bounded retry is
// DEAD-LETTERED and is never counted as lost while a durable copy exists.
func (l *Lane) emit(ctx context.Context, tenant string, findings []secfindings.Finding) (int, error) {
	if len(findings) == 0 {
		return 0, nil
	}
	published := 0
	var firstErr error
	before := l.producer.Metrics().Snapshot()
	for start := 0; start < len(findings); start += emitBatch {
		end := start + emitBatch
		if end > len(findings) {
			end = len(findings)
		}
		batch := findings[start:end]
		n, err := l.producer.Publish(ctx, batch)
		if err != nil {
			l.metrics.AddEmitFailure(1)
			if firstErr == nil {
				firstErr = err
			}
			l.deadLetter(ctx, tenant, batch, err)
			continue
		}
		published += n
		for _, class := range evidenceClasses {
			l.metrics.RecordEmitted(class, countClass(batch, class))
		}
	}
	after := l.producer.Metrics().Snapshot()
	l.metrics.AddUngroundable(after.Skipped - before.Skipped)
	return published, firstErr
}

func countClass(fs []secfindings.Finding, class string) int {
	n := 0
	for _, f := range fs {
		if f.EvidenceClass == class {
			n++
		}
	}
	return n
}

// deadLetter preserves a batch the bus refused. The LADDER (the 189 persist
// contract): the dead-letter TOPIC first, then the local SPOOL, and only when
// both fail does `lost_total` move — `lost` is reserved for evidence with no
// durable copy anywhere, never for evidence sitting in a dead-letter sink.
func (l *Lane) deadLetter(ctx context.Context, tenant string, findings []secfindings.Finding, cause error) {
	recs := make([]Record, 0, len(findings))
	for _, f := range findings {
		ev, err := secbus.FromFinding(f)
		if err != nil {
			continue // already counted as ungroundable by the producer
		}
		recs = append(recs, Record{Key: ev.TenantID, Value: ev})
	}
	if len(recs) == 0 {
		return
	}
	seg := l.deps.TenantSeg(tenant)
	busErr := l.deadLetterToBus(ctx, recs, cause)
	if busErr == nil {
		l.metrics.AddDeadLettered(int64(len(recs)))
		l.deps.LogError("security evidence DEAD-LETTERED onto "+DeadLetterTopic+" after the bounded retry — it is preserved, not lost",
			map[string]any{"tenant_seg": seg, "records": len(recs), "cause": cause.Error()})
		return
	}
	if l.deps.Spool != nil {
		if serr := l.deps.Spool(tenant, recs, cause); serr == nil {
			l.metrics.AddDeadLettered(int64(len(recs)))
			l.deps.LogError("security evidence dead-lettered to the LOCAL SPOOL — the dead-letter topic is unreachable",
				map[string]any{"tenant_seg": seg, "records": len(recs),
					"bus_err": busErr.Error(), "cause": cause.Error()})
			return
		} else {
			l.metrics.AddLost(int64(len(recs)))
			l.deps.LogError("security evidence LOST — neither the bus, the dead-letter topic nor the local spool accepted it",
				map[string]any{"tenant_seg": seg, "records": len(recs),
					"bus_err": busErr.Error(), "spool_err": serr.Error(), "cause": cause.Error()})
			return
		}
	}
	l.metrics.AddLost(int64(len(recs)))
	l.deps.LogError("security evidence LOST — the dead-letter topic is unreachable and no local spool is configured",
		map[string]any{"tenant_seg": seg, "records": len(recs),
			"bus_err": busErr.Error(), "cause": cause.Error()})
}

// deadLetterToBus produces the batch onto netops.deadletter in the SAME shape
// vector's deadletter_encoded transform emits, so both tiers land in the one
// netops-deadletter-* index under one template.
func (l *Lane) deadLetterToBus(ctx context.Context, recs []Record, cause error) error {
	now := l.deps.Now()
	out := make([]Record, 0, len(recs))
	for _, r := range recs {
		out = append(out, Record{Key: r.Key, Value: map[string]any{
			"dropped_at": now.UTC().Format(time.RFC3339Nano),
			"lane":       "security_lane",
			"reason":     "producer_retries_exhausted",
			"detail":     l.deps.Scrub(cause.Error()),
			"raw":        r.Value,
		}})
	}
	n, err := l.deps.Publish(ctx, DeadLetterTopic, out)
	if err != nil {
		return err
	}
	if n == 0 && len(out) > 0 {
		return errors.New("dead-letter transport accepted nothing (bus bridge disabled?)")
	}
	return nil
}

// sortFindings imposes a deterministic total order across lanes so a truncated
// run is reproducible and a diff of two runs reflects real change (§11).
func sortFindings(fs []secfindings.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.EvidenceClass != b.EvidenceClass {
			return a.EvidenceClass < b.EvidenceClass
		}
		if a.Resource.DeviceID != b.Resource.DeviceID {
			return a.Resource.DeviceID < b.Resource.DeviceID
		}
		if a.RawRuleID != b.RawRuleID {
			return a.RawRuleID < b.RawRuleID
		}
		return a.ID < b.ID
	})
}

// toRecords adapts the producer's secbus.Record batch onto the integrator-facing
// Record type. One loop, one place — the seam that keeps main.go free of any
// security import but this package.
func toRecords(in []secbus.Record) []Record {
	out := make([]Record, 0, len(in))
	for _, r := range in {
		out = append(out, Record{Key: r.Key, Value: r.Value})
	}
	return out
}

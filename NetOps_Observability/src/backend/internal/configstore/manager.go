package configstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// manager.go — the module runtime: capture orchestration, the jittered
// scheduler, retention, and the single-flight claim behind the 429.

// CaptureEvent is what a drift consumer is handed after every SUCCESSFUL
// capture. It carries the plaintext of the current, previous and golden versions
// IN MEMORY ONLY — the consumer computes a diff SUMMARY from them and must never
// persist or transmit the text (internal/configdrift's contract, enforced by its
// own bus-event test).
type CaptureEvent struct {
	Device     Device
	Tenant     string
	Vendor     Vendor
	CapturedAt time.Time

	SHA     string
	Current string

	PreviousSHA string
	Previous    string
	HasPrevious bool

	GoldenSHA string
	Golden    string
	HasGolden bool
}

// DriftVerdict is what a drift consumer concluded. State is one of the Drift*
// constants; Added/Removed are the diff summary counts.
type DriftVerdict struct {
	State   string
	Added   int
	Removed int
}

// DriftObserver is the injected consumer seam (§4: the config module PRODUCES
// artifacts, consumers subscribe — it never imports one). internal/configdrift
// binds its evaluator here; nil means "no consumer", and capture still works.
type DriftObserver func(ctx context.Context, ev CaptureEvent) DriftVerdict

// CaptureFailure is handed to the observer when a capture could NOT be taken, so
// the badge can report the honest "unknown / unreachable" rather than going
// stale on the last good verdict.
type CaptureFailure struct {
	Device Device
	Tenant string
	At     time.Time
	Reason string // already scrubbed
}

// FailureObserver is the failure half of the consumer seam.
type FailureObserver func(ctx context.Context, f CaptureFailure)

// Gate names the permission a route needs. The module/level mapping lives in
// package backend (where the RBAC model lives) and is INJECTED — this package
// states WHAT it needs, never WHO grants it (the secapi precedent).
type Gate int

const (
	// GateRead is per-tenant operator READ access (infrastructure:read).
	GateRead Gate = iota
	// GateWrite is per-tenant operator WRITE access (infrastructure:write):
	// trigger a backup, mark a golden baseline.
	GateWrite
)

// Principal is the caller's already-authorized scope.
type Principal struct {
	Tenant  string
	Cross   bool
	Subject string
}

// Deps are the module's injected collaborators (§5). Every field is REQUIRED
// unless its comment says otherwise; New refuses an incomplete Deps rather than
// returning a manager that silently captures nothing.
type Deps struct {
	// Now is the clock (tests pin it). Required.
	Now func() time.Time
	// Tenants lists the tenant ids to sweep, in a stable order. Required.
	Tenants func() []string
	// Devices returns ONE tenant's own devices that are ELIGIBLE for capture
	// (§3a: the caller applies the tenant filter and the SSH-feature gate; this
	// package never widens either). Required.
	Devices func(tenant string) []Device
	// LookupDevice resolves one device id for the HTTP path. It returns the
	// device and its owning tenant; ok=false means "no such device", which the
	// handler renders as 404 for a foreign id too. Required.
	LookupDevice func(deviceID string) (Device, bool)
	// Gateway runs the read-only capture command. Required.
	Gateway Gateway
	// Sealer is the platform sealing mechanism. Required.
	Sealer Sealer
	// Blobs is the sealed blob store. Required.
	Blobs BlobStore
	// Store is the version metadata register. Required.
	Store Store
	// Metrics is the Prometheus surface. Optional (nil = no counters).
	Metrics *Metrics
	// OnCapture / OnFailure are the drift consumer seams. Optional.
	OnCapture DriftObserver
	OnFailure FailureObserver
	// Authz resolves the caller for the HTTP surface. Required.
	Authz func(w http.ResponseWriter, r *http.Request, gate Gate) (Principal, bool)
	// Audit records an API action. `tags` carries the audit classification —
	// this module always passes "sensitive" on a config READ, because the body
	// it returns is a device's configuration. Optional but expected.
	Audit func(r *http.Request, tenant, action string, detail map[string]any)
	// AuditCapture records a capture that had NO request behind it (the
	// scheduler). Optional.
	AuditCapture func(tenant, deviceID, action string, detail map[string]any)
	// WriteJSON / WriteError are the platform's response writers. Required.
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)
	// LogWarn / LogError are the structured loggers (§10). Required.
	LogWarn  func(msg string, fields map[string]any)
	LogError func(msg string, fields map[string]any)
	// Scrub sanitizes an untrusted string before it reaches a log, an audit
	// detail or a stored error (§8 log hygiene). Required.
	Scrub func(string) string

	// Interval is the scheduled cadence; <= 0 uses DefaultInterval.
	Interval time.Duration
	// KeepVersions is per-device retention; clamped to [2, 500].
	KeepVersions int
	// CaptureTimeout bounds ONE device capture; <= 0 uses
	// DefaultCaptureTimeout.
	CaptureTimeout time.Duration
}

func (d Deps) validate() error {
	missing := make([]string, 0, 8)
	check := func(name string, ok bool) {
		if !ok {
			missing = append(missing, name)
		}
	}
	check("Now", d.Now != nil)
	check("Tenants", d.Tenants != nil)
	check("Devices", d.Devices != nil)
	check("LookupDevice", d.LookupDevice != nil)
	check("Gateway", d.Gateway != nil)
	check("Sealer", d.Sealer != nil)
	check("Blobs", d.Blobs != nil)
	check("Store", d.Store != nil)
	check("Authz", d.Authz != nil)
	check("WriteJSON", d.WriteJSON != nil)
	check("WriteError", d.WriteError != nil)
	check("LogWarn", d.LogWarn != nil)
	check("LogError", d.LogError != nil)
	check("Scrub", d.Scrub != nil)
	if len(missing) > 0 {
		return fmt.Errorf("configstore: Deps missing required fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

// Manager is the module runtime.
type Manager struct {
	deps Deps

	// passMu is the scheduler's TryLock non-overlap guard: at most one sweep at
	// a time. A loser YIELDS rather than queueing a redundant sweep behind it.
	passMu sync.Mutex

	// inflight is the per-DEVICE claim set the 429 reads. One capture per device
	// at a time, ticker and manual alike — two SSH sessions racing to write the
	// same version row is exactly the overlap §9 forbids.
	flightMu sync.Mutex
	inflight map[string]string // device id → job id

	interval time.Duration
	keep     int
	timeout  time.Duration
}

// New builds a Manager over the injected Deps, failing CLOSED on an incomplete
// Deps and on a dormant sealing provider (§8: this module refuses to run at all
// rather than write device configurations to disk in cleartext).
func New(d Deps) (*Manager, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	if !d.Sealer.Active() {
		return nil, errors.New("configstore: the platform sealing provider is dormant (SEAL_PROVIDER unset) — refusing to store device configurations in cleartext; enable sealing or leave FEATURE_CONFIG_BACKUP off")
	}
	m := &Manager{
		deps:     d,
		inflight: map[string]string{},
		interval: d.Interval,
		keep:     clampKeep(d.KeepVersions),
		timeout:  d.CaptureTimeout,
	}
	if m.interval <= 0 {
		m.interval = DefaultInterval
	}
	if m.timeout <= 0 {
		m.timeout = DefaultCaptureTimeout
	}
	return m, nil
}

// Metrics exposes the counter set for the /metrics writer.
func (m *Manager) Metrics() *Metrics {
	if m == nil {
		return nil
	}
	return m.deps.Metrics
}

// Interval is the scheduled cadence (the status endpoint's next_scheduled_at).
func (m *Manager) Interval() time.Duration {
	if m == nil {
		return 0
	}
	return m.interval
}

// ── scheduler ───────────────────────────────────────────────────────────────

// Run drives the scheduled sweep until ctx is done. Every interval is fully
// jittered so N replicas never capture in lockstep, and a sweep that is still
// running when the next tick fires is SKIPPED (TryLock), never queued (§9).
func (m *Manager) Run(ctx context.Context) {
	if m == nil {
		return
	}
	timer := time.NewTimer(m.jittered())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			m.Sweep(ctx)
			timer.Reset(m.jittered())
		}
	}
}

// jittered applies ±scheduleJitterFrac full jitter to the interval.
func (m *Manager) jittered() time.Duration {
	span := float64(m.interval) * scheduleJitterFrac
	if span <= 0 {
		return m.interval
	}
	// crypto/rand: no seeded package-level generator, no shared mutable state.
	n, err := rand.Int(rand.Reader, big.NewInt(int64(2*span)))
	if err != nil {
		return m.interval // fail safe to the un-jittered cadence
	}
	out := time.Duration(float64(m.interval) - span + float64(n.Int64()))
	if out <= 0 {
		return m.interval
	}
	return out
}

// Sweep runs ONE bounded pass over every tenant's eligible devices. It returns
// the number of devices attempted (tests assert the TryLock behaviour on it).
func (m *Manager) Sweep(ctx context.Context) int {
	if !m.passMu.TryLock() {
		// A sweep is already running and is doing exactly this work.
		return 0
	}
	defer m.passMu.Unlock()

	attempted := 0
	for _, tenant := range m.deps.Tenants() {
		if ctx.Err() != nil {
			return attempted
		}
		devices := m.deps.Devices(tenant)
		sort.Slice(devices, func(i, j int) bool { return devices[i].ID < devices[j].ID })
		for _, dev := range devices {
			if ctx.Err() != nil {
				return attempted
			}
			if attempted >= maxDevicesPerPass {
				m.deps.LogWarn("scheduled capture pass hit the per-pass device cap", map[string]any{
					"cap": maxDevicesPerPass})
				return attempted
			}
			attempted++
			if _, err := m.Capture(ctx, dev, NormTenant(tenant), "scheduled"); err != nil &&
				!errors.Is(err, ErrInFlight) {
				m.deps.LogWarn("scheduled configuration capture failed", map[string]any{
					"device": dev.ID, "tenant": Seg(tenant), "error": m.deps.Scrub(err.Error())})
			}
		}
	}
	return attempted
}

// ── capture ─────────────────────────────────────────────────────────────────

// claim takes the single-flight claim for a device, minting the job id. ok=false
// is the 429 condition.
func (m *Manager) claim(deviceID string) (string, bool) {
	m.flightMu.Lock()
	defer m.flightMu.Unlock()
	if _, busy := m.inflight[deviceID]; busy {
		return "", false
	}
	job := newJobID()
	m.inflight[deviceID] = job
	return job, true
}

func (m *Manager) release(deviceID string) {
	m.flightMu.Lock()
	defer m.flightMu.Unlock()
	delete(m.inflight, deviceID)
}

// InFlight reports whether a capture is running for a device (tests + the 429).
func (m *Manager) InFlight(deviceID string) bool {
	m.flightMu.Lock()
	defer m.flightMu.Unlock()
	_, busy := m.inflight[deviceID]
	return busy
}

func newJobID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b) // crypto/rand.Read cannot fail (Go 1.24+ aborts instead)
	return hex.EncodeToString(b)
}

// Capture takes ONE device's running-configuration, normalizes it,
// content-addresses it, seals it, stores it, applies retention and hands the
// result to the drift consumer. It returns the stored version.
//
// The whole body is bounded: a context timeout, a byte cap in the gateway, one
// claim per device, and a retention prune at the end.
func (m *Manager) Capture(ctx context.Context, dev Device, tenant, trigger string) (Version, error) {
	tenant = NormTenant(tenant)
	job, ok := m.claim(dev.ID)
	if !ok {
		m.deps.Metrics.RecordRun(OutcomeSkipped)
		return Version{}, ErrInFlight
	}
	defer m.release(dev.ID)
	return m.captureClaimed(ctx, dev, tenant, trigger, job)
}

// CaptureClaimed runs a capture whose single-flight claim the CALLER already
// holds (the async manual path, which answers 202 before the work starts). The
// caller is responsible for Release.
func (m *Manager) CaptureClaimed(ctx context.Context, dev Device, tenant, trigger, job string) (Version, error) {
	return m.captureClaimed(ctx, dev, NormTenant(tenant), trigger, job)
}

// ClaimFor takes the single-flight claim without capturing (the manual 202
// path). Release MUST be called by the caller.
func (m *Manager) ClaimFor(deviceID string) (string, bool) { return m.claim(deviceID) }

// Release drops a claim taken by ClaimFor.
func (m *Manager) Release(deviceID string) { m.release(deviceID) }

func (m *Manager) captureClaimed(ctx context.Context, dev Device, tenant, trigger, job string) (Version, error) {
	now := m.deps.Now().UTC()
	vendor := VendorFromPlatform(dev.Platform())
	cmd, bound := CaptureCommand(vendor)
	if !bound {
		m.recordFailure(ctx, dev, tenant, now, ErrNoVendor, trigger, job)
		return Version{}, ErrNoVendor
	}

	runCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	raw, err := m.deps.Gateway.Run(runCtx, dev, cmd, MaxCaptureBytes)
	if err != nil {
		m.recordFailure(ctx, dev, tenant, now, err, trigger, job)
		return Version{}, err
	}

	normalized := Normalize(vendor, raw)
	if strings.TrimSpace(normalized) == "" {
		err := errors.New("device returned an empty configuration")
		m.recordFailure(ctx, dev, tenant, now, err, trigger, job)
		return Version{}, err
	}
	// A CLI that REFUSED the command (exit zero, diagnostic on stdout — EOS
	// answers a privilege-1 `show running-config` exactly this way) must fail
	// the capture, never be stored as a version. See looksLikeCLIRefusal.
	if line, refused := looksLikeCLIRefusal(normalized); refused {
		err := fmt.Errorf("device refused the capture command: %s", line)
		m.recordFailure(ctx, dev, tenant, now, err, trigger, job)
		return Version{}, err
	}
	sha := SHA256Hex(normalized)

	// The PREVIOUS successful version, read BEFORE this one is stored — it is
	// the drift comparator and the "unchanged" test.
	prev, hasPrev, err := m.deps.Store.Latest(ctx, tenant, false, dev.ID)
	if err != nil {
		return Version{}, err
	}
	golden, hasGolden, err := m.deps.Store.Golden(ctx, tenant, false, dev.ID)
	if err != nil {
		return Version{}, err
	}

	ver := Version{
		TenantID: tenant, DeviceID: dev.ID, SHA: sha, CapturedAt: now,
		SizeBytes: int64(len(normalized)), Vendor: string(vendor),
		Status: StatusOK, Drift: DriftUnknown,
	}

	outcome := OutcomeUnchanged
	if hasPrev && prev.SHA == sha {
		// Content-addressed: an unchanged capture stores NO new blob, it just
		// re-stamps the existing row's captured_at ("last verified").
		ver = prev
		ver.CapturedAt = now
		if err := m.deps.Store.Put(ctx, tenant, false, ver); err != nil {
			return Version{}, err
		}
	} else {
		outcome = OutcomeNew
		sealed, err := m.deps.Sealer.Seal(tenant, BlobField(dev.ID, sha), normalized)
		if err != nil {
			m.recordFailure(ctx, dev, tenant, now, fmt.Errorf("seal: %w", err), trigger, job)
			return Version{}, err
		}
		ref, err := m.deps.Blobs.Put(tenant, dev.ID, sha, sealed)
		if err != nil {
			m.recordFailure(ctx, dev, tenant, now, fmt.Errorf("store blob: %w", err), trigger, job)
			return Version{}, err
		}
		ver.BlobRef = ref
		if err := m.deps.Store.Put(ctx, tenant, false, ver); err != nil {
			// The row is the index; a blob with no row is unreachable garbage.
			_ = m.deps.Blobs.Delete(ref) // best-effort cleanup of the orphan
			return Version{}, err
		}
		m.deps.Metrics.RecordVersion(int64(len(sealed)))
	}
	m.deps.Metrics.RecordRun(outcome)

	// Hand the capture to the drift consumer, then stamp its verdict on the row.
	verdict := m.observe(ctx, dev, tenant, vendor, now, ver, normalized, prev, hasPrev, golden, hasGolden)
	if verdict.State != "" {
		ver.Drift, ver.Added, ver.Removed = verdict.State, verdict.Added, verdict.Removed
		if err := m.deps.Store.RecordDrift(ctx, tenant, false, dev.ID, ver.SHA,
			verdict.State, verdict.Added, verdict.Removed); err != nil && !errors.Is(err, ErrNotFound) {
			m.deps.LogWarn("drift verdict not stamped on the version row", map[string]any{
				"device": dev.ID, "error": m.deps.Scrub(err.Error())})
		}
	}

	m.prune(ctx, tenant, dev.ID)
	m.auditCapture(tenant, dev.ID, "config_backup_capture", map[string]any{
		"trigger": trigger, "job_id": job, "sha": ver.SHA,
		"outcome": outcome, "drift": ver.Drift, "size_bytes": ver.SizeBytes,
	})
	return ver, nil
}

// observe reads the previous/golden plaintext (unsealing only what the consumer
// needs) and asks the drift observer for a verdict.
func (m *Manager) observe(ctx context.Context, dev Device, tenant string, vendor Vendor, now time.Time,
	ver Version, normalized string, prev Version, hasPrev bool, golden Version, hasGolden bool) DriftVerdict {
	if m.deps.OnCapture == nil {
		return DriftVerdict{}
	}
	ev := CaptureEvent{
		Device: dev, Tenant: tenant, Vendor: vendor, CapturedAt: now,
		SHA: ver.SHA, Current: normalized,
	}
	if hasPrev {
		ev.HasPrevious, ev.PreviousSHA = true, prev.SHA
		if prev.SHA == ver.SHA {
			ev.Previous = normalized
		} else if txt, err := m.open(tenant, prev); err == nil {
			ev.Previous = txt
		} else {
			// A previous version we cannot open is NOT "no change" — say so.
			ev.HasPrevious = false
			m.deps.LogWarn("previous configuration version could not be unsealed", map[string]any{
				"device": dev.ID, "sha": prev.SHA, "error": m.deps.Scrub(err.Error())})
		}
	}
	if hasGolden {
		ev.HasGolden, ev.GoldenSHA = true, golden.SHA
		if golden.SHA == ver.SHA {
			ev.Golden = normalized
		} else if txt, err := m.open(tenant, golden); err == nil {
			ev.Golden = txt
		} else {
			ev.HasGolden = false
			m.deps.LogWarn("golden configuration version could not be unsealed", map[string]any{
				"device": dev.ID, "sha": golden.SHA, "error": m.deps.Scrub(err.Error())})
		}
	}
	return m.deps.OnCapture(ctx, ev)
}

// open unseals one stored version's plaintext.
func (m *Manager) open(tenant string, v Version) (string, error) {
	sealed, err := m.deps.Blobs.Get(v.BlobRef)
	if err != nil {
		return "", err
	}
	return m.deps.Sealer.Open(NormTenant(v.TenantID), BlobField(v.DeviceID, v.SHA), sealed)
}

// Open unseals a version the CALLER has already authorized (the version-text and
// diff handlers). It is deliberately not reachable without a Version row that a
// tenant-scoped store read produced.
func (m *Manager) Open(v Version) (string, error) { return m.open(v.TenantID, v) }

// recordFailure stores the failed capture, counts it and tells the consumer, so
// an unreachable device reports "unknown" rather than silently keeping its last
// green badge (§10).
func (m *Manager) recordFailure(ctx context.Context, dev Device, tenant string, now time.Time, cause error, trigger, job string) {
	m.deps.Metrics.RecordRun(OutcomeFailed)
	reason := m.deps.Scrub(cause.Error())
	if len(reason) > 512 {
		reason = reason[:512]
	}
	row := Version{
		TenantID: tenant, DeviceID: dev.ID,
		// A failed capture has no content, so it has no content address. It is
		// keyed by the attempt instant instead, which keeps the failure visible
		// in the timeline without pretending to be a version.
		SHA:        failureSHA(dev.ID, now),
		CapturedAt: now, Status: StatusFailed, Error: reason,
		Vendor: string(VendorFromPlatform(dev.Platform())), Drift: DriftUnknown,
	}
	if err := m.deps.Store.Put(ctx, tenant, false, row); err != nil {
		m.deps.LogError("failed configuration capture was not recorded", map[string]any{
			"device": dev.ID, "error": m.deps.Scrub(err.Error())})
	}
	if m.deps.OnFailure != nil {
		m.deps.OnFailure(ctx, CaptureFailure{Device: dev, Tenant: tenant, At: now, Reason: reason})
	}
	m.auditCapture(tenant, dev.ID, "config_backup_capture_failed", map[string]any{
		"trigger": trigger, "job_id": job, "reason": reason,
	})
}

// failureSHA mints the synthetic, well-formed version id a failed capture is
// filed under. It is derived from (device, instant) so two failures never
// collide and so it can never be mistaken for a content address of real config.
func failureSHA(deviceID string, at time.Time) string {
	return SHA256Hex("capture-failure\x00" + deviceID + "\x00" + at.UTC().Format(time.RFC3339Nano))
}

// prune enforces per-device retention and deletes the pruned blobs.
func (m *Manager) prune(ctx context.Context, tenant, deviceID string) {
	removed, err := m.deps.Store.Prune(ctx, tenant, false, deviceID, m.keep)
	if err != nil {
		m.deps.LogWarn("configuration retention prune failed", map[string]any{
			"device": deviceID, "error": m.deps.Scrub(err.Error())})
		return
	}
	for _, v := range removed {
		if v.BlobRef == "" {
			continue
		}
		if err := m.deps.Blobs.Delete(v.BlobRef); err != nil {
			m.deps.LogWarn("pruned configuration blob was not deleted", map[string]any{
				"device": deviceID, "sha": v.SHA, "error": m.deps.Scrub(err.Error())})
		}
	}
	m.deps.Metrics.RecordPruned(len(removed))
}

func (m *Manager) auditCapture(tenant, deviceID, action string, detail map[string]any) {
	if m.deps.AuditCapture == nil {
		return
	}
	m.deps.AuditCapture(tenant, deviceID, action, detail)
}

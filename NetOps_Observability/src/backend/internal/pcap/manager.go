package pcap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// manager.go — the capture runtime and the GUARDRAILS.
//
// Every bound the design calls non-negotiable is enforced HERE, before the
// gateway is touched, and again on the way back:
//
//	duration  <= MaxDurationSeconds   (60 s)
//	packets   <= MaxPackets           (10 000)
//	bytes     <= MaxBytes             (25 MiB, enforced by the fetch itself)
//	captures  == at most ONE per device at a time (409)
//
// A breach is a 400 naming the bound, not a silent clamp: an operator who asked
// for a 10-minute capture must be told they cannot have one, because a silently
// shortened capture is a capture that missed the event they were chasing.
//
// Cleanup is unconditional. Whatever happens — success, fetch failure, panic in
// a caller's audit sink — the stop and cleanup commands run, so a capture point
// is never left configured on a production interface (the design's top risk).

// Gate is the permission a route needs. This package states WHAT; the integrator
// maps it to the RBAC model.
type Gate int

const (
	// GateRead is per-tenant operator READ access (list/status).
	GateRead Gate = iota
	// GateWrite is the privileged action: start, download (a reveal of payload)
	// and delete.
	GateWrite
)

// Principal is the caller's already-authorized scope.
type Principal struct {
	Tenant  string
	Cross   bool
	Subject string
}

// Gateway runs commands on a device and fetches a file back. Injecting it is
// what lets the whole capture path be tested with no network, and what keeps
// this package from holding ambient authority to reach devices (§5).
type Gateway interface {
	// Exec runs ONE command from the closed table and returns its stdout,
	// bounded by maxBytes.
	Exec(ctx context.Context, dev Device, command string, maxBytes int64) (string, error)
	// Fetch retrieves a file from the device, bounded by maxBytes. A file larger
	// than the bound is ErrTooLarge — never a truncated pcap, which would look
	// like a valid short capture.
	Fetch(ctx context.Context, dev Device, remotePath string, maxBytes int64) ([]byte, error)
}

// StartRequest is the operator's ask, BEFORE validation.
type StartRequest struct {
	Interface   string
	DurationSec int
	MaxPackets  int
	Filter      string
}

// Deps are the module's injected collaborators (§5). Every field is REQUIRED
// unless its comment says otherwise; New refuses an incomplete Deps rather than
// returning a manager that silently captures nothing.
type Deps struct {
	// Now is the clock (tests pin it). Required.
	Now func() time.Time
	// LookupDevice resolves one device id. It returns the device and its owning
	// tenant; ok=false means "no such device", which the handler renders as 404
	// for a foreign id too. Required.
	LookupDevice func(deviceID string) (Device, bool)
	// Gateway runs the capture commands. Required.
	Gateway Gateway
	// Commands is the per-vendor command table. Required.
	Commands CommandTable
	// Sealer is the platform sealing mechanism. Required.
	Sealer Sealer
	// Blobs is the sealed blob store. Required.
	Blobs BlobStore
	// Store is the capture metadata register. Required.
	Store Store
	// Metrics is the Prometheus surface. Optional (nil = no counters).
	Metrics *Metrics
	// Authz resolves the caller for the HTTP surface. Required.
	Authz func(w http.ResponseWriter, r *http.Request, gate Gate) (Principal, bool)
	// Audit records an API action. This module always passes "sensitive" on a
	// start, a fetch and a download: a PCAP reveal is never anonymous. Optional
	// but expected.
	Audit func(r *http.Request, tenant, action string, detail map[string]any)
	// AuditRuntime records an act with NO request behind it — the moment the
	// capture bytes actually leave the device and land sealed in the store. It
	// is a SEPARATE sink because there is no principal to borrow: the actor is
	// the capture's own recorded operator plus the worker identity, and pinning
	// "payload moved off this device at this instant" is exactly the audit
	// question a capture has to be able to answer. Optional.
	AuditRuntime func(tenant, deviceID, action string, detail map[string]any)
	// WriteJSON / WriteError are the platform's response writers. Required.
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)
	// LogWarn / LogError are the structured loggers (§10). Required.
	LogWarn  func(msg string, fields map[string]any)
	LogError func(msg string, fields map[string]any)
	// Scrub sanitizes an untrusted string before it reaches a log, an audit
	// detail or a stored error (§8 log hygiene). Required.
	Scrub func(string) string
	// Keep is per-device retention; clamped to [MinKeep, MaxKeep].
	Keep int
	// Run executes the capture body. Optional: nil runs it in a goroutine, which
	// is what production wants; tests inject a synchronous runner so a capture
	// completes before the assertion.
	Run func(fn func())
}

func (d Deps) validate() error {
	missing := make([]string, 0, 8)
	check := func(name string, ok bool) {
		if !ok {
			missing = append(missing, name)
		}
	}
	check("Now", d.Now != nil)
	check("LookupDevice", d.LookupDevice != nil)
	check("Gateway", d.Gateway != nil)
	check("Commands", d.Commands != nil)
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
		return fmt.Errorf("pcap: Deps missing required fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

// Manager is the module runtime.
type Manager struct {
	deps Deps
	keep int

	// inflight is the per-DEVICE claim set the 409 reads. One capture per device
	// at a time: two capture points racing on one interface is precisely the
	// device impact the design's top risk describes, and the store's ActiveFor
	// is the durable half of the same gate.
	flightMu sync.Mutex
	inflight map[string]string // device id → capture id
}

// New builds a Manager over the injected Deps, failing CLOSED on an incomplete
// Deps and on a dormant sealing provider (§8: this module refuses to run at all
// rather than write packet payload to disk in cleartext).
func New(d Deps) (*Manager, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	if !d.Sealer.Active() {
		return nil, errors.New("pcap: the platform sealing provider is dormant (SEAL_PROVIDER unset) — " +
			"refusing to store packet captures in cleartext; enable sealing or leave FEATURE_PACKET_CAPTURE off")
	}
	return &Manager{deps: d, keep: ClampKeep(d.Keep), inflight: map[string]string{}}, nil
}

// Metrics exposes the counter set for the /metrics writer.
func (m *Manager) Metrics() *Metrics {
	if m == nil {
		return nil
	}
	return m.deps.Metrics
}

// ── guardrails ──────────────────────────────────────────────────────────────

// Bounds is the validated, clamped-and-checked capture request. Producing one is
// the ONLY way to reach the device: every field has been proved, so nothing
// downstream re-derives a bound from caller input.
type Bounds struct {
	Interface   string
	Filter      string
	DurationSec int
	MaxPackets  int
	MaxBytes    int64
}

// CheckBounds validates a start request. It returns a 400-worthy error naming
// the bound that was breached — never a silent clamp (see the file header).
func CheckBounds(req StartRequest) (Bounds, error) {
	iface, err := ValidateInterface(req.Interface)
	if err != nil {
		return Bounds{}, err
	}
	dur := req.DurationSec
	if dur == 0 {
		dur = DefaultDurationSeconds
	}
	if dur < 1 {
		return Bounds{}, errors.New("duration_s must be at least 1 second")
	}
	if dur > MaxDurationSeconds {
		return Bounds{}, fmt.Errorf("duration_s must be %d seconds or less (a packet capture is a bounded, "+
			"privileged action on a production device — there is no unbounded capture)", MaxDurationSeconds)
	}
	pkts := req.MaxPackets
	if pkts == 0 {
		pkts = DefaultPackets
	}
	if pkts < 1 {
		return Bounds{}, errors.New("max_packets must be at least 1")
	}
	if pkts > MaxPackets {
		return Bounds{}, fmt.Errorf("max_packets must be %d or less", MaxPackets)
	}
	filter, err := ValidateFilter(req.Filter)
	if err != nil {
		return Bounds{}, err
	}
	return Bounds{
		Interface: iface, Filter: filter,
		DurationSec: dur, MaxPackets: pkts, MaxBytes: MaxBytes,
	}, nil
}

// ── the capture lifecycle ───────────────────────────────────────────────────

// mintID returns a 32-hex capture id. It is the ONLY source of capture ids: a
// caller-supplied id would become a filesystem path and a device file name.
func mintID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("pcap: capture id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// Start validates, claims the device, records the RUNNING row and launches the
// capture body. It returns the accepted row (202) or an error the handler maps.
func (m *Manager) Start(ctx context.Context, p Principal, dev Device, req StartRequest, actor string) (Capture, error) {
	if m == nil {
		return Capture{}, ErrDisabled
	}
	bounds, err := CheckBounds(req)
	if err != nil {
		m.deps.Metrics.RecordRun(OutcomeRefused)
		return Capture{}, err
	}
	if dev.Address == "" {
		m.deps.Metrics.RecordRun(OutcomeRefused)
		return Capture{}, ErrNoAddress
	}
	// Refuse an unknown platform, and a filter the platform cannot express,
	// BEFORE anything touches the device — the operator gets the honest reason.
	key, supportsFilter, ok := m.deps.Commands.Supports(dev.Platform())
	if !ok {
		m.deps.Metrics.RecordRun(OutcomeRefused)
		return Capture{}, ErrNoPlatform
	}
	if bounds.Filter != "" && !supportsFilter {
		m.deps.Metrics.RecordRun(OutcomeRefused)
		return Capture{}, ErrFilterUnsupported
	}

	owner := NormTenant(dev.TenantID)
	// Durable half of the one-at-a-time gate.
	if running, found, aerr := m.deps.Store.ActiveFor(ctx, p.Tenant, p.Cross, dev.ID); aerr == nil && found {
		if running.ExpiresAt.After(m.deps.Now()) {
			m.deps.Metrics.RecordRun(OutcomeInFlight)
			return Capture{}, ErrInFlight
		}
	}
	id, err := mintID()
	if err != nil {
		return Capture{}, err
	}
	// In-process half. It is claimed AFTER the durable check and released by the
	// capture body on every exit path.
	if !m.claim(dev.ID, id) {
		m.deps.Metrics.RecordRun(OutcomeInFlight)
		return Capture{}, ErrInFlight
	}

	now := m.deps.Now()
	rec := Capture{
		TenantID: owner, DeviceID: dev.ID, ID: id,
		Interface: bounds.Interface, Filter: bounds.Filter,
		DurationSec: bounds.DurationSec, MaxPackets: bounds.MaxPackets,
		StartedAt: now,
		ExpiresAt: now.Add(time.Duration(bounds.DurationSec)*time.Second + StopGrace),
		Status:    StatusRunning, Actor: actor, Platform: key,
	}
	if err := m.deps.Store.Put(ctx, p.Tenant, p.Cross, rec); err != nil {
		m.release(dev.ID)
		m.deps.Metrics.RecordRun(OutcomeFailed)
		return Capture{}, err
	}
	m.deps.Metrics.SetActive(1)

	scope := Principal{Tenant: owner, Cross: false, Subject: p.Subject}
	body := func() { m.run(scope, dev, rec, bounds) }
	if m.deps.Run != nil {
		m.deps.Run(body)
	} else {
		go body()
	}
	return rec, nil
}

func (m *Manager) claim(deviceID, captureID string) bool {
	m.flightMu.Lock()
	defer m.flightMu.Unlock()
	if _, busy := m.inflight[deviceID]; busy {
		return false
	}
	m.inflight[deviceID] = captureID
	return true
}

func (m *Manager) release(deviceID string) {
	m.flightMu.Lock()
	defer m.flightMu.Unlock()
	delete(m.inflight, deviceID)
}

// run is the capture body: start → wait the bound → stop → fetch → seal → store,
// with cleanup on EVERY exit path. It never returns an error to a caller (there
// is none by then); every failure is stored on the row and counted.
func (m *Manager) run(scope Principal, dev Device, rec Capture, bounds Bounds) {
	defer m.release(dev.ID)
	defer m.deps.Metrics.SetActive(-1)

	// The whole body is bounded: the requested duration, the stop grace and a
	// fetch window. A device that never answers cannot hold this goroutine (§9).
	total := time.Duration(bounds.DurationSec)*time.Second + StopGrace + 2*StopGrace
	ctx, cancel := context.WithTimeout(context.Background(), total)
	defer cancel()

	set, err := m.deps.Commands.For(dev.Platform(), CommandRequest{
		Interface: bounds.Interface, File: captureFileName(rec.ID),
		DurationSec: bounds.DurationSec, MaxPackets: bounds.MaxPackets,
		MaxBytes: bounds.MaxBytes, Filter: bounds.Filter, Name: captureName(rec.ID),
	})
	if err != nil {
		m.fail(ctx, scope, rec, err)
		return
	}
	rec.RemotePath = set.RemotePath

	// Cleanup is unconditional and runs LAST — a capture point left configured on
	// a production interface is the design's top operational risk.
	defer m.cleanup(dev, set)

	for _, cmd := range set.Start {
		if _, err := m.deps.Gateway.Exec(ctx, dev, cmd, MaxControlOutputBytes); err != nil {
			m.fail(ctx, scope, rec, fmt.Errorf("capture start failed: %w", err))
			return
		}
	}
	// Wait out the capture window, unless the context (the hard bound) fires
	// first.
	select {
	case <-ctx.Done():
	case <-time.After(time.Duration(bounds.DurationSec) * time.Second):
	}
	for _, cmd := range set.Stop {
		if _, err := m.deps.Gateway.Exec(ctx, dev, cmd, MaxControlOutputBytes); err != nil {
			// A stop that failed is worth a WARN but not a failed capture: the
			// device may have already stopped on its own bound, and the cleanup
			// deferred above still runs.
			m.deps.LogWarn("packet capture stop command failed", map[string]any{
				"device": dev.ID, "capture": rec.ID, "error": m.deps.Scrub(err.Error())})
		}
	}

	raw, err := m.deps.Gateway.Fetch(ctx, dev, set.RemotePath, bounds.MaxBytes)
	if err != nil {
		m.fail(ctx, scope, rec, fmt.Errorf("capture fetch failed: %w", err))
		return
	}
	if int64(len(raw)) > bounds.MaxBytes {
		// Belt-and-braces: a gateway that ignored its bound must not be able to
		// put an oversized blob in the store.
		m.fail(ctx, scope, rec, ErrTooLarge)
		return
	}
	sealed, err := m.deps.Sealer.Seal(NormTenant(rec.TenantID), BlobField(dev.ID, rec.ID), string(raw))
	if err != nil {
		m.fail(ctx, scope, rec, fmt.Errorf("capture could not be sealed: %w", err))
		return
	}
	ref, err := m.deps.Blobs.Put(NormTenant(rec.TenantID), dev.ID, rec.ID, sealed)
	if err != nil {
		m.fail(ctx, scope, rec, fmt.Errorf("capture could not be stored: %w", err))
		return
	}

	ended := m.deps.Now()
	rec.EndedAt = &ended
	rec.Status = StatusStored
	rec.Bytes = int64(len(raw))
	rec.Packets = countPackets(raw)
	rec.BlobRef = ref
	if err := m.deps.Store.Put(ctx, scope.Tenant, scope.Cross, rec); err != nil {
		m.deps.LogError("packet capture stored but its row could not be written", map[string]any{
			"device": dev.ID, "capture": rec.ID, "error": m.deps.Scrub(err.Error())})
		// The blob would otherwise be unreferenced; remove it rather than leak
		// sealed payload nothing can ever reach or delete.
		if derr := m.deps.Blobs.Delete(ref); derr != nil {
			m.deps.LogError("orphaned capture blob could not be removed", map[string]any{
				"device": dev.ID, "capture": rec.ID, "error": m.deps.Scrub(derr.Error())})
		}
		m.deps.Metrics.RecordRun(OutcomeFailed)
		return
	}
	m.deps.Metrics.RecordRun(OutcomeStored)
	m.deps.Metrics.RecordSealed(int64(len(sealed)))
	// The FETCH audit: this is the instant packet payload left the device. It is
	// recorded separately from the start, because a capture that started and a
	// capture that produced bytes are different facts.
	if m.deps.AuditRuntime != nil {
		m.deps.AuditRuntime(NormTenant(rec.TenantID), dev.ID, "pcap_capture_fetched", map[string]any{
			"capture": rec.ID, "interface": rec.Interface, "filter": rec.Filter,
			"bytes": rec.Bytes, "packets": rec.Packets, "actor": rec.Actor,
			"sensitive": true,
		})
	}
	m.prune(ctx, scope, dev.ID)
}

// fail stamps the failure on the row. A failed capture is STORED, not discarded:
// "we tried and could not" is what the operator needs to see (§10).
func (m *Manager) fail(ctx context.Context, scope Principal, rec Capture, cause error) {
	ended := m.deps.Now()
	rec.EndedAt = &ended
	rec.Status = StatusFailed
	rec.Error = m.deps.Scrub(cause.Error())
	if err := m.deps.Store.Put(ctx, scope.Tenant, scope.Cross, rec); err != nil {
		m.deps.LogError("failed packet capture could not be recorded", map[string]any{
			"device": rec.DeviceID, "capture": rec.ID, "error": m.deps.Scrub(err.Error())})
	}
	m.deps.LogWarn("packet capture failed", map[string]any{
		"device": rec.DeviceID, "capture": rec.ID, "error": rec.Error})
	m.deps.Metrics.RecordRun(OutcomeFailed)
}

// cleanup tears the capture point down and removes the on-device file. It runs
// with its OWN short context so a cancelled capture still cleans up.
func (m *Manager) cleanup(dev Device, set CommandSet) {
	if len(set.Cleanup) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), StopGrace)
	defer cancel()
	for _, cmd := range set.Cleanup {
		if _, err := m.deps.Gateway.Exec(ctx, dev, cmd, MaxControlOutputBytes); err != nil {
			// LOUD: a cleanup that did not run may have left a capture point on a
			// production interface. It is never swallowed.
			m.deps.LogError("packet capture cleanup command failed — a capture point may remain on the device",
				map[string]any{"device": dev.ID, "command": cmd, "error": m.deps.Scrub(err.Error())})
		}
	}
}

// prune enforces per-device retention and deletes the blobs it orphaned.
func (m *Manager) prune(ctx context.Context, scope Principal, deviceID string) {
	removed, err := m.deps.Store.Prune(ctx, scope.Tenant, scope.Cross, deviceID, m.keep)
	if err != nil {
		m.deps.LogWarn("packet capture retention failed", map[string]any{
			"device": deviceID, "error": m.deps.Scrub(err.Error())})
		return
	}
	for _, c := range removed {
		if c.BlobRef == "" {
			continue
		}
		if derr := m.deps.Blobs.Delete(c.BlobRef); derr != nil {
			m.deps.LogWarn("pruned capture blob could not be removed", map[string]any{
				"device": deviceID, "capture": c.ID, "error": m.deps.Scrub(derr.Error())})
		}
	}
	m.deps.Metrics.RecordPruned(len(removed))
}

// Open unseals one stored capture. The AAD binding means a blob copied between
// tenants or devices fails HERE rather than being served to the wrong operator.
func (m *Manager) Open(c Capture) ([]byte, error) {
	if m == nil {
		return nil, ErrDisabled
	}
	if c.Status != StatusStored || c.BlobRef == "" {
		return nil, ErrNotReady
	}
	sealed, err := m.deps.Blobs.Get(c.BlobRef)
	if err != nil {
		return nil, err
	}
	plain, err := m.deps.Sealer.Open(NormTenant(c.TenantID), BlobField(c.DeviceID, c.ID), sealed)
	if err != nil {
		return nil, err
	}
	return []byte(plain), nil
}

// Delete removes one capture row and its sealed blob.
func (m *Manager) Delete(ctx context.Context, p Principal, deviceID, captureID string) error {
	if m == nil {
		return ErrDisabled
	}
	c, err := m.deps.Store.Delete(ctx, p.Tenant, p.Cross, deviceID, captureID)
	if err != nil {
		return err
	}
	if c.BlobRef == "" {
		return nil
	}
	if derr := m.deps.Blobs.Delete(c.BlobRef); derr != nil {
		// The row is gone; a blob that outlived it is a leak of sealed payload
		// nothing can reach. Loud, not silent.
		m.deps.LogError("capture row deleted but its sealed blob remains", map[string]any{
			"device": deviceID, "capture": captureID, "error": m.deps.Scrub(derr.Error())})
		return derr
	}
	return nil
}

// pcapMagic are the four leading bytes of a classic libpcap file, either
// endianness, plus the pcapng Section Header Block. Used ONLY to count frames
// for the listing; a file that is not a pcap yields 0 rather than an error,
// because the bytes are still the operator's capture.
var pcapMagic = [][]byte{
	{0xd4, 0xc3, 0xb2, 0xa1}, // libpcap, little-endian
	{0xa1, 0xb2, 0xc3, 0xd4}, // libpcap, big-endian
	{0x4d, 0x3c, 0xb2, 0xa1}, // libpcap ns, little-endian
	{0xa1, 0xb2, 0x3c, 0x4d}, // libpcap ns, big-endian
}

// countPackets counts records in a classic libpcap stream. It is deliberately
// tolerant: an unrecognized or truncated file reports the records it could read,
// never an error — the packet count is a convenience on the listing, not a
// correctness property, and inventing one would be worse than reporting 0.
func countPackets(b []byte) int {
	if len(b) < 24 {
		return 0
	}
	var le bool
	var known bool
	for i, m := range pcapMagic {
		if b[0] == m[0] && b[1] == m[1] && b[2] == m[2] && b[3] == m[3] {
			le = i == 0 || i == 2
			known = true
			break
		}
	}
	if !known {
		return 0
	}
	n := 0
	off := 24
	for off+16 <= len(b) {
		var caplen uint32
		if le {
			caplen = uint32(b[off+8]) | uint32(b[off+9])<<8 | uint32(b[off+10])<<16 | uint32(b[off+11])<<24
		} else {
			caplen = uint32(b[off+11]) | uint32(b[off+10])<<8 | uint32(b[off+9])<<16 | uint32(b[off+8])<<24
		}
		if caplen > uint32(MaxBytes) {
			return n // a nonsense length: stop rather than walk off the buffer
		}
		next := off + 16 + int(caplen)
		if next > len(b) || next <= off {
			return n
		}
		off = next
		n++
		if n > MaxPackets*2 {
			return n // bounded (§9): never loop on a crafted file
		}
	}
	return n
}

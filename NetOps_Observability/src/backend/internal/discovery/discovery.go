package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"
)

// DiscoverySource is the contract every discovery plugin (Netbox, SNMP
// scan, static YAML, future Kubernetes/CMDB integrations) must satisfy.
type DiscoverySource interface {
	Name() string
	Poll(ctx context.Context) ([]models.Device, error)
	Interval() time.Duration
}

// DiscoveryAggregator multiplexes multiple sources, caches their output,
// and resolves conflicts when the same device id is reported by more
// than one source. Source precedence is registration order — first
// registered wins on conflict.
type DiscoveryAggregator struct {
	mu      sync.RWMutex
	sources []DiscoverySource
	cache   map[string]models.Device
	refresh chan struct{}
	stats   map[string]sourceStats
	// detected holds vendors learned via SNMP sysObjectID detection, keyed by
	// device id. Re-applied on every source poll so a re-poll (which rebuilds
	// the cache entry from the source) doesn't wipe a detected vendor.
	detected map[string]string
	// store persists OPERATOR-CREATED devices and deletion tombstones. Nil-safe:
	// a nil store keeps the old in-memory-only behaviour (tests). Source-reported
	// devices are deliberately NOT persisted — their source is their authority
	// and a persisted shadow would resurrect what pollOnce legitimately prunes.
	// See device_persist.go.
	store DeviceStore
}

type sourceStats struct {
	LastPoll  time.Time `json:"last_poll"`
	LastError string    `json:"last_error,omitempty"`
	Devices   int       `json:"devices"`
}

func NewDiscoveryAggregator() *DiscoveryAggregator {
	return &DiscoveryAggregator{
		cache:    make(map[string]models.Device),
		refresh:  make(chan struct{}, 1),
		stats:    make(map[string]sourceStats),
		detected: make(map[string]string),
	}
}

func (a *DiscoveryAggregator) Register(s DiscoverySource) {
	if s == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sources = append(a.sources, s)
}

func (a *DiscoveryAggregator) Start(ctx context.Context) {
	a.mu.RLock()
	sources := make([]DiscoverySource, len(a.sources))
	copy(sources, a.sources)
	a.mu.RUnlock()
	for _, src := range sources {
		go a.pollLoop(ctx, src)
	}
	if os.Getenv("ENABLE_VENDOR_DETECTION") == "true" {
		go a.vendorLoop(ctx)
	}
}

// vendorLoop periodically fills in the vendor of any inventory device that
// doesn't have one yet, via SNMP sysObjectID detection — the authoritative
// signal (LibreNMS/Observium all lead with it). Devices whose source
// already supplies a vendor (Netbox, static YAML) are left untouched.
func (a *DiscoveryAggregator) vendorLoop(ctx context.Context) {
	community := os.Getenv("SNMP_COMMUNITY")
	if community == "" {
		community = "public"
	}
	a.enrichVendors(ctx, community)
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.enrichVendors(ctx, community)
		}
	}
}

func (a *DiscoveryAggregator) enrichVendors(ctx context.Context, community string) {
	// Snapshot the devices still needing detection (don't hold the lock during
	// the SNMP round-trips).
	type todo struct{ id, addr string }
	a.mu.RLock()
	var pending []todo
	for id, d := range a.cache {
		if d.Address == "" || d.Vendor != "" {
			continue
		}
		if _, done := a.detected[id]; done {
			continue
		}
		pending = append(pending, todo{id, d.Address})
	}
	a.mu.RUnlock()

	for _, p := range pending {
		dctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		vendor, descr := collectors.DetectVendor(dctx, p.addr, community)
		cancel()
		if vendor == "" {
			continue // leave it for a later cycle (negative result not cached)
		}
		a.mu.Lock()
		a.detected[p.id] = vendor
		if d, ok := a.cache[p.id]; ok && d.Vendor == "" {
			d.Vendor = vendor
			if d.OS == "" && descr != "" {
				d.OS = TruncateDescr(descr)
			}
			a.cache[p.id] = d
		}
		a.mu.Unlock()
	}
}

// truncateDescr keeps sysDescr short enough for the inventory's OS column
// while preserving the version phrase Vulnerability Management parses out of
// it — Cisco's verbose sysDescrs put "Version x.y" past the 120-char mark.
// TruncateDescr bounds a sysDescr-style string for display.
func TruncateDescr(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

func (a *DiscoveryAggregator) pollLoop(ctx context.Context, src DiscoverySource) {
	interval := src.Interval()
	if interval <= 0 {
		interval = 60 * time.Second
	}
	a.pollOnce(ctx, src)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.pollOnce(ctx, src)
		case <-a.refresh:
			a.pollOnce(ctx, src)
		}
	}
}

func (a *DiscoveryAggregator) pollOnce(ctx context.Context, src DiscoverySource) {
	devices, err := src.Poll(ctx)
	stat := sourceStats{LastPoll: time.Now().UTC(), Devices: len(devices)}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		// A transient poll failure must NOT prune the source's devices (an
		// outage would wipe the inventory). Record the error and leave the
		// cache as-is; reconciliation only happens on a successful poll.
		stat.LastError = err.Error()
		log.Printf("discovery source %s poll error: %v", src.Name(), err)
		a.stats[src.Name()] = stat
		return
	}
	a.stats[src.Name()] = stat
	// Each registered source is an authoritative lister of its own devices, so
	// its cache contents must equal what it reported THIS poll. Track the ids it
	// returned, then drop any stale entry it still owns but no longer reports —
	// a device removed upstream, or (the case that bit us) a source switched to
	// write-only / disabled so it returns nothing. Without this, flipping the
	// NetBox sync direction read→write at runtime would leave the old netbox-*
	// records lingering as duplicates until a restart.
	seen := make(map[string]bool, len(devices))
	for _, d := range devices {
		// An operator deleted this device: honour that instead of resurrecting
		// it every poll (F-69). Recreating it via POST clears the tombstone.
		//
		// A tombstone is checked against BOTH scan-id derivations, not just the
		// live d.ID, so a delete sticks regardless of which id era it was made
		// in: the pre-hash legacy id ScanDeviceID(name, "") and the current
		// address-hashed id ScanDeviceID(name, addr). ScanDeviceID gained an
		// address-hash suffix mid-flight; a device deleted before OR during that
		// window has its tombstone keyed by the id of that era, which no longer
		// equals today's d.ID. Deriving both from the (name, address) we already
		// have makes suppression order- and era-independent without giving up the
		// address-hash uniqueness (see snapshotLocked). d.ID itself is still
		// checked first so non-SNMP sources (static/netbox), whose ids are not
		// scan ids, keep honouring their own tombstones.
		if a.store != nil && (a.store.IsSuppressed(d.ID) ||
			a.store.IsSuppressed(ScanDeviceID(d.Name, "")) ||
			a.store.IsSuppressed(ScanDeviceID(d.Name, d.Address))) {
			continue
		}
		existing, ok := a.cache[d.ID]
		if ok && existing.Source != src.Name() {
			continue // higher-precedence source already won this id
		}
		seen[d.ID] = true
		d.Source = src.Name()
		d.LastSeen = time.Now().UTC()
		if d.Vendor == "" {
			if v, ok := a.detected[d.ID]; ok {
				d.Vendor = v
			}
		}
		a.cache[d.ID] = d
	}
	for id, d := range a.cache {
		if d.Source == src.Name() && !seen[id] {
			delete(a.cache, id)
		}
	}
}

// PollOnceForTest runs a single synchronous poll of src into the cache — test
// support for seeding an aggregator without the poll loop.
func (a *DiscoveryAggregator) PollOnceForTest(ctx context.Context, src DiscoverySource) {
	a.pollOnce(ctx, src)
}

func (a *DiscoveryAggregator) RefreshNow() {
	select {
	case a.refresh <- struct{}{}:
	default:
	}
}

// Devices returns the de-duplicated device inventory. The cache is keyed by
// source-prefixed ID (snmp-…/netbox-…/static-…), so the SAME physical device seen
// by multiple sources would otherwise appear multiple times. We collapse entries
// that share a STABLE identity (mgmt IP → serial → normalized name) into one,
// preferring the NetBox record (richer source-of-truth metadata) and folding in
// the live discovery fields (vendor/model/status/last-seen). Collectors read this
// too, so each physical device is polled once.
func (a *DiscoveryAggregator) Devices() []models.Device {
	a.mu.RLock()
	defer a.mu.RUnlock()
	devices, _ := dedupeWithOwners(a.cache)
	return devices
}

// ResolveIdentity reports what became of the record stored under cacheID once
// cross-source identity merging has run.
//
// TRACKER 161. A create can be absorbed: two records that share an identity
// token (management IP, serial, or normalized name) are the same physical
// device, so one of them stops existing as its own row. The caller of
// POST /api/devices must be told when that happened to ITS device, because
// nothing downstream will ever key on the name it chose — the tenant-enrichment
// export writes the SURVIVOR's name, so telemetry bearing the absorbed name is
// unattributable forever.
//
// Returns the surviving record, whether it kept cacheID's own identity, and
// whether the record was found at all. The answer is derived from the same
// dedupe the read path uses, so it cannot drift from what /api/devices shows.
func (a *DiscoveryAggregator) ResolveIdentity(cacheID string) (models.Device, bool, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	devices, owners := dedupeWithOwners(a.cache)
	ownerID, ok := owners[cacheID]
	if !ok {
		return models.Device{}, false, false
	}
	for _, d := range devices {
		if d.ID == ownerID {
			return d, ownerID == cacheID, true
		}
	}
	return models.Device{}, false, false
}

// dedupeDevices collapses per-source records of the same physical device into
// one. Cross-source identity is NOT a single key — a device seen by SNMP is
// keyed by management IP, but its NetBox twin (synced create-only, so it carries
// the name + serial but no primary IP) shares no IP. So records are unioned when
// they agree on ANY stable identity (IP, serial, OR normalized name): the SNMP
// record (ip + name) and the NetBox record (name + maybe serial) merge on name.
// This is the same multi-identity matching the compliance pairing uses; doing it
// here is what stops the Infrastructure inventory from showing each synced device
// twice. Pure (operates on the passed map) so it is unit-testable.
func dedupeDevices(cache map[string]models.Device) []models.Device {
	out, _ := dedupeWithOwners(cache)
	return out
}

// dedupeWithOwners is dedupeDevices plus the mapping every input cache id ->
// the id of the merged record that now represents it. ResolveIdentity needs
// that mapping, and deriving it here rather than reimplementing the union-find
// is what stops the two answers drifting apart (tracker 161).
func dedupeWithOwners(cache map[string]models.Device) ([]models.Device, map[string]string) {
	// Stable iteration: sort the source-prefixed IDs so the merge result and
	// ordering are deterministic regardless of Go's map iteration order.
	ids := make([]string, 0, len(cache))
	for id := range cache {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	// Union-find over record indices, linked by shared identity tokens.
	parent := make([]int, len(ids))
	for i := range parent {
		parent[i] = i
	}
	find := func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	union := func(i, j int) { parent[find(i)] = find(j) }

	// First record that claimed each identity token; subsequent claimants union.
	// Tokens are TENANT-PARTITIONED (identityTokens), so a merge can never cross
	// a tenant boundary — see identityTokens.
	seen := make(map[string]int, len(ids)*2)
	for i, id := range ids {
		for _, tok := range identityTokens(cache[id]) {
			if j, ok := seen[tok]; ok {
				union(i, j)
			} else {
				seen[tok] = i
			}
		}
	}

	// Fold each group (in first-seen order) into one merged device.
	merged := make(map[int]models.Device, len(ids))
	order := make([]int, 0, len(ids))
	for i, id := range ids {
		root := find(i)
		if cur, ok := merged[root]; ok {
			merged[root] = mergeDevices(cur, cache[id])
		} else {
			merged[root] = cache[id]
			order = append(order, root)
		}
	}
	out := make([]models.Device, 0, len(order))
	for _, root := range order {
		out = append(out, merged[root])
	}
	owners := make(map[string]string, len(ids))
	for i, id := range ids {
		owners[id] = merged[find(i)].ID
	}
	return out, owners
}

// RawDevices returns the per-source records BEFORE cross-source merging — the
// same physical device may appear once per source (netbox-…, static-…, manual).
// Compliance drift detection needs both sides of a pair (NetBox intent vs the
// observed/operator record) that Devices() folds into one.
func (a *DiscoveryAggregator) RawDevices() []models.Device {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]models.Device, 0, len(a.cache))
	for _, d := range a.cache {
		out = append(out, d)
	}
	return out
}

// deviceIdentities returns every stable identity token a record carries:
// management IP, serial (from labels), and normalized name. Two records that
// share ANY token are the same physical device — even if one (e.g. an SNMP
// poll) has an IP the other (an IP-less synced NetBox record) lacks, they still
// collapse via the shared name or serial. Empty/normalized-empty tokens are
// dropped so a missing field can't accidentally union unrelated devices.
// DeviceIdentities lists a device's stable identity keys (id, name, address).
func DeviceIdentities(d models.Device) []string {
	var out []string
	if ip := strings.TrimSpace(d.Address); ip != "" {
		out = append(out, "ip:"+ip)
	}
	if sn := strings.TrimSpace(d.Labels["serial"]); sn != "" {
		out = append(out, "sn:"+strings.ToLower(sn))
	}
	if nm := strings.ToLower(strings.TrimSpace(d.Name)); nm != "" {
		out = append(out, "name:"+nm)
	}
	return out
}

// deviceTenantKey is the normalized owning tenant of a record. "" is NOT a
// wildcard: untagged means platform-scoped ("discovered infrastructure is
// platform-scoped until an operator assigns it" — snmp_source.go), which is its
// own partition.
func deviceTenantKey(d models.Device) string {
	return strings.ToLower(strings.TrimSpace(d.TenantID))
}

// identityTokens is DeviceIdentities partitioned by owning tenant.
//
// §3a: identity resolution must never cross a tenant boundary. Two tenants may
// legitimately run the same RFC1918 management address or the same hostname
// (`core-sw01`); those are DIFFERENT devices. Unioning them would fold one
// tenant's row into the other's — the merged record carries a single TenantID,
// so the loser's owner either sees a device that is not theirs or loses sight of
// their own. Prefixing every token with the tenant makes the union-find in
// dedupeWithOwners partition by tenant, which is the storage-layer enforcement
// §3a rule 4 asks for. Untagged (platform) records keep their existing
// behaviour: they share the "" partition with each other.
func identityTokens(d models.Device) []string {
	tenant := deviceTenantKey(d)
	toks := DeviceIdentities(d)
	out := make([]string, 0, len(toks))
	for _, tok := range toks {
		// NUL separator: no tenant id or identity token can contain one, so the
		// partition prefix can never be forged by a crafted name/address.
		out = append(out, tenant+"\x00"+tok)
	}
	return out
}

// mergeDevices folds two records for the same physical device into one. The
// NetBox record (source of truth) is the base when present; the other record
// fills gaps and contributes the freshest live signal (vendor/model/status via
// labels, last-seen, credential ref for polling).
func mergeDevices(x, y models.Device) models.Device {
	base, other := x, y
	if y.Source == "netbox" && x.Source != "netbox" {
		base, other = y, x
	}
	if base.Vendor == "" {
		base.Vendor = other.Vendor
	}
	if base.Model == "" {
		base.Model = other.Model
	}
	if base.OS == "" {
		base.OS = other.OS
	}
	if base.Address == "" {
		base.Address = other.Address
	}
	if base.Name == "" {
		base.Name = other.Name
	}
	if base.CredentialRef == "" {
		base.CredentialRef = other.CredentialRef // keep the SNMP cred so collectors can poll
	}
	if base.PreferredProtocol == "" {
		base.PreferredProtocol = other.PreferredProtocol
	}
	if other.LastSeen.After(base.LastSeen) {
		base.LastSeen = other.LastSeen
	}
	// COPY-ON-WRITE: base/other are struct copies, but their Labels field still
	// points at the LIVE map in the discovery cache. dedupeDevices runs under a
	// read lock and Devices() callers keep the returned maps past the lock, so an
	// in-place write here is a concurrent map read/write — a fatal runtime error
	// (crashed the API in production the moment two records merged on one IP).
	crossSource := base.Source != other.Source && other.Source != ""
	if len(other.Labels) > 0 || crossSource {
		merged := make(map[string]string, len(base.Labels)+len(other.Labels)+1)
		for k, v := range base.Labels {
			merged[k] = v
		}
		for k, v := range other.Labels {
			if _, ok := merged[k]; !ok {
				merged[k] = v
			}
		}
		if crossSource {
			// Record multi-source corroboration (e.g. "snmp+netbox") for the UI.
			merged["sources"] = base.Source + "+" + other.Source
		}
		base.Labels = merged
	}
	return base
}

func (a *DiscoveryAggregator) Get(id string) (models.Device, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	d, ok := a.cache[id]
	return d, ok
}

// SetStore attaches the persistence layer and seeds the cache from it. Called
// once at startup, before Start(), so operator-created devices exist before the
// first poll and before the API serves a request.
// NetboxConfig is the NetBox connection + sync-direction config (persisted by
// the integrator's netbox_config store; the source only reads it).
type NetboxConfig struct {
	Enabled     bool   `json:"enabled"`
	URL         string `json:"url"`
	Token       string `json:"token,omitempty"`
	IntervalSec int    `json:"interval_sec"` // poll cadence; 0 → default 60s
	// Direction: "none" (default) | "write" | "read" | "both" — see the
	// integrator's netbox_config.go for the full doctrine.
	Direction string `json:"direction,omitempty"`
	// Managed is derived (not persisted): the platform-bundled internal NetBox.
	Managed bool `json:"managed,omitempty"`
}

// NetboxDirection normalizes the direction ("" → none).
func NetboxDirection(c NetboxConfig) string {
	switch d := strings.ToLower(strings.TrimSpace(c.Direction)); d {
	case "write", "read", "both":
		return d
	default:
		return "none"
	}
}

// NetboxReadsDevices / NetboxWritesDevices report which way devices flow.
func NetboxReadsDevices(c NetboxConfig) bool {
	d := NetboxDirection(c)
	return d == "read" || d == "both"
}

func NetboxWritesDevices(c NetboxConfig) bool {
	d := NetboxDirection(c)
	return d == "write" || d == "both"
}

// DeviceStore is the injected persistence seam for manual devices and F-69
// delete-suppression (implemented by main's deviceStore).
type DeviceStore interface {
	IsSuppressed(id string) bool
	Put(d models.Device) error
	Remove(id string) error
	Devices() []models.Device
}

func (a *DiscoveryAggregator) SetStore(st DeviceStore) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.store = st
	for _, d := range st.Devices() {
		if d.Source == "" {
			d.Source = "manual"
		}
		// F-8 repair: rows persisted before the empty-id guard existed are
		// keyed "" and unaddressable through the API. Heal them at load —
		// derive the id the same way the create path now does, persist under
		// the new key, drop the "" row. A row with nothing to derive from is
		// dropped LOUDLY: it identifies no device and can never be addressed.
		if strings.TrimSpace(d.ID) == "" {
			derived := ScanDeviceID(d.Name, d.Address)
			if derived == "" {
				log.Printf("device store: dropping anonymous row (no id/name/address) — unaddressable (F-8): %+v", d)
				if err := st.Remove(""); err != nil {
					log.Printf("device store: could not remove anonymous row: %v", err)
				}
				continue
			}
			d.ID = derived
			if err := st.Put(d); err != nil {
				// Keep the row visible in RAM under the derived id even if the
				// re-key could not persist; the next boot retries the repair.
				log.Printf("device store: could not persist repaired id %q: %v", derived, err)
			} else if err := st.Remove(""); err != nil {
				log.Printf("device store: repaired %q but could not drop the old anonymous row: %v", derived, err)
			}
			log.Printf("device store: repaired empty-id row -> %q (F-8)", derived)
		}
		a.cache[d.ID] = d
	}
}

// Upsert records an operator-created device and PERSISTS it.
//
// This used to be an in-memory map write with no persistence anywhere, so
// POST /api/devices returned 201 Created for a device that evaporated on the
// next restart, container recreate, crash, deploy or documented upgrade — a 2xx
// for a write that never landed. It now returns error so the handler can refuse
// to claim success; the cache is only updated once the store has accepted it,
// so RAM never claims a device the store does not have.
func (a *DiscoveryAggregator) Upsert(d models.Device) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.upsertLocked(d)
}

// upsertLocked is Upsert's body; CreateOrResolve needs the store write and the
// identity resolution to happen under ONE hold of the lock (see there).
// Caller holds a.mu.
func (a *DiscoveryAggregator) upsertLocked(d models.Device) error {
	// F-8: an empty id persists a ""-keyed row no API path can ever address
	// again (DELETE /api/devices/{id} cannot express it). The handler derives
	// ids before calling here; this guard is the storage-layer enforcement so
	// no future caller can reintroduce the row class.
	if strings.TrimSpace(d.ID) == "" {
		return errors.New("device id required (an empty id would persist an unaddressable row)")
	}
	if d.Source == "" {
		d.Source = "manual"
	}
	d.LastSeen = time.Now().UTC()
	// Only manual devices persist; a source-owned record is rebuilt by its
	// source and must not be shadowed here.
	if d.Source == "manual" && a.store != nil {
		if err := a.store.Put(d); err != nil {
			return err
		}
	}
	a.cache[d.ID] = d
	return nil
}

// CreateOrResolve is the operator-create path: it persists d ONLY when d's
// identity is genuinely new, and reports the device that actually represents
// that identity either way.
//
// TRACKER 181. Upsert-then-ResolveIdentity wrote the requested row FIRST and
// only then asked what became of it, so a create that dedupe absorbed still
// persisted its own row: a SHADOW — invisible to GET /api/devices (the read
// path shows the merged survivor), still addressable by DELETE, and it
// SURFACES the moment the absorber is deleted. Two overlapping scale runs left
// 1,000 such rows that no prefix-scoped cleanup could list. Resolving first and
// declining to write is what makes GET and DELETE agree about what exists.
//
// Returns (canonical, created, err):
//
//	created=true  — d was new, was persisted, and owns its own identity (201)
//	created=false — the identity already exists; NOTHING was written and
//	                canonical is the device that owns it (200)
//
// Atomic: the check and the write share one hold of a.mu, so two concurrent
// creates of the same identity cannot both decide they are new and race a
// shadow row into the cache.
func (a *DiscoveryAggregator) CreateOrResolve(d models.Device) (models.Device, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	id, err := a.tenantSafeIDLocked(d)
	if err != nil {
		return models.Device{}, false, err
	}
	d.ID = id
	if canonical, absorbed := a.absorbedByLocked(d); absorbed {
		return canonical, false, nil
	}
	if err := a.upsertLocked(d); err != nil {
		return models.Device{}, false, err
	}
	devices, owners := dedupeWithOwners(a.cache)
	ownerID, ok := owners[d.ID]
	if !ok {
		// Stored but not projected — report the store's own view rather than
		// inventing a verdict.
		return a.cache[d.ID], true, nil
	}
	for _, dev := range devices {
		if dev.ID == ownerID {
			return dev, ownerID == d.ID, nil
		}
	}
	return a.cache[d.ID], ownerID == d.ID, nil
}

// tenantSafeIDLocked returns a cache key for a create that cannot overwrite
// ANOTHER tenant's row.
//
// §3a. The cache is keyed by id, and an operator-created id is derived from
// (name, address) — both tenant-independent. Two tenants legitimately running
// `core-sw01` on 10.10.0.1 therefore derived the SAME key, and the second
// create silently REPLACED the first tenant's device: a cross-tenant write, and
// a device that vanished from its owner's inventory with a 201 reported to
// somebody else. (Same failure mode ScanDeviceID's address hash was introduced
// to stop — see snmp_source.go — one key, two devices, one silently gone.)
//
// The id is namespaced ONLY when it would collide across tenants, so ids are
// unchanged for every non-colliding create, including every untagged
// (platform-scoped) one. A re-onboard does not fragment: it derives the bare id
// again, and absorbedByLocked folds it into the tenant's existing record via
// the shared identity tokens.
// Caller holds a.mu.
func (a *DiscoveryAggregator) tenantSafeIDLocked(d models.Device) (string, error) {
	cur, exists := a.cache[d.ID]
	if !exists || deviceTenantKey(cur) == deviceTenantKey(d) {
		return d.ID, nil
	}
	// Suffix with a stable tag for the OWNING tenant (not the incumbent's), so
	// the same tenant re-deriving this key lands on the same row every time.
	scoped := d.ID + "-" + shortAddrHash("tenant:"+deviceTenantKey(d))
	if other, taken := a.cache[scoped]; taken && deviceTenantKey(other) != deviceTenantKey(d) {
		// Astronomically unlikely (8 hex chars over a tenant id, and only when
		// the bare id collides too). Refusing the write is the only safe answer;
		// overwriting another tenant's device is exactly the failure being fixed.
		return "", fmt.Errorf("device id %q is held by another tenant", d.ID)
	}
	return scoped, nil
}

// absorbedByLocked reports whether a NEW record d would be absorbed by an
// existing one, and if so which device owns that identity today.
//
// A record joins a dedupe group only through a shared identity token, so
// "shares a token with something already in the cache" is exactly "would not
// exist as its own row". The candidate is NOT added to the cache to find that
// out — that is the whole point (tracker 181).
//
// Tokens are tenant-partitioned (identityTokens), so an identical address or
// hostname in ANOTHER tenant is not a match and that create proceeds
// independently (§3a).
//
// A d.ID that is already in the cache is not a create at all: it rewrites an
// existing row, which cannot add a shadow, so it is left to the normal upsert.
// Caller holds a.mu.
func (a *DiscoveryAggregator) absorbedByLocked(d models.Device) (models.Device, bool) {
	if _, exists := a.cache[d.ID]; exists {
		return models.Device{}, false
	}
	want := identityTokens(d)
	if len(want) == 0 {
		return models.Device{}, false // nothing to match on; it can only stand alone
	}
	set := make(map[string]bool, len(want))
	for _, tok := range want {
		set[tok] = true
	}
	// Deterministic winner when several existing records match: the smallest
	// cache id, the same ordering dedupeWithOwners uses.
	ids := make([]string, 0, len(a.cache))
	for id := range a.cache {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	match := ""
	for _, id := range ids {
		for _, tok := range identityTokens(a.cache[id]) {
			if set[tok] {
				match = id
				break
			}
		}
		if match != "" {
			break
		}
	}
	if match == "" {
		return models.Device{}, false
	}
	devices, owners := dedupeWithOwners(a.cache)
	if ownerID, ok := owners[match]; ok {
		for _, dev := range devices {
			if dev.ID == ownerID {
				return dev, true
			}
		}
	}
	// The projection could not name an owner. Still absorbed — report the raw
	// matching record rather than falling through to a write, because writing
	// is the defect.
	return a.cache[match], true
}

// Delete removes a device and records a TOMBSTONE so it stays deleted.
//
// F-69: this used to be a bare cache delete, so DELETE returned 204 and the
// owning source re-added the device within 60s on its next poll. The operator
// was told the device was gone and it was not. The suppression below is honoured
// by pollOnce, so a delete now means what it says.
func (a *DiscoveryAggregator) Delete(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.store != nil {
		if err := a.store.Remove(id); err != nil {
			return err
		}
	}
	delete(a.cache, id)
	return nil
}

func (a *DiscoveryAggregator) Health() map[string]sourceStats {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make(map[string]sourceStats, len(a.stats))
	for k, v := range a.stats {
		out[k] = v
	}
	return out
}

// =============================================================================
// Static source — reads a small YAML file off disk.
// =============================================================================

type StaticSource struct {
	path string
}

func NewStaticSource(path string) *StaticSource {
	if path == "" {
		path = "/config/devices.yaml"
	}
	return &StaticSource{path: path}
}

func (s *StaticSource) Name() string            { return "static" }
func (s *StaticSource) Interval() time.Duration { return 60 * time.Second }
func (s *StaticSource) Poll(_ context.Context) ([]models.Device, error) {
	return ParseStaticDevices(s.path)
}

// ParseStaticDevices reads a YAML file shaped like:
//
//	devices:
//	  core-router-01:
//	    address: 10.0.0.1
//	    preferred_protocol: snmp
//	    credential_ref: corp-snmp
//	    labels:
//	      site: hq
//
// We accept this narrow shape only — the parser is hand-rolled to keep
// the build dependency-free. Swap for `gopkg.in/yaml.v3` when you need
// anchors, multi-doc, or arbitrary nesting.
func ParseStaticDevices(path string) ([]models.Device, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return parseStaticDevicesYAML(string(b))
}

func parseStaticDevicesYAML(s string) ([]models.Device, error) {
	var devices []models.Device
	var cur *models.Device
	inDevices := false
	inLabels := false
	labelIndent := -1

	flush := func() {
		if cur != nil && cur.ID != "" {
			devices = append(devices, *cur)
		}
		cur = nil
		inLabels = false
		labelIndent = -1
	}

	for _, raw := range strings.Split(s, "\n") {
		line := raw
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		trim := strings.TrimRight(line, " \t\r")
		if strings.TrimSpace(trim) == "" {
			continue
		}
		indent := indentOf(trim)
		body := strings.TrimSpace(trim)

		// Top-level
		if indent == 0 {
			flush()
			inDevices = body == "devices:"
			continue
		}
		if !inDevices {
			continue
		}
		// Device key: 2-space indented "name:"
		if indent == 2 && strings.HasSuffix(body, ":") {
			flush()
			cur = &models.Device{ID: strings.TrimSuffix(body, ":"), Name: strings.TrimSuffix(body, ":")}
			continue
		}
		if cur == nil {
			continue
		}
		// Inside labels block
		if inLabels && indent > labelIndent {
			if k, v, ok := splitKV(body); ok {
				if cur.Labels == nil {
					cur.Labels = map[string]string{}
				}
				cur.Labels[k] = unquoteValue(v)
			}
			continue
		}
		inLabels = false
		// Device fields
		switch {
		case strings.HasPrefix(body, "address:"):
			cur.Address = unquoteValue(strings.TrimSpace(strings.TrimPrefix(body, "address:")))
		case strings.HasPrefix(body, "preferred_protocol:"):
			cur.PreferredProtocol = unquoteValue(strings.TrimSpace(strings.TrimPrefix(body, "preferred_protocol:")))
		case strings.HasPrefix(body, "credential_ref:"):
			cur.CredentialRef = unquoteValue(strings.TrimSpace(strings.TrimPrefix(body, "credential_ref:")))
		case strings.HasPrefix(body, "vendor:"):
			cur.Vendor = unquoteValue(strings.TrimSpace(strings.TrimPrefix(body, "vendor:")))
		case strings.HasPrefix(body, "model:"):
			cur.Model = unquoteValue(strings.TrimSpace(strings.TrimPrefix(body, "model:")))
		case strings.HasPrefix(body, "os:"):
			cur.OS = unquoteValue(strings.TrimSpace(strings.TrimPrefix(body, "os:")))
		case body == "labels:":
			inLabels = true
			labelIndent = indent
		}
	}
	flush()
	return devices, nil
}

func indentOf(s string) int {
	n := 0
	for _, c := range s {
		if c == ' ' {
			n++
		} else if c == '\t' {
			n += 2
		} else {
			break
		}
	}
	return n
}

func splitKV(s string) (string, string, bool) {
	i := strings.Index(s, ":")
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
}

func unquoteValue(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// =============================================================================
// SNMP subnet-scan source lives in snmp_discovery.go (real prober + its
// platform-owner runtime config; was a no-op stub until #91).
// =============================================================================

// =============================================================================
// Netbox source — real HTTP client.
// =============================================================================

type NetboxSource struct {
	warn   func(msg string, fields map[string]any)
	cfg    func() NetboxConfig // live config (UI-set store, env fallback)
	client *http.Client
}

// NewNetboxSource takes a live config getter so the poller honors runtime changes
// from the Automation → Source of Truth UI without a restart, falling back to env.
func NewNetboxSource(cfg func() NetboxConfig, warn func(msg string, fields map[string]any)) *NetboxSource {
	if warn == nil {
		warn = func(string, map[string]any) {}
	}
	return &NetboxSource{
		cfg:    cfg,
		warn:   warn,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (n *NetboxSource) Name() string { return "netbox" }
func (n *NetboxSource) Interval() time.Duration {
	if c := n.cfg(); c.IntervalSec > 0 {
		return time.Duration(c.IntervalSec) * time.Second
	}
	return 60 * time.Second
}

// netboxDevice is the subset of /dcim/devices/ we care about.
type netboxDevice struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Serial    string `json:"serial"`
	PrimaryIP *struct {
		Address string `json:"address"`
	} `json:"primary_ip"`
	DeviceType *struct {
		Manufacturer *struct {
			Name string `json:"name"`
		} `json:"manufacturer"`
		Model string `json:"model"`
	} `json:"device_type"`
	Platform *struct {
		Name string `json:"name"`
	} `json:"platform"`
	Site *struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	} `json:"site"`
	Tags []struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	} `json:"tags"`
}

type netboxResp struct {
	Count   int            `json:"count"`
	Next    *string        `json:"next"`
	Results []netboxDevice `json:"results"`
}

func (n *NetboxSource) Poll(ctx context.Context) ([]models.Device, error) {
	cfg := n.cfg()
	nbURL := strings.TrimRight(cfg.URL, "/")
	token := cfg.Token
	if !cfg.Enabled || nbURL == "" || token == "" {
		return nil, nil // unconfigured / disabled → no-op (not an error)
	}
	// Sync direction: in write-only mode (the default) NetBox is a downstream
	// mirror, never a device source — so synced devices can't flow back into the
	// inventory as duplicates. Only "read"/"both" poll devices.
	if !NetboxReadsDevices(cfg) {
		return nil, nil
	}

	// SR-023: the API token rides in the Authorization header on EVERY request,
	// including the upstream-supplied `next` pagination URL. A compromised or
	// MITM'd Netbox could point `next` at an attacker host and harvest the token
	// (and SSRF the backend). Pin pagination to the configured instance's host.
	base, err := url.Parse(nbURL)
	if err != nil {
		return nil, fmt.Errorf("netbox: invalid URL %q: %w", nbURL, err)
	}
	if base.Host == "" {
		// Parsed fine but carries no host (e.g. "netbox.example" with no scheme).
		// Wrapping a nil err here printed "%!w(<nil>)" and told the operator
		// nothing about which of the two failures happened.
		return nil, fmt.Errorf("netbox: invalid URL %q: no host (a scheme is required, e.g. https://…)", nbURL)
	}

	// Page through /dcim/devices/?limit=200.
	next := nbURL + "/api/dcim/devices/?limit=200"
	var out []models.Device
	for next != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return out, err
		}
		req.Header.Set("Authorization", "Token "+token)
		req.Header.Set("Accept", "application/json")

		resp, err := n.client.Do(req)
		if err != nil {
			return out, err
		}
		if resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512)) // best-effort: diagnostic snippet; a read error just leaves it empty
			resp.Body.Close()
			return out, fmt.Errorf("netbox %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		var page netboxResp
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			resp.Body.Close()
			return out, err
		}
		resp.Body.Close()

		for _, d := range page.Results {
			dev := models.Device{
				ID:     fmt.Sprintf("netbox-%d", d.ID),
				Name:   d.Name,
				Labels: map[string]string{},
			}
			if d.PrimaryIP != nil && d.PrimaryIP.Address != "" {
				// "10.0.0.1/24" → "10.0.0.1"
				addr := d.PrimaryIP.Address
				if i := strings.Index(addr, "/"); i > 0 {
					addr = addr[:i]
				}
				dev.Address = addr
			}
			if d.DeviceType != nil {
				dev.Model = d.DeviceType.Model
				if d.DeviceType.Manufacturer != nil {
					dev.Vendor = d.DeviceType.Manufacturer.Name
				}
			}
			if d.Platform != nil {
				dev.OS = d.Platform.Name
			}
			if sn := strings.TrimSpace(d.Serial); sn != "" {
				// Carry the serial so a NetBox device with no primary IP still
				// dedupes against its SNMP twin on the serial identity.
				dev.Labels["serial"] = sn
			}
			if d.Site != nil {
				dev.Labels["site"] = d.Site.Slug
			}
			for _, t := range d.Tags {
				dev.Labels["tag_"+t.Slug] = "true"
			}
			out = append(out, dev)
		}

		// Advance to the next page only if Netbox supplied an absolute URL on the
		// SAME host as the configured instance (SR-023) — never follow a
		// cross-host `next` (it would leak the token / SSRF).
		next = ""
		if page.Next != nil && *page.Next != "" {
			nu, perr := url.Parse(*page.Next)
			switch {
			case perr != nil || (nu.Scheme != "http" && nu.Scheme != "https"):
				n.warn("netbox: ignoring malformed pagination URL", nil)
			case !strings.EqualFold(nu.Host, base.Host):
				n.warn("netbox: ignoring cross-host pagination URL", map[string]any{"got": nu.Host, "want": base.Host})
			default:
				next = *page.Next
			}
		}
	}

	return out, nil
}

// Quiet unused-import lint if url is ever removed; keeps it stable.
var _ = url.Parse

package discovery

import (
	"sort"
	"time"
)

// devstore_compact.go — BOUNDING TOMBSTONE GROWTH (tracker 175).
//
// THE DEFECT. Every `DELETE /api/devices/{id}` writes one suppression record
// and NOTHING ever removed it. A lab that had run the scale ladder for weeks
// held 35,427 tombstones / 142 MB for ZERO real devices (≈4 KiB of filesystem
// block per ~90-byte record). The acute symptom — a >6 min synchronous boot
// read that wedged the api before it reached its listener — was fixed by
// parallelising FileKV.LoadPrefix (6b79ea58), but that raised the ceiling, it
// did not put one in place: each 2,500-device create+delete run adds another
// 2,500 records forever, and the 5k/10k ladder multiplies that 2–4×.
//
// ---------------------------------------------------------------------------
// RESURRECTION SEMANTICS — READ THIS BEFORE CHANGING ANY BOUND
// ---------------------------------------------------------------------------
//
// A tombstone is NOT a log entry. It is the ONLY thing standing between a
// deleted device and its resurrection. pollOnce consults it for every device a
// source reports (against the live id AND both ScanDeviceID eras), and drops
// the device when it is suppressed. Delete the tombstone and the very next poll
// re-adds the device — the F-69 defect, restored.
//
// So the naive reading of "compact tombstones older than the longest replay
// horizon" is UNSAFE, and we do not implement it. A source does not replay a
// device once and stop: NetBox lists the same device on EVERY poll, forever,
// until an operator removes it upstream; the SNMP source re-probes any address
// that is not already in inventory on every sweep (snmp_source.go builds
// `knownAddr` from the CACHE, and a deleted device is not in the cache — so a
// deleted, still-live device is re-discovered every sweep, forever). There is
// therefore NO age measured from `deleted_at` after which a tombstone is
// automatically safe to drop. A tombstone that is doing its job at t+24 h is
// still doing its job at t+24 y.
//
// What IS decidable is whether a tombstone is doing its job AT ALL. A source
// that can resurrect the id must PRESENT it, and presenting it hits the
// tombstone. So the store records the instant a tombstone last suppressed
// something (`last_hit`) and retention is measured from
//
//	lastActivity = max(deleted_at, last_hit)
//
// — "the last time this suppression was either created or actually needed" —
// not from deleted_at alone. A tombstone that a live source keeps trying to
// resurrect refreshes itself on every poll and is retained indefinitely; that
// is correct, and it is not unbounded, because a tombstone can only be hit by a
// device some source actually reports, so the actively-suppressing set is
// bounded by the fleet size, which is bounded by the operator's network.
//
// THE HORIZON: 24 h (DefaultTombstoneTTL). Justified from the code, longest
// first:
//   - SNMPSource.Interval()  = 5 min, floored by ScanCooldown = 60 s;
//   - StaticSource.Interval() = 60 s;
//   - NetboxSource.Interval() = operator-set NetboxConfig.IntervalSec, default
//     60 s (an operator may raise it; hours would be extreme);
//   - pollLoop's fallback for a source that reports <= 0 = 60 s.
//
// The slowest *complete* cycle in the code is therefore an SNMP sweep at 5 min
// (a wide-range sweep takes longer in wall-clock, but it re-probes on every
// sweep, so it hits the tombstone on the first one that reaches the address).
// 24 h is 288x the slowest interval and, more importantly, absorbs the failure
// modes that a poll interval does not: a source disabled and re-enabled the
// same day, a NetBox outage, a container restart, an operator flipping the
// NetBox sync direction write->read. Below 24 h an overnight source outage
// could drop a load-bearing tombstone; far above it the bound stops being one.
// The number is a TombstoneLimits field, so a deployment with a genuinely
// slower source can raise it without touching this logic.
//
// Kafka retention is deliberately NOT in that list: no device-discovery source
// replays from the bus. Sources are polled (SNMP probe, NetBox HTTP, static
// YAML file), so bus retention cannot resurrect a device.
//
// ---------------------------------------------------------------------------
// THE BOUND
// ---------------------------------------------------------------------------
//
// Two tiers, in strict order, evicting OLDEST-lastActivity-first:
//
//  1. EXPIRED — lastActivity older than TTL. Nothing has needed this
//     suppression for a full day of continuous polling by every configured
//     source. Safe, unconditional, tenant-blind (expiry is equally safe for
//     everyone).
//
//  2. OVER CAP — while count > Max (10,000 ≈ 40 MB on the file backend, 3.8x
//     under the 38,666 that wedged the lab). This tier is a SAFETY VALVE, not
//     routine hygiene, so it is deliberately narrow:
//     - it only ever considers tombstones with NO recorded hit. A tombstone a
//     source is actively trying to resurrect is NEVER cap-evicted; that is
//     the correctness invariant of this file.
//     - it drains the tenant holding the MOST such tombstones first (§3a), so
//     one tenant's create/delete churn can never evict another tenant's
//     suppressions. Rebuilds rotate to whoever is largest next.
//     - every pass that cap-evicts says so through errf (§10) — it is a
//     deliberate degradation, never silent.
//     If every tombstone over the cap is hit-protected the count is allowed to
//     exceed Max rather than resurrect a device; that residue is bounded by the
//     fleet, per the argument above.
//
// INCREMENTAL, NEVER STOP-THE-WORLD. Growth is Remove-driven, so compaction is
// Remove-driven: each Remove that already does one record write also does at
// most `Budget` (64) record deletes, from a candidate queue built lazily
// (O(N log N) once per ~4,096 evictions, and at most once per minute when
// nothing is evictable). Boot runs ONE bounded pass (BootBudget, 4,096) so an
// existing residue drains over a few boots instead of turning the boot read
// into a 35k-unlink stall — the 6b79ea58 wedge must not come back through this
// door. Nothing scans the whole store on a serving path.
//
// BOOT IS EXPIRED-TIER ONLY. `last_hit` is durable but rate-limited (persisted
// at most once per HitPersistInterval per tombstone, and only from a pass that
// is already scanning), so immediately after boot the in-memory hit picture is
// incomplete. The cap tier is therefore gated on the store having been up for
// HitObservationWindow (15 min > the 5 min slowest poll interval), long enough
// for every configured source to have polled at least once and hit whatever it
// was going to hit. Before that only the expired tier — which reads the durable
// deleted_at/last_hit — can evict.
//
// PER-RECORD MODE ONLY. The whole-blob fallback (non-prefix backends: test
// fakes) rewrites everything on every write and has no scale story; leaving it
// untouched keeps its crash/rollback reasoning exactly as audited.

const (
	// DefaultTombstoneTTL is the retention horizon measured from
	// lastActivity = max(deleted_at, last_hit). See the header for the
	// derivation from the source poll intervals.
	DefaultTombstoneTTL = 24 * time.Hour
	// DefaultTombstoneMax is the hard count cap (~40 MB on the file backend).
	DefaultTombstoneMax = 10000

	defaultEvictBudget          = 64
	defaultBootEvictBudget      = 4096
	defaultHitObservationWindow = 15 * time.Minute
	defaultHitPersistInterval   = time.Hour

	// evictQueueLimit bounds one lazily-built candidate queue, so a build is
	// O(N log N) at most once per this many evictions.
	evictQueueLimit = 4096
	// evictScanCooldown throttles rebuilds when the last one found nothing
	// evictable and the store is under its cap.
	evictScanCooldown = time.Minute
	// hitFlushPerScan bounds the record writes one queue build may spend
	// making in-memory hits durable (§9: bounded IO).
	hitFlushPerScan = 64
)

// TombstoneLimits is the injected retention policy (§2: dependencies explicit
// and injectable). The zero value means "defaults" — see withDefaults.
type TombstoneLimits struct {
	// TTL is the retention horizon from lastActivity.
	TTL time.Duration
	// Max is the hard count cap enforced by the cap tier.
	Max int
	// Budget is the eviction budget of one incremental (Remove-driven) pass.
	Budget int
	// BootBudget is the eviction budget of the single pass run at load.
	BootBudget int
	// HitObservationWindow is the uptime a store must have before the cap tier
	// is allowed to run (see the header).
	HitObservationWindow time.Duration
	// HitPersistInterval rate-limits making an in-memory hit durable.
	HitPersistInterval time.Duration
	// Now is the clock. Injected so retention is testable without sleeping.
	Now func() time.Time
}

func (l TombstoneLimits) withDefaults() TombstoneLimits {
	if l.TTL <= 0 {
		l.TTL = DefaultTombstoneTTL
	}
	if l.Max <= 0 {
		l.Max = DefaultTombstoneMax
	}
	if l.Budget <= 0 {
		l.Budget = defaultEvictBudget
	}
	if l.BootBudget <= 0 {
		l.BootBudget = defaultBootEvictBudget
	}
	if l.HitObservationWindow <= 0 {
		l.HitObservationWindow = defaultHitObservationWindow
	}
	if l.HitPersistInterval <= 0 {
		l.HitPersistInterval = defaultHitPersistInterval
	}
	if l.Now == nil {
		l.Now = func() time.Time { return time.Now().UTC() }
	}
	return l
}

// TombstoneStats is the observable state of the bound (§10). Counters are
// cumulative since boot.
type TombstoneStats struct {
	Count          int           `json:"count"`
	Max            int           `json:"max"`
	TTL            time.Duration `json:"ttl"`
	EvictedExpired int           `json:"evicted_expired"`
	EvictedCap     int           `json:"evicted_cap"`
	HitProtected   int           `json:"hit_protected"`
}

// Tombstones reports the current bound state. Read-only; safe to call from a
// handler or a metrics scrape.
func (s *DevStore) Tombstones() TombstoneStats {
	if s == nil {
		return TombstoneStats{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := TombstoneStats{
		Count:          len(s.suppressed),
		Max:            s.lim.Max,
		TTL:            s.lim.TTL,
		EvictedExpired: s.evictedExpired,
		EvictedCap:     s.evictedCap,
	}
	for _, ts := range s.suppressed {
		if ts.lastHit.Load() != 0 {
			st.HitProtected++
		}
	}
	return st
}

// ---- compaction ------------------------------------------------------------

// compactLocked runs ONE bounded incremental pass. Caller holds s.mu (write).
// Per-record mode only — the whole-blob fallback is untouched by design.
//
// It never returns an error: compaction is best-effort hygiene layered on a
// write that already succeeded, so a backend failure here must not turn a
// successful DELETE into a 5xx. It IS reported through errf (§10) and the pass
// stops rather than spinning on a broken backend.
func (s *DevStore) compactLocked(budget int) {
	if s.pkv == nil || budget <= 0 {
		return
	}
	now := s.lim.Now()
	if len(s.evictQ) == 0 {
		// At most ONE queue build per pass, so a pass costs O(N log N) once,
		// never once per eviction. A queue that empties mid-pass simply ends
		// the pass; the next Remove continues where this one stopped.
		if len(s.suppressed) <= s.lim.Max && now.Before(s.evictScanAt) {
			return // nothing was evictable at the last look and we are under cap
		}
		// KNOWN COST, accepted: the cooldown is deliberately NOT honoured while
		// over the cap, because a burst of deletes can arrive faster than the
		// clock moves and must not be allowed to sail past the bound. In the one
		// pathological shape — over cap AND every tombstone hit-protected, so no
		// build can find a candidate — that means one O(N log N) in-memory scan
		// per delete (~1 ms at N=10k). Deletes are operator-driven, and that
		// shape means the fleet itself is over the cap, which is the case the
		// bound deliberately loses to (correctness beats the cap).
		s.buildEvictQueueLocked(now)
		if len(s.evictQ) == 0 {
			s.evictScanAt = now.Add(evictScanCooldown)
			return
		}
	}
	nExpired, nCap := 0, 0
	for evicted := 0; evicted < budget && len(s.evictQ) > 0; {
		id := s.evictQ[0]
		ts, ok := s.suppressed[id]
		if !ok {
			s.evictQ = s.evictQ[1:] // already gone (recreated, or evicted earlier)
			continue
		}
		expired := now.Sub(ts.lastActivity()) > s.lim.TTL
		if !expired {
			if !s.capTierAllowedLocked(now) || len(s.suppressed) <= s.lim.Max {
				// The pressure that justified this queue is gone — typically
				// because the evictions above already brought the count back
				// under the cap. STOP and keep the queue: draining it here to
				// discover that every remaining entry is ineligible would make
				// each Remove O(queue), which is how an incremental compactor
				// turns back into a stop-the-world scan.
				break
			}
			if ts.lastHit.Load() != 0 {
				// Hit since the queue was built: load-bearing, never
				// cap-evicted. Drop it from the queue and keep going.
				s.evictQ = s.evictQ[1:]
				continue
			}
		}
		s.evictQ = s.evictQ[1:]
		if err := s.pkv.Delete(s.suppressedKey(id)); err != nil {
			s.errf("devices", "could not compact a device tombstone; retention is degraded until the next pass", map[string]any{"id": id, "error": err.Error()})
			break
		}
		delete(s.suppressed, id)
		evicted++
		if expired {
			nExpired++
		} else {
			nCap++
		}
	}
	s.evictedExpired += nExpired
	s.evictedCap += nCap
	if nCap > 0 {
		// A deliberate degradation: these suppressions were inside their
		// retention horizon and were dropped only because the store is over its
		// hard cap. Never silent (§10).
		s.errf("devices", "device tombstone store is over its cap — evicted never-hit suppressions early to bound growth", map[string]any{
			"evicted": nCap, "remaining": len(s.suppressed), "max": s.lim.Max,
		})
	}
}

// capTierAllowedLocked gates the cap tier on enough uptime for every source to
// have polled at least once, so a tombstone is not cap-evicted merely because
// this process has not yet observed the hit that protects it.
func (s *DevStore) capTierAllowedLocked(now time.Time) bool {
	return !now.Before(s.bootAt.Add(s.lim.HitObservationWindow))
}

// buildEvictQueueLocked refills the candidate queue, oldest-lastActivity-first.
// Caller holds s.mu (write).
//
// Exactly one tier is queued per build, expired before cap, because they have
// different safety rules: expiry is safe for every tenant, the cap tier is a
// degradation that must be aimed at the tenant responsible for it.
//
// This is also the only place in-memory hits are made durable, rate-limited to
// hitFlushPerScan writes and HitPersistInterval per tombstone (§9). It runs
// under the write lock on a Remove/boot path, never on a read path.
func (s *DevStore) buildEvictQueueLocked(now time.Time) {
	s.evictQ = nil
	type cand struct {
		id string
		at time.Time
	}
	var expired []cand
	byTenant := map[string][]cand{}
	flushed := 0
	for id, ts := range s.suppressed {
		hit := ts.lastHit.Load()
		if flushed < hitFlushPerScan && hit != 0 && hit-ts.hitSaved >= int64(s.lim.HitPersistInterval) {
			if err := s.saveTombstoneLocked(id, ts); err != nil {
				s.errf("devices", "could not persist a device tombstone's last-hit; it may be evicted early after a restart", map[string]any{"id": id, "error": err.Error()})
			} else {
				ts.hitSaved = hit
				flushed++
			}
		}
		at := ts.lastActivity()
		if now.Sub(at) > s.lim.TTL {
			expired = append(expired, cand{id, at})
			continue
		}
		if hit == 0 {
			byTenant[ts.tenant] = append(byTenant[ts.tenant], cand{id, at})
		}
	}

	pick := expired
	if len(pick) == 0 {
		if !s.capTierAllowedLocked(now) || len(s.suppressed) <= s.lim.Max {
			return
		}
		// §3a: drain the tenant holding the most never-hit tombstones, so a
		// churning tenant cannot evict a quiet one's suppressions. Ties break
		// lexicographically for determinism.
		big, bigN, chosen := "", -1, false
		for tenant, c := range byTenant {
			if len(c) > bigN || (len(c) == bigN && tenant < big) {
				big, bigN, chosen = tenant, len(c), true
			}
		}
		if !chosen {
			return // every tombstone is hit-protected: correctness beats the cap
		}
		pick = byTenant[big]
	}
	sort.Slice(pick, func(i, j int) bool {
		if pick[i].at.Equal(pick[j].at) {
			return pick[i].id < pick[j].id
		}
		return pick[i].at.Before(pick[j].at)
	})
	if len(pick) > evictQueueLimit {
		pick = pick[:evictQueueLimit]
	}
	s.evictQ = make([]string, len(pick))
	for i, c := range pick {
		s.evictQ[i] = c.id
	}
}

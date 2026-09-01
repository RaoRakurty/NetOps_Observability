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
// DURABLE HIT FLUSH (ultra 9). Retention hinges on `last_hit` being DURABLE,
// but hits are recorded in memory on the poll path, which must never do IO.
// Originally the only path that persisted them was buildEvictQueueLocked —
// reached from load() (boot) and from Remove-driven compaction. That left a
// hole exactly in the steady state this file protects: a deployment that
// deletes a device ONCE (still live on the network, so it hits its tombstone
// on every sweep) and then never deletes anything again would keep every hit
// in memory only; a restart more than TTL after the delete read durable
// lastActivity = deleted_at, classified the tombstone expired, and boot-evicted
// it — resurrecting the deleted device, the F-69 class again. So the store now
// runs a background flusher (hitFlushLoop) that makes dirty hits durable on a
// TTL-derived cadence: TTL/4 (hitFlushInterval), which bounds a continuously
// hit tombstone's durable staleness to a quarter of the horizon — a restart
// can only mis-expire it if the process was DOWN (unhittable) for more than
// 3/4 TTL, and a graceful shutdown (Close) flushes the margin to zero. The
// cadence is driven by the hits themselves on the INJECTED clock (IsSuppressed
// kicks the flusher at most once per interval, via one atomic CAS and a
// non-blocking send — still zero IO on the poll path); a wall-clock ticker at
// the same interval is the safety net for hits that stop arriving. Each flush
// is dirty-set-only (lastHit newer than what the record already holds) and
// writes in bounded chunks (hitFlushChunk) so no single lock hold is O(dirty).
//
// BOOT IS EXPIRED-TIER ONLY. `last_hit` is durable but lazily so (flushed on
// the TTL/4 cadence above, and opportunistically from a compaction pass that
// is already scanning, rate-limited per tombstone), so immediately after boot
// the in-memory hit picture is incomplete. The cap tier is therefore gated on the store having been up for
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
	// hitFlushChunk bounds the record writes the background hit flusher does
	// under ONE write-lock hold; a dirtier set drains over successive chunks so
	// the poll path's readers are never starved (§9: bounded IO).
	hitFlushChunk = 256
	// minHitFlushInterval floors the TTL-derived flush cadence so a
	// pathologically small TTL cannot turn the flusher into a busy loop.
	minHitFlushInterval = time.Minute
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

// hitFlushInterval derives the durable-hit flush cadence from the retention
// horizon: TTL/4 bounds a continuously-hit tombstone's durable staleness to a
// quarter of the horizon, so a crash + restart can only boot-evict it if the
// process was DOWN (unhittable) for more than 3/4 TTL — and a graceful
// shutdown (Close) flushes the margin to zero. At the 24 h default this is one
// sweep per 6 h: at most 4 record writes per day per actively-hit tombstone, a
// set bounded by the fleet (see the header). Called after withDefaults.
func (l TombstoneLimits) hitFlushInterval() time.Duration {
	iv := l.TTL / 4
	if iv < minHitFlushInterval {
		iv = minHitFlushInterval
	}
	return iv
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
	// HitsFlushed counts tombstone records rewritten to make an in-memory hit
	// durable (background flusher + compaction-scan piggyback). Observability
	// for the ultra-9 invariant: if this stays 0 while HitProtected > 0, hit
	// recency is not being persisted.
	HitsFlushed int `json:"hits_flushed"`
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
		HitsFlushed:    s.hitsFlushed,
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
// This is also one of the two places in-memory hits are made durable — the
// scan piggyback, rate-limited to hitFlushPerScan writes and HitPersistInterval
// per tombstone (§9); the guaranteed cadence is the background flusher
// (hitFlushLoop, ultra 9), which this opportunistic path merely front-runs. It
// runs under the write lock on a Remove/boot path, never on a read path.
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

// ---- durable hit flush (ultra 9) -------------------------------------------
//
// See the "DURABLE HIT FLUSH" section of the file header for why this exists:
// without it, a continuously-hit suppression in a deployment with no further
// deletes never persisted its hits, and a restart >TTL after the delete
// boot-evicted it — resurrecting the deleted device.

// hitFlushLoop is the background flusher goroutine, started by the constructor
// in per-record mode and stopped by Close. Two triggers: the hit-driven kick
// from IsSuppressed (the routine cadence — it follows the INJECTED clock, so
// retention tests stay deterministic) and a wall-clock ticker at the same
// interval (the safety net for a dirty tombstone whose hits stop arriving).
// flushSync is a test barrier; see syncHitFlush.
func (s *DevStore) hitFlushLoop(tick *time.Ticker) {
	defer close(s.flushDone)
	defer tick.Stop()
	for {
		select {
		case <-s.stopFlush:
			return
		case <-tick.C:
			s.flushDirtyHits()
		case <-s.flushKick:
			s.flushDirtyHits()
		case r := <-s.flushSync:
			// Barrier: a pending kick is serviced BEFORE the acknowledgement,
			// so a caller that saw a kick sent knows its flush has landed.
			select {
			case <-s.flushKick:
				s.flushDirtyHits()
			default:
			}
			close(r)
		}
	}
}

// syncHitFlush blocks until the flusher has serviced every kick sent before
// the call. Tests only — the fake clock cannot drive the wall-clock ticker, so
// this is how a test waits for an in-flight flush without sleeping.
func (s *DevStore) syncHitFlush() {
	r := make(chan struct{})
	s.flushSync <- r
	<-r
}

// flushDirtyHits makes every un-persisted hit durable. Dirty-set only (a
// tombstone whose record already holds its current hit costs nothing), in
// bounded chunks so no single write-lock hold is O(dirty) — between chunks the
// poll path's readers get the lock back.
func (s *DevStore) flushDirtyHits() {
	for {
		n, more := s.flushDirtyHitChunk(hitFlushChunk)
		if !more || n < hitFlushChunk {
			return
		}
	}
}

// flushDirtyHitChunk flushes up to budget dirty hits under one write-lock
// hold. Returns how many it wrote and whether it is safe to continue (false on
// a backend failure — never spin on a broken backend, the next trigger
// retries).
func (s *DevStore) flushDirtyHitChunk(budget int) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pkv == nil || s.loadErr != nil {
		// The write gate (writeAllowedLocked doctrine) applies to flushes too:
		// an unread store must not be written around.
		return 0, false
	}
	flushed := 0
	for id, ts := range s.suppressed {
		if flushed >= budget {
			return flushed, true // more may remain; the caller re-chunks
		}
		hit := ts.lastHit.Load()
		if hit == 0 || hit == ts.hitSaved {
			continue // clean — the dirty set is what bounds the work
		}
		if err := s.saveTombstoneLocked(id, ts); err != nil {
			s.errf("devices", "could not persist a device tombstone's last-hit; it may be evicted early after a restart", map[string]any{"id": id, "error": err.Error()})
			return flushed, false
		}
		ts.hitSaved = hit
		s.hitsFlushed++
		flushed++
	}
	return flushed, true
}

// Close stops the background hit flusher and makes one final best-effort flush
// of any un-persisted hits, so a graceful shutdown carries hit recency across
// the restart with zero staleness. Idempotent and nil-safe; a no-op in
// whole-blob mode (no flusher runs there — the blob format has no last_hit).
// Wired into main's shutdown sequence after the pollers have drained.
func (s *DevStore) Close() {
	if s == nil || s.flushKick == nil {
		return
	}
	s.closeOnce.Do(func() {
		close(s.stopFlush)
		<-s.flushDone
		s.flushDirtyHits()
	})
}

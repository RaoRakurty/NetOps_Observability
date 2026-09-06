// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpwatch

// evidence.go — the correlation seam.
//
// ── THE CONTRACT ────────────────────────────────────────────────────────────
//
// EvidenceEvent is byte-for-byte the GENERIC evidence envelope internal/secbus
// emits and src/correlation/signals.py's `evidence_signal_from_event` consumes:
// schema_version, tenant_id, ts, kind, entity_id, entity_type, entity_tokens,
// severity, native_id, attrs. Nothing on the wire is BGP-specific except the
// values — the specific classification (incident class, vantage points,
// thresholds) rides in `attrs`, which the engine treats as opaque, exactly as
// the security lane puts its control id there. The type is DECLARED HERE rather
// than imported from secbus for the reason secbus itself states: the wire
// schema is pinned independently per producer, and this package must not depend
// on the security module (which is separately removable).
//
// ── THE GROUNDING SEAM (stated plainly, not implied) ────────────────────────
//
// The engine's intake is generic in its FIELD HANDLING but not in its kind
// vocabulary: `EVIDENCE_CLASS_BY_KIND` is a registry, and a `kind` with no row
// dead-letters (signals.py, "unknown evidence kind"). Registering a class is a
// ONE-ROW DATA EDIT in `EVIDENCE_CLASSES` plus the topic in
// `CORR_EVIDENCE_TOPICS` — by the registry's own documented design ("Adding a
// class is adding a row; nothing in the engine has to change"). That row is
// ENGINE-SIDE and is deliberately NOT made here: this package ships the
// producer, correctly shaped and inert until an operator opts in, and
// TestEvidenceEventSatisfiesEngineIntake pins every field-level rule the
// consumer enforces so the day the row lands, it grounds with no rework.
//
// Until then the events are published onto their own topic
// (DefaultEvidenceTopic), which nothing else consumes: they cannot pollute the
// security lane's findings index or its CTEM funnel counts, and they cannot be
// silently dead-lettered by a consumer that was never told about them. The
// topic IS pre-created by kafka-init (both compose files) with the same
// partition count as every other lane, so tenant-keyed records already land on
// the partition that tenant owns.
//
// THE THIRD STEP, stated because forgetting it is silent: under enforced ACLs
// the correlation principal must ALSO be granted Read+Describe on this topic
// (deployment/docker/kafka/apply-acls.sh). A kafka-python consumer that
// subscribes to a topic it may not Describe fails the WHOLE subscription, not
// just that lane — the 2026-09-02 T2b blocker, one lane later. The grant is
// deliberately NOT added today: granting a topic nothing consumes would imply
// a consumer that does not exist.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// SchemaVersion pins the wire contract. It matches the evidence-bus schema
// version the engine accepts (secbus.SchemaVersion / EVIDENCE_SCHEMA_VERSIONS).
const SchemaVersion = "1"

// DefaultEvidenceTopic is the bus topic these events publish onto, in the
// netops.* convention the bus bridge enforces.
const DefaultEvidenceTopic = "netops.bgp"

// Kind* are the engine-facing signal kinds this lane emits — one per alertable
// condition. They are a SMALL, STABLE vocabulary: the per-prefix specifics ride
// in attrs, never in the kind.
const (
	KindRPKIInvalid    = "bgp_rpki_invalid"
	KindVisibilityLoss = "bgp_visibility_loss"
	KindOriginChange   = "bgp_origin_change"
	KindTransitChange  = "bgp_transit_change"
	KindBogonSeen      = "bgp_bogon_seen"
	KindPeerDown       = "bgp_peer_down"
)

// EvidenceKinds is the full emitted vocabulary, sorted. Exported so the wiring
// layer (and the engine-side registry row, when it is written) has ONE source
// for the list instead of a hand-copied literal.
var EvidenceKinds = []string{
	KindBogonSeen, KindOriginChange, KindPeerDown,
	KindRPKIInvalid, KindTransitChange, KindVisibilityLoss,
}

// kindForClass maps an incident class onto its engine-facing kind. An
// unalertable class returns "" and the caller emits nothing — a guessed lane is
// invented provenance (§10).
func kindForClass(c IncidentClass) string {
	switch c {
	case ClassRPKIInvalid:
		return KindRPKIInvalid
	case ClassVisibilityLoss:
		return KindVisibilityLoss
	case ClassOriginChange:
		return KindOriginChange
	case ClassRouteLeak:
		return KindTransitChange
	case ClassBogon:
		return KindBogonSeen
	default:
		return ""
	}
}

// Entity types. A routing incident grounds on the PREFIX (the engine's
// EntityType.PREFIX), not on a device — there is no single device that "is" a
// hijacked prefix, and grounding it on one would be a fabricated attribution. A
// BMP peer-down grounds on the DEVICE that reported it, which really is one.
const (
	EntityTypePrefix = "prefix"
	EntityTypeDevice = "device"
)

// EvidenceEvent is the generic evidence envelope on the bus.
type EvidenceEvent struct {
	SchemaVersion string         `json:"schema_version"`
	TenantID      string         `json:"tenant_id"`
	TS            string         `json:"ts"`
	Kind          string         `json:"kind"`
	EntityID      string         `json:"entity_id"`
	EntityType    string         `json:"entity_type"`
	EntityTokens  []string       `json:"entity_tokens,omitempty"`
	Severity      string         `json:"severity"`
	NativeID      string         `json:"native_id"`
	Attrs         map[string]any `json:"attrs,omitempty"`
}

// Record is one bus record from a producer's point of view — a partition Key
// and a JSON-serializable Value. It mirrors what the Vector bus-bridge producer
// accepts WITHOUT importing it, so this package stays a leaf.
type Record struct {
	Key   string `json:"key,omitempty"`
	Value any    `json:"value"`
}

// Publisher is the injected bus transport (§5). Its single production
// implementation is a thin adapter over the existing bus bridge; tests inject a
// fake. Publish MUST honor ctx cancellation.
type Publisher interface {
	Publish(ctx context.Context, topic string, recs []Record) (int, error)
}

// PublisherFunc adapts a bare function to Publisher.
type PublisherFunc func(ctx context.Context, topic string, recs []Record) (int, error)

// Publish implements Publisher.
func (f PublisherFunc) Publish(ctx context.Context, topic string, recs []Record) (int, error) {
	return f(ctx, topic, recs)
}

// EventFromIncident builds the evidence event for one prefix incident.
//
// PURE and deterministic: the same incident always yields the same event, so a
// redelivery is idempotent downstream (the engine hashes native_id + ts into a
// stable signal id). It returns an error — never a partial or guessed event —
// when the incident cannot ground.
//
// §3a: tenant is the CALLER's already-resolved tenant; there is no path by
// which a request body could set it.
func EventFromIncident(tenant string, inc Incident, cfg PolicyConfig) (EvidenceEvent, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return EvidenceEvent{}, err
	}
	kind := kindForClass(inc.Class)
	if kind == "" {
		return EvidenceEvent{}, errors.New("bgpwatch: incident class " + string(inc.Class) + " is not an alertable evidence kind")
	}
	entity := strings.TrimSpace(inc.Prefix)
	if entity == "" {
		return EvidenceEvent{}, errors.New("bgpwatch: incident carries no prefix to ground on")
	}
	ts := inc.Since
	if ts.IsZero() {
		ts = inc.LastSeen
	}
	if ts.IsZero() {
		return EvidenceEvent{}, errors.New("bgpwatch: incident has no event time (event-time discipline)")
	}

	attrs := map[string]any{
		"evidence_class":  "bgp",
		"rule_id":         string(inc.Class),
		"incident_class":  string(inc.Class),
		"provider_source": "bgp-watch",
		"summary":         clip(inc.Summary, 400),
		"detail":          clip(inc.Evidence.Detail, 600),
	}
	if len(inc.Evidence.Vantages) > 0 {
		attrs["vantages"] = clipStrings(inc.Evidence.Vantages, MaxEvidenceVantages)
		attrs["vantage_count"] = len(inc.Evidence.Vantages)
	}
	if len(inc.Evidence.Origins) > 0 {
		keys := make([]string, 0, len(inc.Evidence.Origins))
		for k := range inc.Evidence.Origins {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		attrs["observed_origins"] = keys
	}
	if inc.Evidence.PeersTotal > 0 {
		attrs["peers_seeing"] = inc.Evidence.PeersSeeing
		attrs["peers_total"] = inc.Evidence.PeersTotal
	}
	if inc.Evidence.Bogon != nil {
		attrs["bogon_block"] = inc.Evidence.Bogon.Block
		attrs["bogon_reason"] = inc.Evidence.Bogon.Reason
	}
	if inc.LearnedOrigin {
		// Honesty on the wire: a learned baseline is weaker than a declared one
		// and the consumer must be able to tell them apart.
		attrs["origin_baseline"] = "learned"
	} else if len(cfg.ExpectedOrigins) > 0 {
		attrs["origin_baseline"] = "declared"
	}

	return EvidenceEvent{
		SchemaVersion: SchemaVersion,
		TenantID:      t,
		TS:            ts.UTC().Format(time.RFC3339Nano),
		Kind:          kind,
		EntityID:      entity,
		EntityType:    EntityTypePrefix,
		EntityTokens:  prefixTokens(entity),
		Severity:      inc.Severity,
		NativeID:      nativeID(t, kind, entity, inc),
		Attrs:         attrs,
	}, nil
}

// EventFromPeerDown builds the evidence event for a BMP peer that went down.
// It grounds on the DEVICE, so it co-locates with that device's syslog, metric
// and verification signals — which is the whole point of emitting it.
func EventFromPeerDown(tenant string, p PeerObservation, now time.Time) (EvidenceEvent, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return EvidenceEvent{}, err
	}
	device := strings.TrimSpace(p.DeviceID)
	if device == "" {
		return EvidenceEvent{}, errors.New("bgpwatch: peer observation carries no device to ground on")
	}
	ts := p.ChangedAt
	if ts.IsZero() {
		ts = now
	}
	if ts.IsZero() {
		return EvidenceEvent{}, errors.New("bgpwatch: peer observation has no event time")
	}
	peer := clip(strings.TrimSpace(p.Peer), 64)
	attrs := map[string]any{
		"evidence_class":  "bgp",
		"rule_id":         "bgp_peer_down",
		"provider_source": "bgp-watch",
		"peer":            peer,
		"summary":         clip("BMP peer "+peer+" on "+device+" is down", 400),
	}
	if p.PeerAS != 0 {
		attrs["peer_as"] = int(p.PeerAS)
	}
	if p.Reason != "" {
		attrs["down_reason"] = clip(p.Reason, 200)
	}
	if p.SessionID != "" {
		attrs["session_id"] = clip(p.SessionID, 64)
	}
	return EvidenceEvent{
		SchemaVersion: SchemaVersion,
		TenantID:      t,
		TS:            ts.UTC().Format(time.RFC3339Nano),
		Kind:          KindPeerDown,
		EntityID:      device,
		EntityType:    EntityTypeDevice,
		EntityTokens:  deviceTokens(device, peer),
		Severity:      SevHigh,
		NativeID:      "bgp|" + KindPeerDown + "|" + t + "|" + device + "|" + peer,
		Attrs:         attrs,
	}, nil
}

// prefixTokens builds the engine's CO-LOCATION grounding keys for a prefix.
// Both are ENTITY-scoped — neither is in the engine's forbidden tenant/org/
// global/all set — so an incident can never merge unrelated entities.
func prefixTokens(prefix string) []string {
	return []string{prefix, "prefix:" + prefix}
}

// deviceTokens builds the co-location keys for a device-grounded event.
func deviceTokens(device, peer string) []string {
	out := []string{device, "device:" + device}
	if peer != "" {
		out = append(out, "peer:"+peer)
	}
	return out
}

// nativeID is the deterministic verdict identity the engine hashes into a
// stable signal id. It is the identity of THIS incident episode: same tenant,
// kind, prefix and episode start ⇒ same id ⇒ a redelivery dedups; a NEW episode
// (the class cleared and came back) gets a new id, which is what makes two
// outages two stories instead of one. Hashed when the joined form would exceed
// the engine's 256-char id cap, so a long value can never silently truncate
// into a colliding id.
func nativeID(tenant, kind, entity string, inc Incident) string {
	raw := strings.Join([]string{"bgp", kind, tenant, entity, inc.Since.UTC().Format(time.RFC3339)}, "|")
	if len(raw) <= 256 {
		return raw
	}
	sum := sha256.Sum256([]byte(raw))
	return "bgp|" + kind + "|" + hex.EncodeToString(sum[:])
}

// ── the producer ────────────────────────────────────────────────────────────

// EvidenceMetrics counts what the producer did (§10).
type EvidenceMetrics struct {
	published atomic.Int64
	retries   atomic.Int64
	skipped   atomic.Int64
	dropped   atomic.Int64
}

// EvidenceSnapshot is an immutable read of the counters.
type EvidenceSnapshot struct {
	Published int64 `json:"published"`
	Retries   int64 `json:"retries"`
	Skipped   int64 `json:"skipped"`
	Dropped   int64 `json:"dropped"`
}

// Snapshot reads the counters.
func (m *EvidenceMetrics) Snapshot() EvidenceSnapshot {
	if m == nil {
		return EvidenceSnapshot{}
	}
	return EvidenceSnapshot{
		Published: m.published.Load(), Retries: m.retries.Load(),
		Skipped: m.skipped.Load(), Dropped: m.dropped.Load(),
	}
}

// evidenceProducer publishes evidence events with bounded retry (exponential
// backoff + FULL jitter) and FAIL-SAFE behaviour: a batch that exhausts its
// retries is dropped-to-error with a metric and a log line rather than blocking
// the evaluator forever (§9 reliability, §10 observability).
type evidenceProducer struct {
	pub     Publisher
	topic   string
	maxTry  int
	base    time.Duration
	maxWait time.Duration
	metrics *EvidenceMetrics
	sleep   func(context.Context, time.Duration) error
	jitter  func() float64
	logErr  func(string, map[string]any)
}

// publish produces the records, retrying transient failures.
func (p *evidenceProducer) publish(ctx context.Context, recs []Record) (int, error) {
	if p == nil || p.pub == nil || len(recs) == 0 {
		return 0, nil
	}
	var lastErr error
	backoff := p.base
	for attempt := 0; attempt < p.maxTry; attempt++ {
		if attempt > 0 {
			p.metrics.retries.Add(1)
			wait := time.Duration(p.jitter() * float64(min64(backoff, p.maxWait)))
			if err := p.sleep(ctx, wait); err != nil {
				return 0, err
			}
			backoff *= 2
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		n, err := p.pub.Publish(ctx, p.topic, recs)
		if err == nil {
			p.metrics.published.Add(int64(n))
			return n, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return 0, err // a cancelled context is terminal, not transient
		}
	}
	p.metrics.dropped.Add(int64(len(recs)))
	if p.logErr != nil {
		p.logErr("BGP evidence records dropped after exhausting retries — these incidents did NOT reach the bus",
			map[string]any{"records": len(recs), "attempts": p.maxTry, "topic": p.topic, "err": errText(lastErr)})
	}
	return 0, lastErr
}

func min64(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

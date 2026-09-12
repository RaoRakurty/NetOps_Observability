// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpwatch

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func sampleIncident() Incident {
	obs := healthy()
	obs.RPKIState = "invalid"
	return Classify(obs, policy(), NewBogonSet(), clsNow)
}

// TestEvidenceEventSatisfiesEngineIntake is the CONTRACT test against
// src/correlation/signals.py's evidence_signal_from_event. Every assertion here
// mirrors one refusal in that function, so a shape change on either side fails
// here instead of dead-lettering silently in production.
func TestEvidenceEventSatisfiesEngineIntake(t *testing.T) {
	ev, err := EventFromIncident("acme", sampleIncident(), policy())
	if err != nil {
		t.Fatalf("EventFromIncident: %v", err)
	}
	// The envelope must serialize to the wire names the consumer reads.
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"schema_version", "tenant_id", "ts", "kind", "entity_id", "entity_type", "entity_tokens", "severity", "native_id", "attrs"} {
		if _, ok := wire[k]; !ok {
			t.Fatalf("wire envelope is missing %q — the consumer reads it by name", k)
		}
	}
	// schema_version ∈ EVIDENCE_SCHEMA_VERSIONS ({"", "1"}).
	if ev.SchemaVersion != "1" {
		t.Fatalf("schema_version=%q, want \"1\"", ev.SchemaVersion)
	}
	// entity_id is MANDATORY (the consumer dead-letters an empty one).
	if strings.TrimSpace(ev.EntityID) == "" {
		t.Fatal("entity_id must never be empty")
	}
	// native_id is MANDATORY (it is the identity the consumer hashes).
	if strings.TrimSpace(ev.NativeID) == "" {
		t.Fatal("native_id must never be empty")
	}
	if len(ev.NativeID) > 256 {
		t.Fatalf("native_id is %d chars; the engine's id cap is 256", len(ev.NativeID))
	}
	// ts must be RFC3339(Nano) and parse back to the same instant.
	back, perr := time.Parse(time.RFC3339Nano, ev.TS)
	if perr != nil {
		t.Fatalf("ts %q is not RFC3339Nano: %v", ev.TS, perr)
	}
	if !back.Equal(sampleIncident().Since.UTC()) {
		t.Fatalf("ts %s is not the incident's event time", ev.TS)
	}
	// entity_type must be a member of the engine's EntityType enum.
	if ev.EntityType != EntityTypePrefix {
		t.Fatalf("entity_type=%q, want %q (EntityType.PREFIX)", ev.EntityType, EntityTypePrefix)
	}
	// severity must be a token in EVIDENCE_SEVERITY_ALIASES.
	known := map[string]bool{"info": true, "informational": true, "notice": true, "debug": true, "ok": true,
		"low": true, "none": true, "pass": true, "warn": true, "warning": true, "minor": true, "medium": true,
		"moderate": true, "high": true, "error": true, "err": true, "major": true, "important": true,
		"crit": true, "critical": true, "fatal": true, "emergency": true}
	if !known[ev.Severity] {
		t.Fatalf("severity %q is not in the engine's alias table — it would silently become WARN", ev.Severity)
	}
	// entity_tokens must all be ENTITY-scoped (never tenant/org/global/all),
	// or the engine's grounding-token guard would merge unrelated entities.
	for _, tok := range ev.EntityTokens {
		for _, forbidden := range []string{"tenant:", "org:", "global", "all", "ssid:", "wlan:"} {
			if strings.HasPrefix(strings.ToLower(tok), forbidden) {
				t.Fatalf("entity token %q is not entity-scoped", tok)
			}
		}
	}
	// attrs must carry the provenance fields the registry reads by name.
	if ev.Attrs["rule_id"] == nil || ev.Attrs["provider_source"] == nil {
		t.Fatalf("attrs must carry rule_id + provider_source: %+v", ev.Attrs)
	}
	// No raw payload / secret rides on the bus (§3a, LLM06 discipline): the
	// attrs blob carries CLASSIFICATION and pointers, never captured content.
	attrsRaw, aerr := json.Marshal(ev.Attrs)
	if aerr != nil {
		t.Fatalf("marshal attrs: %v", aerr)
	}
	for _, bad := range []string{"password", "secret", "api_key", "credential", "BEGIN "} {
		if strings.Contains(strings.ToLower(string(attrsRaw)), strings.ToLower(bad)) {
			t.Fatalf("the evidence attrs must never carry credential-shaped content (%q)", bad)
		}
	}
}

// Every emitted kind must be in the declared vocabulary — a kind that is not in
// EvidenceKinds is a kind no engine-side registry row would ever cover.
func TestEveryEmittedKindIsDeclared(t *testing.T) {
	declared := map[string]bool{}
	for _, k := range EvidenceKinds {
		declared[k] = true
	}
	for _, c := range []IncidentClass{ClassRPKIInvalid, ClassVisibilityLoss, ClassOriginChange, ClassRouteLeak, ClassBogon} {
		k := kindForClass(c)
		if k == "" {
			t.Fatalf("class %s has no evidence kind", c)
		}
		if !declared[k] {
			t.Fatalf("kind %q is emitted but not declared in EvidenceKinds", k)
		}
	}
	if !declared[KindPeerDown] {
		t.Fatal("bgp_peer_down is emitted but not declared")
	}
	if kindForClass(ClassNone) != "" || kindForClass(ClassUnknown) != "" {
		t.Fatal("none/unknown must not map to a kind — they are not events")
	}
}

func TestEventIdentityIsStablePerEpisode(t *testing.T) {
	inc := sampleIncident()
	a, _ := EventFromIncident("acme", inc, policy())
	b, _ := EventFromIncident("acme", inc, policy())
	if a.NativeID != b.NativeID {
		t.Fatal("the same incident must yield the same native_id (redelivery must dedup)")
	}
	// A NEW episode (the class cleared and came back) is a NEW story.
	next := inc
	next.Since = inc.Since.Add(time.Hour)
	c, _ := EventFromIncident("acme", next, policy())
	if c.NativeID == a.NativeID {
		t.Fatal("a new episode must get a new native_id, or two outages collapse into one story")
	}
	// Two tenants watching the SAME prefix must never share an identity.
	d, _ := EventFromIncident("globex", inc, policy())
	if d.NativeID == a.NativeID {
		t.Fatal("native_id must be tenant-discriminated")
	}
	if d.TenantID != "globex" {
		t.Fatalf("tenant_id=%q — it comes from the caller, never the incident", d.TenantID)
	}
}

func TestEventRefusesUngroundableInput(t *testing.T) {
	inc := sampleIncident()
	if _, err := EventFromIncident("", inc, policy()); err == nil {
		t.Fatal("an empty tenant must be refused")
	}
	if _, err := EventFromIncident("*", inc, policy()); err == nil {
		t.Fatal("the cross-tenant wildcard must be refused")
	}
	noPrefix := inc
	noPrefix.Prefix = ""
	if _, err := EventFromIncident("acme", noPrefix, policy()); err == nil {
		t.Fatal("an incident with no prefix has nothing to ground on")
	}
	clean := inc
	clean.Class = ClassNone
	if _, err := EventFromIncident("acme", clean, policy()); err == nil {
		t.Fatal("a clean verdict must not become an evidence event")
	}
	noTime := inc
	noTime.Since, noTime.LastSeen = time.Time{}, time.Time{}
	if _, err := EventFromIncident("acme", noTime, policy()); err == nil {
		t.Fatal("an event with no event time must be refused, never stamped with arrival time")
	}
}

func TestEventFromPeerDownGroundsOnTheDevice(t *testing.T) {
	ev, err := EventFromPeerDown("acme", PeerObservation{
		DeviceID: "edge-r1", Peer: "10.0.0.5", PeerAS: 64500, State: "down",
		Reason: "hold timer expired", ChangedAt: clsNow,
	}, clsNow)
	if err != nil {
		t.Fatalf("EventFromPeerDown: %v", err)
	}
	if ev.EntityType != EntityTypeDevice || ev.EntityID != "edge-r1" {
		t.Fatalf("a peer-down grounds on the device, got %s/%s", ev.EntityType, ev.EntityID)
	}
	if ev.Kind != KindPeerDown {
		t.Fatalf("kind=%s", ev.Kind)
	}
	if _, err := EventFromPeerDown("acme", PeerObservation{Peer: "10.0.0.5"}, clsNow); err == nil {
		t.Fatal("a peer observation with no device must be refused")
	}
}

// The producer's bounded retry + fail-safe drop.
type flakyPub struct {
	fails int
	calls int
	last  []Record
}

func (p *flakyPub) Publish(_ context.Context, _ string, recs []Record) (int, error) {
	p.calls++
	if p.calls <= p.fails {
		return 0, errors.New("bus down")
	}
	p.last = recs
	return len(recs), nil
}

func TestEvidenceProducerRetriesThenDropsObservably(t *testing.T) {
	m := &EvidenceMetrics{}
	pub := &flakyPub{fails: 2}
	p := &evidenceProducer{pub: pub, topic: DefaultEvidenceTopic, maxTry: 4,
		base: time.Millisecond, maxWait: time.Millisecond, metrics: m,
		sleep: noSleep, jitter: fixedJitter}
	n, err := p.publish(context.Background(), []Record{{Key: "acme", Value: 1}})
	if err != nil || n != 1 {
		t.Fatalf("publish after transient failures: n=%d err=%v", n, err)
	}
	if m.Snapshot().Retries != 2 {
		t.Fatalf("retries=%d, want 2", m.Snapshot().Retries)
	}

	var dropped string
	always := &flakyPub{fails: 99}
	p2 := &evidenceProducer{pub: always, topic: DefaultEvidenceTopic, maxTry: 3,
		base: time.Millisecond, maxWait: time.Millisecond, metrics: &EvidenceMetrics{},
		sleep: noSleep, jitter: fixedJitter,
		logErr: func(msg string, _ map[string]any) { dropped = msg }}
	if _, err := p2.publish(context.Background(), []Record{{Key: "acme", Value: 1}}); err == nil {
		t.Fatal("a persistent bus failure must surface as an error")
	}
	if dropped == "" {
		t.Fatal("a dropped batch must be LOGGED, not silently lost (§10)")
	}
	if p2.metrics.Snapshot().Dropped != 1 {
		t.Fatal("a dropped batch must be counted")
	}
}

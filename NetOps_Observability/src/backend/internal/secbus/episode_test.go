// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package secbus

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestStampEpisodeAnnotatesWithoutChangingTheVerdict(t *testing.T) {
	ev, err := FromFinding(postureFinding())
	if err != nil {
		t.Fatal(err)
	}
	ts, nid, sid := ev.TS, ev.NativeID, ev.Attrs["status_id"]
	first := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	StampEpisode(&ev, TransitionChange, first, BasisObserved)
	if ev.TS != ts || ev.NativeID != nid || ev.Attrs["status_id"] != sid {
		t.Fatal("the stamp moved the verdict's ts, identity or status")
	}
	if ev.Attrs[AttrTransition] != TransitionChange ||
		ev.Attrs[AttrFirstSeen] != "2026-08-01T09:00:00Z" || ev.Attrs[AttrFirstSeenBasis] != BasisObserved {
		t.Fatalf("stamp attrs: %+v", ev.Attrs)
	}
	var bare EvidenceEvent
	StampEpisode(&bare, TransitionUnclassified, time.Time{}, "")
	if _, has := bare.Attrs[AttrFirstSeen]; has {
		t.Fatal("a zero first_seen must be omitted, never written as year 1")
	}
}

func TestClearEventPairsWithItsOnset(t *testing.T) {
	onset, err := FromFinding(postureFinding())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	first := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	clr := ClearEvent(ClearSubject{
		TenantID: onset.TenantID, Kind: onset.Kind, NativeID: onset.NativeID,
		EntityID: onset.EntityID, EntityType: onset.EntityType, EntityTokens: onset.EntityTokens,
		EvidenceClass: "posture", ControlID: "xccdf_org.cis_rule_ssh_root", RawRuleID: "sshd_root_login",
		ProviderSource: "openscap",
	}, at, "scan-456", first, BasisObserved)
	if clr.Kind != "security_posture_clear" || !IsClearKind(clr.Kind) || IsClearKind(onset.Kind) {
		t.Fatalf("clear kind = %q", clr.Kind)
	}
	if clr.NativeID != onset.NativeID || clr.EntityID != onset.EntityID || clr.TenantID != onset.TenantID {
		t.Fatal("a clear must carry its onset's identity, entity and tenant")
	}
	if clr.TS != "2026-08-28T00:00:00Z" || clr.Severity != "info" || clr.SchemaVersion != SchemaVersion {
		t.Fatalf("clear ts/severity/schema = %s/%s/%s", clr.TS, clr.Severity, clr.SchemaVersion)
	}
	if clr.Attrs[AttrTransition] != TransitionClear || clr.Attrs[AttrFirstSeen] != "2026-08-27T12:00:00Z" ||
		clr.Attrs["scan_id"] != "scan-456" || clr.Attrs["evidence_class"] != "posture" {
		t.Fatalf("clear attrs: %+v", clr.Attrs)
	}
	if _, has := clr.Attrs["status"]; has {
		t.Fatal("a clear must not state a verdict")
	}
	if clr.FindingID != "" {
		t.Fatal("a clear is not a stored verdict and carries no document id")
	}
}

func TestWithTopicAcceptsOnlyTheSecurityTopics(t *testing.T) {
	bus := &fakeBus{}
	for topic, want := range map[string]string{
		TopicSecurityAudit:    TopicSecurityAudit,
		TopicSecurityEvidence: TopicSecurityEvidence,
		"netops.syslog":       TopicSecurityEvidence,
		"":                    TopicSecurityEvidence,
	} {
		p, err := NewProducer(bus, WithTopic(topic))
		if err != nil {
			t.Fatal(err)
		}
		if p.Topic() != want {
			t.Errorf("WithTopic(%q) → %q, want %q", topic, p.Topic(), want)
		}
	}
}

func TestPublishEventsKeysByTenantAndRefusesUnkeyedEvents(t *testing.T) {
	bus := &fakeBus{}
	p, err := NewProducer(bus, WithTopic(TopicSecurityAudit), WithRetry(1, time.Millisecond, time.Millisecond),
		withClock(noSleep, fixedJitter))
	if err != nil {
		t.Fatal(err)
	}
	good, err := FromFinding(postureFinding())
	if err != nil {
		t.Fatal(err)
	}
	noTenant := good
	noTenant.TenantID = ""
	noID := good
	noID.NativeID = ""
	n, err := p.PublishEvents(context.Background(), []EvidenceEvent{good, noTenant, noID})
	if err != nil || n != 1 {
		t.Fatalf("PublishEvents = %d, %v; want exactly the keyed event", n, err)
	}
	if bus.lastTopic != TopicSecurityAudit || len(bus.lastRecs) != 1 || bus.lastRecs[0].Key != "tenant-A" {
		t.Fatalf("topic %q recs %+v", bus.lastTopic, bus.lastRecs)
	}
	if got := p.Metrics().Snapshot(); got.Skipped != 2 || got.Published != 1 {
		t.Fatalf("metrics = %+v", got)
	}
	// The wire form carries the stamp in attrs, where the engine's generic
	// evidence pass-through copies it onto Signal.attrs.
	StampEpisode(&good, TransitionAppear, time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC), BasisObserved)
	raw, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	attrs, _ := wire["attrs"].(map[string]any)
	if attrs["first_seen"] != "2026-08-27T12:00:00Z" || attrs["transition"] != "appear" {
		t.Fatalf("wire attrs: %+v", attrs)
	}

	bus.failAll = true
	if _, err := p.PublishEvents(context.Background(), []EvidenceEvent{good}); err == nil {
		t.Fatal("a persistent bus failure must return an error")
	}
	if p.Metrics().Snapshot().Dropped != 1 {
		t.Fatal("the dropped batch was not counted")
	}
}

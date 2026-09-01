package secbus

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/secfindings"
)

// fakeBus is an in-memory Publisher: records calls, and can be told to fail a
// given number of times before succeeding (transient) or forever (persistent).
type fakeBus struct {
	mu        sync.Mutex
	calls     int
	failFirst int  // fail this many attempts, then succeed
	failAll   bool // always fail
	lastTopic string
	lastRecs  []Record
}

func (b *fakeBus) Publish(ctx context.Context, topic string, recs []Record) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	if b.failAll || b.calls <= b.failFirst {
		return 0, errors.New("transient bridge error")
	}
	b.lastTopic = topic
	b.lastRecs = recs
	return len(recs), nil
}

func noSleep(context.Context, time.Duration) error { return nil }
func fixedJitter() float64                         { return 0.5 }

func newTestProducer(t *testing.T, pub Publisher, attempts int) *Producer {
	t.Helper()
	p, err := NewProducer(pub,
		WithRetry(attempts, time.Millisecond, 10*time.Millisecond),
		withClock(noSleep, fixedJitter),
	)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPublish_RightTopicAndKey(t *testing.T) {
	bus := &fakeBus{}
	p := newTestProducer(t, bus, 3)
	n, err := p.Publish(context.Background(), []secfindings.Finding{postureFinding()})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if n != 1 {
		t.Fatalf("produced = %d, want 1", n)
	}
	if bus.lastTopic != TopicSecurityEvidence {
		t.Errorf("topic = %q, want %q", bus.lastTopic, TopicSecurityEvidence)
	}
	if len(bus.lastRecs) != 1 {
		t.Fatalf("records = %d, want 1", len(bus.lastRecs))
	}
	// Partition key is the tenant (co-partitioning), stable given the finding.
	if bus.lastRecs[0].Key != "tenant-A" {
		t.Errorf("record key = %q, want tenant-A", bus.lastRecs[0].Key)
	}
	ev, ok := bus.lastRecs[0].Value.(EvidenceEvent)
	if !ok {
		t.Fatalf("record value type = %T, want EvidenceEvent", bus.lastRecs[0].Value)
	}
	if ev.EntityID != "dev-77" {
		t.Errorf("event entity_id = %q", ev.EntityID)
	}
	if p.Metrics().Snapshot().Published != 1 {
		t.Errorf("published metric = %d", p.Metrics().Snapshot().Published)
	}
}

// Idempotent event key: re-publishing the same finding yields the same tenant
// key AND the same deterministic native_id (downstream dedups on signal_id).
func TestPublish_StableIdempotentKey(t *testing.T) {
	bus := &fakeBus{}
	p := newTestProducer(t, bus, 1)
	f := postureFinding()
	_, _ = p.Publish(context.Background(), []secfindings.Finding{f})
	first := bus.lastRecs[0]
	_, _ = p.Publish(context.Background(), []secfindings.Finding{f})
	second := bus.lastRecs[0]
	if first.Key != second.Key {
		t.Errorf("partition key not stable: %q vs %q", first.Key, second.Key)
	}
	if first.Value.(EvidenceEvent).NativeID != second.Value.(EvidenceEvent).NativeID {
		t.Errorf("native_id not stable across re-emission")
	}
}

func TestPublish_RetriesTransient(t *testing.T) {
	bus := &fakeBus{failFirst: 2} // fail twice, succeed on the 3rd attempt
	p := newTestProducer(t, bus, 4)
	n, err := p.Publish(context.Background(), []secfindings.Finding{postureFinding()})
	if err != nil {
		t.Fatalf("Publish should have recovered: %v", err)
	}
	if n != 1 {
		t.Errorf("produced = %d, want 1", n)
	}
	if bus.calls != 3 {
		t.Errorf("bus calls = %d, want 3 (2 failures + success)", bus.calls)
	}
	if p.Metrics().Snapshot().Retries != 2 {
		t.Errorf("retries metric = %d, want 2", p.Metrics().Snapshot().Retries)
	}
}

func TestPublish_FailsSafeOnPersistentError(t *testing.T) {
	bus := &fakeBus{failAll: true}
	p := newTestProducer(t, bus, 3)
	n, err := p.Publish(context.Background(), []secfindings.Finding{postureFinding()})
	if err == nil {
		t.Fatal("expected a persistent-failure error")
	}
	if n != 0 {
		t.Errorf("produced = %d on failure, want 0", n)
	}
	if bus.calls != 3 { // bounded: exactly maxTry attempts, never unbounded
		t.Errorf("bus calls = %d, want bounded 3", bus.calls)
	}
	if p.Metrics().Snapshot().Dropped != 1 {
		t.Errorf("dropped metric = %d, want 1 (fail-safe)", p.Metrics().Snapshot().Dropped)
	}
}

func TestPublish_ContextCancelledIsTerminal(t *testing.T) {
	bus := &fakeBus{failAll: true}
	p := newTestProducer(t, bus, 5)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := p.Publish(ctx, []secfindings.Finding{postureFinding()})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if bus.calls > 1 {
		t.Errorf("bus calls = %d, want no retry loop after cancel", bus.calls)
	}
}

func TestPublish_SkipsUngroundable(t *testing.T) {
	bus := &fakeBus{}
	p := newTestProducer(t, bus, 2)
	bad := secfindings.Finding{Time: time.Now()} // no class, no subject
	good := postureFinding()
	n, err := p.Publish(context.Background(), []secfindings.Finding{bad, good})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("produced = %d, want 1 (bad skipped)", n)
	}
	if p.Metrics().Snapshot().Skipped != 1 {
		t.Errorf("skipped metric = %d, want 1", p.Metrics().Snapshot().Skipped)
	}
}

func TestPublish_EmptyAndNilPublisher(t *testing.T) {
	if _, err := NewProducer(nil); err == nil {
		t.Error("expected error for nil Publisher")
	}
	bus := &fakeBus{}
	p := newTestProducer(t, bus, 2)
	n, err := p.Publish(context.Background(), nil)
	if err != nil || n != 0 {
		t.Errorf("empty publish = (%d,%v), want (0,nil)", n, err)
	}
	if bus.calls != 0 {
		t.Errorf("bus called %d times for empty batch", bus.calls)
	}
}

// PublisherFunc adapts a bare produceJSON-shaped function without importing it.
func TestPublisherFuncAdapter(t *testing.T) {
	var gotTopic string
	pub := PublisherFunc(func(_ context.Context, topic string, recs []Record) (int, error) {
		gotTopic = topic
		return len(recs), nil
	})
	p := newTestProducer(t, pub, 1)
	if _, err := p.Publish(context.Background(), []secfindings.Finding{postureFinding()}); err != nil {
		t.Fatal(err)
	}
	if gotTopic != TopicSecurityEvidence {
		t.Errorf("func adapter topic = %q", gotTopic)
	}
}

// Golden: pin the exact wire JSON so T2b can rely on the shape, plus round-trip.
func TestGoldenWireShape(t *testing.T) {
	ev, err := FromFinding(exposureFinding())
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	// Exact wire shape T2b (the Python consume-and-ground adapter) relies on.
	// Struct fields serialize in declaration order; Go sorts map keys, so attrs
	// order is deterministic. A change here is a wire-contract change — bump
	// SchemaVersion deliberately, never re-baseline this silently.
	const want = `{
  "schema_version": "1",
  "tenant_id": "tenant-B",
  "ts": "2026-08-27T13:30:00Z",
  "kind": "security_exposure",
  "entity_id": "wan-gw",
  "entity_type": "device",
  "entity_tokens": [
    "wan-gw",
    "host:wan-gw",
    "seam:seam-isp-1"
  ],
  "severity": "critical",
  "native_id": "security|security_exposure|exposure|expose-telnet|wan-gw|scan-999|",
  "seam_id": "seam-isp-1",
  "seam_type": "ISP",
  "internet_facing": true,
  "attrs": {
    "control_id": "expose-telnet",
    "evidence_class": "exposure",
    "internet_facing": true,
    "provider_source": "correlix-netrule",
    "scan_id": "scan-999",
    "seam_id": "seam-isp-1",
    "seam_type": "ISP",
    "status": "Fail",
    "status_id": 3
  }
}`
	if string(blob) != want {
		t.Errorf("golden wire shape drift:\n--- got ---\n%s\n--- want ---\n%s", blob, want)
	}

	// Round-trip: unmarshal back and assert the load-bearing fields survive.
	var back EvidenceEvent
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if back.SchemaVersion != "1" || back.Kind != KindExposure || back.EntityID != "wan-gw" {
		t.Errorf("round-trip lost fields: %+v", back)
	}
	if back.NativeID != "security|security_exposure|exposure|expose-telnet|wan-gw|scan-999|" {
		t.Errorf("native_id = %q", back.NativeID)
	}
	if back.TS != "2026-08-27T13:30:00Z" {
		t.Errorf("ts = %q, want RFC3339 UTC", back.TS)
	}
}

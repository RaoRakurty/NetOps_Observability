package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"netops/backend/collectors"
)

// bus_producer_failure_test.go — FAULT INJECTION at the bus seam.
//
// Why this file exists. A coverage sweep across the backend found fault
// injection at the kv/settings seam, the HTTP-upstream seam, the ClickHouse
// seam, the notification seam and the Postgres seam — and ZERO at the bus. The
// bus is the spine: every telemetry lane and every producer crosses it. It was
// also the subject of F-04, where Vector returned HTTP 200 the moment it parsed
// the body — long before the event reached Kafka — so the backend recorded
// success for events still sitting in an in-memory buffer.
//
// These tests pin what produceJSON must do when the bridge misbehaves, because
// "the bus is down" is a normal Tuesday, not an exotic case:
//
//   - a non-2xx is an ERROR, never a silent success with a plausible count
//   - a transport failure is an ERROR
//   - the returned count is what the bridge ACCEPTED, never what we hoped
//   - a hung bridge is bounded by the timeout instead of pinning a worker
//   - the F-08 auth header is present on every produce, or anything on the
//     compose network can inject onto any tenant's topic
//   - the wire shape stays one envelope per record (the consumer's contract)

// busBridgeStub is a fake bus bridge with a programmable verdict.
type busBridgeStub struct {
	srv      *httptest.Server
	status   int
	body     string
	delay    time.Duration
	requests atomic.Int32
	lastAuth atomic.Value // string
	lastBody atomic.Value // []byte
}

func newBusBridgeStub(t *testing.T, status int, body string) *busBridgeStub {
	t.Helper()
	s := &busBridgeStub{status: status, body: body}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		s.lastAuth.Store(r.Header.Get("Authorization"))
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		s.lastBody.Store(b)
		if s.delay > 0 {
			time.Sleep(s.delay)
		}
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.body))
	}))
	t.Cleanup(s.srv.Close)
	t.Setenv("BUS_BRIDGE_URL", s.srv.URL)
	return s
}

func oneRecord() []proxyRecord {
	return []proxyRecord{{Key: "k1", Value: map[string]any{"device": "sw01", "n": 1}}}
}

// TestProduceReportsNon2xxAsFailure: the whole F-04 class. A bridge that
// rejects the batch must not read as success to the caller.
func TestProduceReportsNon2xxAsFailure(t *testing.T) {
	for _, status := range []int{400, 401, 403, 429, 500, 502, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			newBusBridgeStub(t, status, "rejected")
			n, err := produceJSON(context.Background(), "netops.test", oneRecord())
			if err == nil {
				t.Fatalf("bridge answered %d and produceJSON reported success — "+
					"the producer would count these events as delivered", status)
			}
			if n != 0 {
				t.Fatalf("bridge answered %d but produceJSON claimed %d records accepted; "+
					"a rejected batch delivered nothing", status, n)
			}
		})
	}
}

// TestProduceReportsTransportFailure: bridge unreachable — the realistic shape
// during a restart or a network partition.
func TestProduceReportsTransportFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // now refusing connections
	t.Setenv("BUS_BRIDGE_URL", url)

	n, err := produceJSON(context.Background(), "netops.test", oneRecord())
	if err == nil {
		t.Fatal("unreachable bridge reported success — every event in this batch is " +
			"lost and no counter moved")
	}
	if n != 0 {
		t.Fatalf("unreachable bridge claimed %d records accepted", n)
	}
}

// TestProduceIsBoundedWhenTheBridgeHangs: a hung bridge must not pin the
// calling worker forever. §9 requires every IO to be bounded.
func TestProduceIsBoundedWhenTheBridgeHangs(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	s := newBusBridgeStub(t, 200, "")
	s.delay = 3 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := produceJSON(ctx, "netops.test", oneRecord())
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a hung bridge returned success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("produceJSON ignored its context deadline — a hung bus bridge " +
			"pins the calling worker and the backlog grows behind it")
	}
}

// TestProduceCarriesIngestAuth is F-08: the bridge's netops.* prefix check is a
// ROUTING guard, not identity. Without this header anything on the compose
// network could produce onto any tenant's topic.
func TestProduceCarriesIngestAuth(t *testing.T) {
	t.Setenv("INGEST_TOKEN", "secret-token")
	// The credential is cached behind a sync.Once (deliberate in production: a
	// mid-flight env change must not split the fleet's behaviour). Re-read it so
	// this test actually exercises the configured path.
	collectors.ResetIngestCredentialForTest()
	t.Cleanup(collectors.ResetIngestCredentialForTest)
	s := newBusBridgeStub(t, 200, "")

	if _, err := produceJSON(context.Background(), "netops.test", oneRecord()); err != nil {
		t.Fatalf("produce: %v", err)
	}
	auth, _ := s.lastAuth.Load().(string)
	if strings.TrimSpace(auth) == "" {
		t.Fatal("produce sent NO Authorization header — the bus bridge accepts " +
			"unauthenticated writes from anything that can reach it (F-08)")
	}
}

// TestProduceWireShapeIsOneEnvelopePerRecord pins the consumer's contract: the
// remap on the other side unwraps `event` onto the topic named by `topic`, so a
// shape change here silently breaks every downstream consumer.
func TestProduceWireShapeIsOneEnvelopePerRecord(t *testing.T) {
	s := newBusBridgeStub(t, 200, "")

	recs := []proxyRecord{
		{Key: "a", Value: map[string]any{"n": 1}},
		{Key: "b", Value: map[string]any{"n": 2}},
		{Value: map[string]any{"n": 3}}, // keyless is legal
	}
	n, err := produceJSON(context.Background(), "netops.demo", recs)
	if err != nil {
		t.Fatalf("produce: %v", err)
	}
	if n != len(recs) {
		t.Fatalf("accepted count = %d, want %d", n, len(recs))
	}

	raw, _ := s.lastBody.Load().([]byte)
	var envs []busEnvelope
	if err := json.Unmarshal(raw, &envs); err != nil {
		t.Fatalf("body is not a JSON array of envelopes: %v (%s)", err, string(raw))
	}
	if len(envs) != len(recs) {
		t.Fatalf("wire carried %d envelopes for %d records", len(envs), len(recs))
	}
	for i, e := range envs {
		if e.Topic != "netops.demo" {
			t.Fatalf("envelope %d topic = %q, want netops.demo", i, e.Topic)
		}
		if e.Event == nil {
			t.Fatalf("envelope %d has no event payload", i)
		}
	}
}

// TestProduceEmptyAndDisabledAreNoOps: the offline-safe paths must stay silent
// successes — a dev box with the bridge disabled must not error on every emit.
func TestProduceEmptyAndDisabledAreNoOps(t *testing.T) {
	s := newBusBridgeStub(t, 500, "should never be called")

	if n, err := produceJSON(context.Background(), "netops.test", nil); err != nil || n != 0 {
		t.Fatalf("empty batch = (%d, %v), want (0, nil)", n, err)
	}
	t.Setenv("BUS_BRIDGE_URL", "")
	if n, err := produceJSON(context.Background(), "netops.test", oneRecord()); err != nil || n != 0 {
		t.Fatalf("disabled bridge = (%d, %v), want a silent (0, nil) no-op", n, err)
	}
	if got := s.requests.Load(); got != 0 {
		t.Fatalf("stub received %d requests; neither path should have dialled", got)
	}
}

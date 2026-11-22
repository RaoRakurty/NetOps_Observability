// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

// dem_signed_test.go — both Digital Experience channels are signed (tracker
// 475). Before this, any service holding the Valkey password could SET
// netops:dem:targets to point the prober's checks at hosts of its choosing, or
// SET netops:dem:runs:<v> with runs naming any tenant — and those runs landed
// in that tenant's experience grade.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/dem"
	"netops/backend/internal/probercontrol"
)

func testDEMRunVerifier(acceptUnsigned bool) *probercontrol.ResultVerifier {
	return probercontrol.NewResultVerifier(testPathRing(), probercontrol.KindDEMRuns, DEMRunsMaxAge,
		time.Now, func() bool { return acceptUnsigned }, nil)
}

// sealRunBatch signs body as vantage's run batch with the test key.
func sealRunBatch(t *testing.T, vantage string, body []byte) string {
	t.Helper()
	raw, err := NewDEMRunSealer(testPathRing())(vantage, body)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return raw
}

func runBatchJSON(t *testing.T, runs ...dem.WireRun) []byte {
	t.Helper()
	b, err := json.Marshal(runs)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func aRun(id, tenant, vantage string) dem.WireRun {
	now := time.Now().UTC()
	return dem.WireRun{ID: id, Tenant: tenant, TargetID: "dem-1", Kind: dem.KindICMP, Vantage: vantage,
		StartedAt: now.Add(-time.Second), EndedAt: now, Outcome: dem.RunSuccess}
}

// ── the run batches (prober → api) ──────────────────────────────────────────

func TestFetchDEMRunsServesASignedBatchAttributedToItsSigner(t *testing.T) {
	// The batch claims another vantage on its run; the signature says who ran it.
	body := runBatchJSON(t, aRun("r1", "t_acme", "someone-else"))
	fakeRedis(t, respArray("van-a"), respBulk(sealRunBatch(t, "van-a", body)))
	v := testDEMRunVerifier(false)
	runs, err := FetchDEMRuns(context.Background(), v)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(runs) != 1 || runs[0].ID != "r1" || runs[0].Vantage != "van-a" {
		t.Fatalf("runs = %+v, want the one signed run attributed to van-a", runs)
	}
	if v.Count(probercontrol.ReasonVerified) != 1 {
		t.Fatal("the verified batch was not counted")
	}
}

func TestFetchDEMRunsRefusesAnUnsignedBatch(t *testing.T) {
	forged := runBatchJSON(t, aRun("forged", "t_victim", "van-a"))
	good := runBatchJSON(t, aRun("good", "t_acme", "van-b"))
	fakeRedis(t, respArray("van-a", "van-b"), respBulk(string(forged)), respBulk(sealRunBatch(t, "van-b", good)))
	v := testDEMRunVerifier(false)
	runs, err := FetchDEMRuns(context.Background(), v)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(runs) != 1 || runs[0].ID != "good" {
		t.Fatalf("runs = %+v, want only the signed vantage's run", runs)
	}
	if v.Count(probercontrol.ReasonUnsigned) != 1 {
		t.Fatal("the unsigned batch was not counted")
	}
}

func TestFetchDEMRunsRefusesABadSignature(t *testing.T) {
	body := runBatchJSON(t, aRun("r1", "t_acme", "van-a"))
	other := probercontrol.NewKeyring(staticKey("another-key-that-is-not-the-prober-control"), time.Now)
	forged, err := NewDEMRunSealer(other)("van-a", body)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(sealRunBatch(t, "van-a", body), "t_acme", "t_evil", 1)
	for name, raw := range map[string]string{"another key": forged, "tampered tenant": tampered} {
		t.Run(name, func(t *testing.T) {
			fakeRedis(t, respArray("van-a"), respBulk(raw))
			v := testDEMRunVerifier(false)
			runs, err := FetchDEMRuns(context.Background(), v)
			if err != nil {
				t.Fatalf("drain: %v", err)
			}
			if len(runs) != 0 || v.Count(probercontrol.ReasonBadSignature) != 1 {
				t.Fatalf("a badly signed batch was believed: runs=%+v", runs)
			}
		})
	}
}

// A path set signed by the prober is still not a run batch: the kind is bound
// into the signature.
func TestFetchDEMRunsRefusesARecordOfAnotherKind(t *testing.T) {
	body := runBatchJSON(t, aRun("r1", "t_acme", "van-a"))
	fakeRedis(t, respArray("van-a"), respBulk(sealPathSet(t, "van-a", body)))
	v := testDEMRunVerifier(false)
	runs, err := FetchDEMRuns(context.Background(), v)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(runs) != 0 || v.Count(probercontrol.ReasonBadSignature) != 1 {
		t.Fatalf("a probe-paths record was believed as a run batch: %+v", runs)
	}
}

func TestFetchDEMRunsRefusesABatchFromAnotherVantagesSlot(t *testing.T) {
	body := runBatchJSON(t, aRun("r1", "t_acme", "van-a"))
	fakeRedis(t, respArray("van-b"), respBulk(sealRunBatch(t, "van-a", body)))
	v := testDEMRunVerifier(false)
	runs, err := FetchDEMRuns(context.Background(), v)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(runs) != 0 || v.Count(probercontrol.ReasonWrongVantage) != 1 {
		t.Fatalf("van-a's batch was believed from van-b's slot: %+v", runs)
	}
}

func TestFetchDEMRunsRefusesAStaleOrFutureBatch(t *testing.T) {
	body := runBatchJSON(t, aRun("r1", "t_acme", "van-a"))
	for name, at := range map[string]time.Time{
		"stale":  time.Now().Add(-DEMRunsMaxAge - time.Minute),
		"future": time.Now().Add(5 * time.Minute),
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := probercontrol.SealResult(testPathRing(), probercontrol.KindDEMRuns, "van-a", body, at)
			if err != nil {
				t.Fatal(err)
			}
			fakeRedis(t, respArray("van-a"), respBulk(raw))
			v := testDEMRunVerifier(false)
			runs, err := FetchDEMRuns(context.Background(), v)
			if err != nil {
				t.Fatalf("drain: %v", err)
			}
			if len(runs) != 0 || v.Count(probercontrol.ReasonStale) != 1 {
				t.Fatalf("a %s batch was believed: %+v", name, runs)
			}
		})
	}
}

func TestFetchDEMRunsRefusesAReplayedOlderBatch(t *testing.T) {
	v := testDEMRunVerifier(false)
	now := time.Now()
	older, err := probercontrol.SealResult(testPathRing(), probercontrol.KindDEMRuns, "van-a",
		runBatchJSON(t, aRun("old", "t_acme", "van-a")), now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	newer, err := probercontrol.SealResult(testPathRing(), probercontrol.KindDEMRuns, "van-a",
		runBatchJSON(t, aRun("new", "t_acme", "van-a")), now)
	if err != nil {
		t.Fatal(err)
	}
	fakeRedis(t, respArray("van-a"), respBulk(newer))
	if runs, err := FetchDEMRuns(context.Background(), v); err != nil || len(runs) != 1 {
		t.Fatalf("the current batch was not read: %+v %v", runs, err)
	}
	fakeRedis(t, respArray("van-a"), respBulk(older))
	runs, err := FetchDEMRuns(context.Background(), v)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(runs) != 0 || v.Count(probercontrol.ReasonReplayed) != 1 {
		t.Fatalf("an older batch replayed into the slot was believed: %+v", runs)
	}
}

func TestFetchDEMRunsWithoutAKeyOrVerifierBelievesNothing(t *testing.T) {
	body := runBatchJSON(t, aRun("r1", "t_acme", "van-a"))
	fakeRedis(t, respArray("van-a"), respBulk(sealRunBatch(t, "van-a", body)))
	v := probercontrol.NewResultVerifier(probercontrol.NewKeyring(nil, time.Now), probercontrol.KindDEMRuns,
		DEMRunsMaxAge, time.Now, nil, nil)
	runs, err := FetchDEMRuns(context.Background(), v)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(runs) != 0 || v.Count(probercontrol.ReasonNoKey) != 1 {
		t.Fatalf("a verifier with no key believed a batch: %+v", runs)
	}
	if runs, err := FetchDEMRuns(context.Background(), nil); err == nil || len(runs) != 0 {
		t.Fatalf("a nil verifier read runs: %+v %v", runs, err)
	}
}

func TestFetchDEMRunsLegacySwitchAcceptsUnsignedButNeverABadSignature(t *testing.T) {
	body := runBatchJSON(t, aRun("legacy", "t_acme", "van-a"))
	tampered := strings.Replace(sealRunBatch(t, "van-b", runBatchJSON(t, aRun("x", "t_acme", "van-b"))), "t_acme", "t_evil", 1)
	fakeRedis(t, respArray("van-a", "van-b"), respBulk(string(body)), respBulk(tampered))
	v := testDEMRunVerifier(true)
	runs, err := FetchDEMRuns(context.Background(), v)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(runs) != 1 || runs[0].ID != "legacy" {
		t.Fatalf("runs = %+v, want only the unsigned legacy batch", runs)
	}
	if v.Count(probercontrol.ReasonUnsignedAccepted) != 1 || v.Count(probercontrol.ReasonBadSignature) != 1 {
		t.Fatalf("outcomes: unsigned_accepted=%d bad_signature=%d",
			v.Count(probercontrol.ReasonUnsignedAccepted), v.Count(probercontrol.ReasonBadSignature))
	}
}

// ── the work queue (api → prober) ───────────────────────────────────────────

func demQueueJSON(t *testing.T, ts ...dem.WireTarget) []byte {
	t.Helper()
	b, err := json.Marshal(ts)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sealQueue(t *testing.T, ring *probercontrol.Keyring, body []byte, ttl int, at time.Time) string {
	t.Helper()
	raw, err := probercontrol.SealDEMTargets(ring, body, ttl, at)
	if err != nil {
		t.Fatalf("seal queue: %v", err)
	}
	return raw
}

var queueTarget = dem.WireTarget{ID: "dem-1", Tenant: "t_acme", Kind: dem.KindHTTP, Host: "https://app.example.com", IntervalSec: 60}

func TestFetchDEMTargetsReadsASignedQueue(t *testing.T) {
	fakeRedis(t, respBulk(sealQueue(t, testPathRing(), demQueueJSON(t, queueTarget), 180, time.Now())))
	got, err := FetchDEMTargets(context.Background(), probercontrol.NewDEMTargetsReader(testPathRing(), time.Now))
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got) != 1 || got[0] != queueTarget {
		t.Fatalf("queue = %+v, want the one signed target", got)
	}
}

func TestFetchDEMTargetsAbsentKeyIsAnEmptyQueue(t *testing.T) {
	fakeRedis(t, "$-1\r\n")
	got, err := FetchDEMTargets(context.Background(), probercontrol.NewDEMTargetsReader(testPathRing(), time.Now))
	if err != nil || len(got) != 0 {
		t.Fatalf("an absent queue read as %+v %v, want empty and no error", got, err)
	}
}

// Every refusal is an error naming the reason, and NOTHING is measured.
func TestFetchDEMTargetsRefusesEveryUnprovenQueue(t *testing.T) {
	body := demQueueJSON(t, queueTarget)
	other := probercontrol.NewKeyring(staticKey("another-key-that-is-not-the-prober-control"), time.Now)
	now := time.Now()
	asP3Targets, err := testPathRing().Seal(probercontrol.KindTargets, body)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		raw  string
		ring *probercontrol.Keyring
		want probercontrol.Reason
	}{
		{"unsigned", string(body), testPathRing(), probercontrol.ReasonUnsigned},
		{"another key", sealQueue(t, other, body, 180, now), testPathRing(), probercontrol.ReasonBadSignature},
		{"tampered host", strings.Replace(sealQueue(t, testPathRing(), body, 180, now), "app.example.com", "evil.example.net", 1),
			testPathRing(), probercontrol.ReasonBadSignature},
		{"another kind", asP3Targets, testPathRing(), probercontrol.ReasonBadSignature},
		{"stale", sealQueue(t, testPathRing(), body, 180, now.Add(-4*time.Minute)), testPathRing(), probercontrol.ReasonStale},
		{"future", sealQueue(t, testPathRing(), body, 180, now.Add(5*time.Minute)), testPathRing(), probercontrol.ReasonStale},
		{"no key", sealQueue(t, testPathRing(), body, 180, now), probercontrol.NewKeyring(nil, time.Now), probercontrol.ReasonNoKey},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fakeRedis(t, respBulk(c.raw))
			got, err := FetchDEMTargets(context.Background(), probercontrol.NewDEMTargetsReader(c.ring, time.Now))
			if !errors.Is(err, ErrDEMTargetsRefused) || !strings.Contains(err.Error(), string(c.want)) {
				t.Fatalf("err = %v, want a refusal naming %s", err, c.want)
			}
			if len(got) != 0 {
				t.Fatalf("a refused queue still yielded targets: %+v", got)
			}
		})
	}
	if _, err := FetchDEMTargets(context.Background(), nil); !errors.Is(err, ErrDEMTargetsRefused) {
		t.Fatalf("a nil reader read a queue: %v", err)
	}
}

func TestFetchDEMTargetsRefusesAReplayedOlderQueue(t *testing.T) {
	r := probercontrol.NewDEMTargetsReader(testPathRing(), time.Now)
	now := time.Now()
	fakeRedis(t, respBulk(sealQueue(t, testPathRing(), demQueueJSON(t, queueTarget), 180, now)))
	if _, err := FetchDEMTargets(context.Background(), r); err != nil {
		t.Fatalf("the current queue was refused: %v", err)
	}
	fakeRedis(t, respBulk(sealQueue(t, testPathRing(), []byte("[]"), 180, now.Add(-time.Minute))))
	if _, err := FetchDEMTargets(context.Background(), r); !errors.Is(err, ErrDEMTargetsRefused) ||
		!strings.Contains(err.Error(), string(probercontrol.ReasonReplayed)) {
		t.Fatalf("an older queue replayed into the key was believed: %v", err)
	}
}

// ── both directions end to end, through the real publishers ────────────────

// captureRedis serves any number of connections, records every command, and
// answers GET from what was SET (SADD/EXPIRE/SMEMBERS are answered plausibly).
type captureRedis struct {
	mu   sync.Mutex
	cmds [][]string
	kv   map[string]string
	set  map[string][]string
}

func newCaptureRedis(t *testing.T) *captureRedis {
	t.Helper()
	cr := &captureRedis{kv: map[string]string{}, set: map[string][]string{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("REDIS_HOST", host)
	t.Setenv("REDIS_PORT", port)
	t.Setenv("REDIS_PASSWORD", "")
	t.Setenv("REDIS_TLS", "")
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go cr.serve(c)
		}
	}()
	return cr
}

func (cr *captureRedis) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	for {
		hdr, err := r.ReadString('\n')
		if err != nil || len(hdr) == 0 || hdr[0] != '*' {
			return
		}
		n, err := strconv.Atoi(strings.TrimSpace(hdr[1:]))
		if err != nil {
			return
		}
		args := make([]string, 0, n)
		for i := 0; i < n; i++ {
			lh, err := r.ReadString('\n')
			if err != nil || len(lh) == 0 || lh[0] != '$' {
				return
			}
			l, err := strconv.Atoi(strings.TrimSpace(lh[1:]))
			if err != nil {
				return
			}
			buf := make([]byte, l+2)
			if _, err := io.ReadFull(r, buf); err != nil {
				return
			}
			args = append(args, string(buf[:l]))
		}
		cr.mu.Lock()
		cr.cmds = append(cr.cmds, args)
		reply := "+OK\r\n"
		switch strings.ToUpper(args[0]) {
		case "SET":
			cr.kv[args[1]] = args[2]
		case "GET":
			if v, ok := cr.kv[args[1]]; ok {
				reply = respBulk(v)
			} else {
				reply = "$-1\r\n"
			}
		case "SADD":
			cr.set[args[1]] = append(cr.set[args[1]], args[2:]...)
			reply = ":1\r\n"
		case "EXPIRE":
			reply = ":1\r\n"
		case "SMEMBERS":
			reply = respArray(cr.set[args[1]]...)
		}
		cr.mu.Unlock()
		if _, err := c.Write([]byte(reply)); err != nil {
			return
		}
	}
}

func (cr *captureRedis) value(key string) string {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	return cr.kv[key]
}

func TestPublishedDEMTargetsAreSignedAndReadBack(t *testing.T) {
	cr := newCaptureRedis(t)
	if err := PublishDEMTargets(context.Background(), testPathRing(), []dem.WireTarget{queueTarget}, 180); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if strings.HasPrefix(cr.value(demTargetsKey), "[") {
		t.Fatal("the work queue was published as plain JSON")
	}
	got, err := FetchDEMTargets(context.Background(), probercontrol.NewDEMTargetsReader(testPathRing(), time.Now))
	if err != nil || len(got) != 1 || got[0] != queueTarget {
		t.Fatalf("the published queue did not read back: %+v %v", got, err)
	}
	// An empty queue is published as an empty (signed) list, not as null.
	if err := PublishDEMTargets(context.Background(), testPathRing(), nil, 180); err != nil {
		t.Fatalf("publish empty: %v", err)
	}
	if got, err := FetchDEMTargets(context.Background(), probercontrol.NewDEMTargetsReader(testPathRing(), time.Now)); err != nil || len(got) != 0 {
		t.Fatalf("the empty queue did not read back as empty: %+v %v", got, err)
	}
}

func TestPublishDEMTargetsWithoutAKeyWritesNothing(t *testing.T) {
	cr := newCaptureRedis(t)
	err := PublishDEMTargets(context.Background(), probercontrol.NewKeyring(nil, time.Now), []dem.WireTarget{queueTarget}, 180)
	if !errors.Is(err, probercontrol.ErrNoKey) {
		t.Fatalf("err = %v, want ErrNoKey", err)
	}
	if cr.value(demTargetsKey) != "" {
		t.Fatal("an unsigned queue was written")
	}
}

func TestPublishedDEMRunsAreSignedAndReadBack(t *testing.T) {
	cr := newCaptureRedis(t)
	t.Setenv("PROBER_ID", "van-pub")
	if err := PublishDEMRuns(context.Background(), NewDEMRunSealer(testPathRing()), []dem.WireRun{aRun("r1", "t_acme", "van-pub")}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if strings.HasPrefix(cr.value(demRunsKeyFor("van-pub")), "[") {
		t.Fatal("the run batch was published as plain JSON")
	}
	runs, err := FetchDEMRuns(context.Background(), testDEMRunVerifier(false))
	if err != nil || len(runs) != 1 || runs[0].ID != "r1" || runs[0].Vantage != "van-pub" {
		t.Fatalf("the published batch did not read back: %+v %v", runs, err)
	}
}

func TestPublishDEMRunsWithoutAKeyWritesNothing(t *testing.T) {
	cr := newCaptureRedis(t)
	t.Setenv("PROBER_ID", "van-pub")
	err := PublishDEMRuns(context.Background(), NewDEMRunSealer(probercontrol.NewKeyring(nil, time.Now)), []dem.WireRun{aRun("r1", "t_acme", "van-pub")})
	if !errors.Is(err, probercontrol.ErrNoKey) {
		t.Fatalf("err = %v, want ErrNoKey", err)
	}
	if err := PublishDEMRuns(context.Background(), nil, nil); err == nil {
		t.Fatal("a nil sealer published")
	}
	cr.mu.Lock()
	n := len(cr.cmds)
	cr.mu.Unlock()
	if n != 0 {
		t.Fatalf("an unsigned batch reached the store (%d commands)", n)
	}
}

// NewDEM wires both directions to the rendered prober-control key.
func TestNewDEMSignsBothWaysWithTheRenderedKey(t *testing.T) {
	cr := newCaptureRedis(t)
	keyFile := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(keyFile, []byte(testPathKey), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(probercontrol.EnvKeyFile, keyFile)
	t.Setenv("PROBER_ID", "van-wired")
	if err := PublishDEMTargets(context.Background(), testPathRing(), []dem.WireTarget{queueTarget}, 180); err != nil {
		t.Fatalf("publish queue: %v", err)
	}
	r := NewDEM().(*demRunner)
	got, err := r.fetch(context.Background())
	if err != nil || len(got) != 1 || got[0] != queueTarget {
		t.Fatalf("the runner did not read the signed queue: %+v %v", got, err)
	}
	if err := r.publishRuns(context.Background(), []dem.WireRun{aRun("r1", "t_acme", "van-wired")}); err != nil {
		t.Fatalf("publish runs: %v", err)
	}
	if _, why, ok := testDEMRunVerifier(false).Open("van-wired", cr.value(demRunsKeyFor("van-wired"))); !ok {
		t.Fatalf("the runner's batch does not verify: %s", why)
	}
}

// With no key, the runner measures nothing from the store and says why.
func TestDEMRunnerWithoutAKeyMeasuresNothing(t *testing.T) {
	newCaptureRedis(t)
	t.Setenv(probercontrol.EnvKeyFile, "")
	if err := PublishDEMTargets(context.Background(), testPathRing(), []dem.WireTarget{queueTarget}, 180); err != nil {
		t.Fatalf("publish queue: %v", err)
	}
	h := newDEMHarness(t, nil)
	r := NewDEM().(*demRunner)
	h.runner.fetch = r.fetch
	h.tick(t)
	st := h.runner.Status()
	if st.Healthy || !strings.Contains(st.LastError, string(probercontrol.ReasonNoKey)) {
		t.Fatalf("status after a queue the runner cannot verify: %+v", st)
	}
}

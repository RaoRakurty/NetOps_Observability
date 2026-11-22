// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package probercontrol

// dem_test.go — the Digital Experience channels (tracker 475). The work queue
// (api → prober) and the run batches (prober → api) each refuse every record
// they cannot prove; each case below is a separate hole.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const queueBody = `[{"id":"dem-1","tenant":"t_acme","kind":"http","host":"https://app.example.com?a=1&b=<2>","interval_sec":60}]`

const runsBody = `[{"id":"r1","tenant":"t_acme","target_id":"dem-1","kind":"http","vantage":"prober","outcome":"success"}]`

func sealQueueAt(t *testing.T, r *Keyring, ttl int, at time.Time) string {
	t.Helper()
	raw, err := SealDEMTargets(r, []byte(queueBody), ttl, at)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return raw
}

// ── work queue ──────────────────────────────────────────────────────────────

func TestDEMTargetsRoundTrip(t *testing.T) {
	r := NewDEMTargetsReader(ring(), clock(t0.Add(time.Minute)))
	body, why := r.Open(sealQueueAt(t, ring(), 180, t0))
	if why != ReasonPublished {
		t.Fatalf("a good queue was refused: %s", why)
	}
	// The same queue (the encoder may escape &, < and > inside the record;
	// the decoded host is identical — a URL query string is the case that
	// broke the P3 envelope once).
	var got, want []map[string]any
	if json.Unmarshal(body, &got) != nil || json.Unmarshal([]byte(queueBody), &want) != nil ||
		len(got) != 1 || got[0]["host"] != want[0]["host"] || got[0]["tenant"] != "t_acme" {
		t.Fatalf("the queue changed in transit: %s", body)
	}
	// Re-reading the same record is the ordinary case (every tick).
	if _, why := r.Open(sealQueueAt(t, ring(), 180, t0)); why != ReasonPublished {
		t.Fatalf("re-reading the current queue was refused: %s", why)
	}
}

func TestDEMTargetsReaderRefusals(t *testing.T) {
	other := NewKeyring(&keyVal{v: strings.Repeat("q", 43)}, clock(t0))
	good := sealQueueAt(t, ring(), 180, t0)
	asP3Targets, err := ring().Seal(KindTargets, []byte(queueBody))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(DEMTargetsRecord{V: DEMTargetsSchemaVersion, IssuedAt: t0, TTLSec: 180, Targets: json.RawMessage(queueBody)})
	if err != nil {
		t.Fatal(err)
	}
	asRuns, err := ring().Seal(KindDEMRuns, payload)
	if err != nil {
		t.Fatal(err)
	}
	seal := func(rec DEMTargetsRecord) string {
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		s, err := ring().Seal(KindDEMTargets, b)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	cases := []struct {
		name string
		ring *Keyring
		now  time.Time
		raw  string
		want Reason
	}{
		{"empty key", ring(), t0, "", ReasonNotPublished},
		{"unsigned", ring(), t0, queueBody, ReasonUnsigned},
		{"another key", ring(), t0, sealQueueAt(t, other, 180, t0), ReasonBadSignature},
		{"tampered tenant", ring(), t0, strings.Replace(good, "t_acme", "t_other", 1), ReasonBadSignature},
		{"P3 targets kind", ring(), t0, asP3Targets, ReasonBadSignature},
		{"dem-runs kind", ring(), t0, asRuns, ReasonBadSignature},
		{"no key", NewKeyring(nil, clock(t0)), t0, good, ReasonNoKey},
		{"older than its TTL", ring(), t0.Add(181 * time.Second), good, ReasonStale},
		{"future-stamped", ring(), t0.Add(-2 * time.Minute), good, ReasonStale},
		{"TTL capped", ring(), t0.Add(MaxDEMTargetsAge + time.Second), sealQueueAt(t, ring(), 86400, t0), ReasonStale},
		{"schema", ring(), t0, seal(DEMTargetsRecord{V: 2, IssuedAt: t0, TTLSec: 180, Targets: json.RawMessage(queueBody)}), ReasonInvalid},
		{"no issued_at", ring(), t0, seal(DEMTargetsRecord{V: 1, TTLSec: 180, Targets: json.RawMessage(queueBody)}), ReasonInvalid},
		{"no ttl", ring(), t0, seal(DEMTargetsRecord{V: 1, IssuedAt: t0, Targets: json.RawMessage(queueBody)}), ReasonInvalid},
		{"targets not a list", ring(), t0, seal(DEMTargetsRecord{V: 1, IssuedAt: t0, TTLSec: 180, Targets: json.RawMessage(`{"id":"x"}`)}), ReasonInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body, why := NewDEMTargetsReader(c.ring, clock(c.now)).Open(c.raw)
			if why != c.want || body != nil {
				t.Fatalf("Open = %s %q, want %s and no body", why, body, c.want)
			}
		})
	}
	var nilR *DEMTargetsReader
	if body, why := nilR.Open(good); why != ReasonNoKey || body != nil {
		t.Fatalf("a nil reader read a queue: %s", why)
	}
}

func TestDEMTargetsReplayOfAnOlderQueueIsRefused(t *testing.T) {
	r := NewDEMTargetsReader(ring(), clock(t0.Add(2*time.Minute)))
	if _, why := r.Open(sealQueueAt(t, ring(), 180, t0.Add(time.Minute))); why != ReasonPublished {
		t.Fatalf("the newer queue was refused: %s", why)
	}
	if body, why := r.Open(sealQueueAt(t, ring(), 180, t0)); why != ReasonReplayed || body != nil {
		t.Fatalf("an older queue replayed into the key was accepted: %s", why)
	}
}

func TestSealDEMTargetsRefusesABadInput(t *testing.T) {
	if _, err := SealDEMTargets(ring(), []byte(queueBody), 0, t0); err == nil {
		t.Error("a queue with no TTL was sealed")
	}
	for _, body := range []string{"not json", "null", `{"id":"x"}`} {
		if _, err := SealDEMTargets(ring(), []byte(body), 180, t0); err == nil {
			t.Errorf("a non-list queue %q was sealed", body)
		}
	}
	if _, err := SealDEMTargets(NewKeyring(nil, clock(t0)), []byte(queueBody), 180, t0); err == nil {
		t.Error("a queue was sealed with no key")
	}
}

// ── run batches ─────────────────────────────────────────────────────────────

func runVerifierAt(now *time.Time, accept bool) *ResultVerifier {
	return NewResultVerifier(ring(), KindDEMRuns, 2*time.Minute, func() time.Time { return *now },
		func() bool { return accept }, nil)
}

func sealRuns(t *testing.T, r *Keyring, vantage string, at time.Time) string {
	t.Helper()
	raw, err := SealResult(r, KindDEMRuns, vantage, []byte(runsBody), at)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return raw
}

func TestDEMRunsRoundTripCarriesTheSignedVantage(t *testing.T) {
	now := t0
	v := runVerifierAt(&now, false)
	o, why, ok := v.Open("prober", sealRuns(t, ring(), "prober", t0))
	if !ok || why != ReasonVerified || !o.Signed || o.Vantage != "prober" || !bytes.Equal(o.Body, []byte(runsBody)) {
		t.Fatalf("a good run batch was not accepted intact: %+v %s %v", o, why, ok)
	}
}

func TestDEMRunsRefusals(t *testing.T) {
	other := NewKeyring(&keyVal{v: strings.Repeat("q", 43)}, clock(t0))
	asPaths, err := SealResult(ring(), KindProbePaths, "prober", []byte(runsBody), t0)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		slot string
		now  time.Time
		raw  string
		want Reason
	}{
		{"unsigned", "prober", t0, runsBody, ReasonUnsigned},
		{"another key", "prober", t0, sealRuns(t, other, "prober", t0), ReasonBadSignature},
		{"tampered tenant", "prober", t0, strings.Replace(sealRuns(t, ring(), "prober", t0), "t_acme", "t_victim", 1), ReasonBadSignature},
		{"probe-paths kind", "prober", t0, asPaths, ReasonBadSignature},
		{"another vantage's slot", "lan", t0, sealRuns(t, ring(), "prober", t0), ReasonWrongVantage},
		{"stale", "prober", t0.Add(2*time.Minute + time.Second), sealRuns(t, ring(), "prober", t0), ReasonStale},
		{"future-stamped", "prober", t0, sealRuns(t, ring(), "prober", t0.Add(2*time.Minute)), ReasonStale},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			now := c.now
			v := runVerifierAt(&now, false)
			if _, why, ok := v.Open(c.slot, c.raw); ok || why != c.want {
				t.Fatalf("Open = %s %v, want refused as %s", why, ok, c.want)
			}
			if v.Count(c.want) != 1 {
				t.Fatalf("the refusal was not counted under %s", c.want)
			}
		})
	}
}

func TestDEMRunsReplayOfAnOlderBatchIsRefused(t *testing.T) {
	now := t0.Add(time.Minute)
	v := runVerifierAt(&now, false)
	if _, why, ok := v.Open("prober", sealRuns(t, ring(), "prober", t0.Add(30*time.Second))); !ok {
		t.Fatalf("the newer batch was refused: %s", why)
	}
	if _, why, ok := v.Open("prober", sealRuns(t, ring(), "prober", t0)); ok || why != ReasonReplayed {
		t.Fatalf("an older batch replayed into the slot was accepted: %s %v", why, ok)
	}
}

func TestDEMRunsLegacySwitchAcceptsUnsignedButNeverABadSignature(t *testing.T) {
	now := t0
	v := runVerifierAt(&now, true)
	if o, why, ok := v.Open("prober", runsBody); !ok || why != ReasonUnsignedAccepted || o.Signed || o.Vantage != "" {
		t.Fatalf("the legacy switch did not accept the unsigned form as unproven: %+v %s %v", o, why, ok)
	}
	forged := strings.Replace(sealRuns(t, ring(), "prober", t0), "t_acme", "t_victim", 1)
	if _, why, ok := v.Open("prober", forged); ok || why != ReasonBadSignature {
		t.Fatalf("the legacy switch let a bad signature through: %s %v", why, ok)
	}
}

// The signature construction is pinned by a golden vector shared with
// scripts/demo_fill.py (tests/test_demo_fill_signing.py holds the same one):
// the demo signs its path set outside Go, so a change here must break both.
func TestSignatureGoldenVectorMatchesTheDemoSigner(t *testing.T) {
	const payload = `{"schema":1,"vantage":"demo-fill","issued_at":"2026-11-22T00:00:00.000000Z","body":[{"dst":"10.0.0.1"}]}`
	const want = "f70e6bee0e8064f509568abde6e86e36139c38ef9c79bd9d237eb0d9cb7674aa"
	k := NewKeyring(&keyVal{v: "golden-key-0123456789abcdefghijklmnopqrstu"}, clock(t0))
	raw, err := k.Seal(KindProbePaths, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatal(err)
	}
	if env.Sig != want || env.Payload != payload || env.V != 1 {
		t.Fatalf("envelope = %+v, want sig %s over the exact payload", env, want)
	}
	// A record in the demo's issued_at format opens as a result record.
	v := NewResultVerifier(k, KindProbePaths, 5*time.Minute, clock(time.Date(2026, 11, 22, 0, 1, 0, 0, time.UTC)), nil, nil)
	if o, why, ok := v.Open("", raw); !ok || o.Vantage != "demo-fill" {
		t.Fatalf("the demo-shaped record was refused: %s", why)
	}
}

// Two verifiers in one exposition share ONE HELP/TYPE header.
func TestWriteResultMetricsWritesOneHeaderForEveryKind(t *testing.T) {
	now := t0
	paths := verifierAt(&now, false, nil)
	runs := runVerifierAt(&now, false)
	runs.Open("prober", runsBody)
	var b bytes.Buffer
	WriteResultMetrics(&b, paths, nil, runs)
	out := b.String()
	if n := strings.Count(out, "# TYPE netops_prober_results_total"); n != 1 {
		t.Fatalf("TYPE header written %d times:\n%s", n, out)
	}
	if n := strings.Count(out, "# HELP netops_prober_results_total"); n != 1 {
		t.Fatalf("HELP header written %d times:\n%s", n, out)
	}
	for _, kind := range []string{KindProbePaths, KindDEMRuns} {
		for _, r := range resultReasons {
			if !strings.Contains(out, `netops_prober_results_total{kind="`+kind+`",reason="`+string(r)+`"}`) {
				t.Errorf("series %s/%s is missing", kind, r)
			}
		}
	}
	if !strings.Contains(out, `{kind="dem-runs",reason="unsigned"} 1`) {
		t.Errorf("the dem-runs refusal was not exposed:\n%s", out)
	}
	b.Reset()
	WriteResultMetrics(&b, nil, nil)
	if b.Len() != 0 {
		t.Errorf("no verifier still wrote a header: %q", b.String())
	}
}

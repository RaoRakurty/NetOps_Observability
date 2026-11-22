// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package probercontrol

// results_test.go — the prober's result records (tracker 475). Each refusal is
// a separate case because each closes a separate hole: a forged record
// (unsigned), a record from another key or edited in flight (bad signature),
// a record of another kind copied into a path slot, a record moved into
// another vantage's slot, a record kept and replayed later, and an older
// record replayed to roll a path back.

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

const pathsBody = `[{"dst":"10.0.0.1","method":"icmp","tenant_id":"t_acme","hops":[{"ip":"10.0.0.254"}]}]`

type reportLog struct{ got []string }

func (r *reportLog) report(kind, slot string, why Reason) {
	r.got = append(r.got, kind+"|"+slot+"|"+string(why))
}

func verifierAt(now *time.Time, accept bool, rep *reportLog) *ResultVerifier {
	var f ResultReport
	if rep != nil {
		f = rep.report
	}
	return NewResultVerifier(ring(), KindProbePaths, 5*time.Minute, func() time.Time { return *now },
		func() bool { return accept }, f)
}

func sealPaths(t *testing.T, r *Keyring, vantage string, at time.Time) string {
	t.Helper()
	raw, err := SealResult(r, KindProbePaths, vantage, []byte(pathsBody), at)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return raw
}

func TestResultRoundTripCarriesTheSignedVantage(t *testing.T) {
	now := t0
	v := verifierAt(&now, false, nil)
	o, why, ok := v.Open("prober", sealPaths(t, ring(), "prober", t0))
	if !ok || why != ReasonVerified || !o.Signed || o.Vantage != "prober" {
		t.Fatalf("a good record was not accepted: %+v %s %v", o, why, ok)
	}
	if !bytes.Equal(o.Body, []byte(pathsBody)) {
		t.Fatalf("the body changed in transit: %s", o.Body)
	}
	// A slot that names no vantage (legacy key, shared file) takes any vantage.
	if _, why, ok := v.Open("", sealPaths(t, ring(), "prober", t0)); !ok {
		t.Fatalf("a vantage-less slot refused a good record: %s", why)
	}
}

func TestResultMissingSignatureIsRefused(t *testing.T) {
	now := t0
	v := verifierAt(&now, false, nil)
	if _, why, ok := v.Open("prober", pathsBody); ok || why != ReasonUnsigned {
		t.Fatalf("an unsigned path set was accepted: %s %v", why, ok)
	}
	if v.Count(ReasonUnsigned) != 1 {
		t.Fatalf("the refusal was not counted")
	}
}

func TestResultTamperedBodyIsRefused(t *testing.T) {
	now := t0
	v := verifierAt(&now, false, nil)
	raw := sealPaths(t, ring(), "prober", t0)
	// Move the path to another tenant inside the signed payload.
	forged := strings.Replace(raw, `t_acme`, `t_other`, 1)
	if forged == raw {
		t.Fatal("test setup: the tenant is not in the envelope")
	}
	if _, why, ok := v.Open("prober", forged); ok || why != ReasonBadSignature {
		t.Fatalf("a tampered path set was accepted: %s %v", why, ok)
	}
}

func TestResultWrongKeyIsRefused(t *testing.T) {
	now := t0
	v := verifierAt(&now, false, nil)
	other := NewKeyring(&keyVal{v: strings.Repeat("q", 43)}, clock(t0))
	if _, why, ok := v.Open("prober", sealPaths(t, other, "prober", t0)); ok || why != ReasonBadSignature {
		t.Fatalf("a record under another key was accepted: %s %v", why, ok)
	}
}

func TestResultAnotherKindIsRefused(t *testing.T) {
	now := t0
	v := verifierAt(&now, false, nil)
	payload, err := json.Marshal(ResultRecord{Schema: resultSchema, Vantage: "prober", IssuedAt: t0, Body: json.RawMessage(pathsBody)})
	if err != nil {
		t.Fatal(err)
	}
	asTargets, err := ring().Seal(KindTargets, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, why, ok := v.Open("prober", asTargets); ok || why != ReasonBadSignature {
		t.Fatalf("a record signed as another kind was accepted as paths: %s %v", why, ok)
	}
}

func TestResultFromAnotherVantagesSlotIsRefused(t *testing.T) {
	now := t0
	v := verifierAt(&now, false, nil)
	if _, why, ok := v.Open("lan-vantage", sealPaths(t, ring(), "prober", t0)); ok || why != ReasonWrongVantage {
		t.Fatalf("vantage A's record was accepted from vantage B's slot: %s %v", why, ok)
	}
}

func TestResultStaleOrFutureIsRefused(t *testing.T) {
	now := t0.Add(5*time.Minute + time.Second)
	v := verifierAt(&now, false, nil)
	if _, why, ok := v.Open("prober", sealPaths(t, ring(), "prober", t0)); ok || why != ReasonStale {
		t.Fatalf("a record older than MaxAge was accepted: %s %v", why, ok)
	}
	now = t0
	if _, why, ok := v.Open("prober", sealPaths(t, ring(), "prober", t0.Add(2*time.Minute))); ok || why != ReasonStale {
		t.Fatalf("a record stamped in the future was accepted: %s %v", why, ok)
	}
}

func TestResultReplayOfAnOlderRecordIsRefused(t *testing.T) {
	now := t0.Add(2 * time.Minute)
	v := verifierAt(&now, false, nil)
	older := sealPaths(t, ring(), "prober", t0)
	newer := sealPaths(t, ring(), "prober", t0.Add(time.Minute))
	if _, why, ok := v.Open("prober", newer); !ok {
		t.Fatalf("the newer record was refused: %s", why)
	}
	// Re-reading the same record is the ordinary case (every read tick).
	if _, why, ok := v.Open("prober", newer); !ok {
		t.Fatalf("re-reading the current record was refused: %s", why)
	}
	if _, why, ok := v.Open("prober", older); ok || why != ReasonReplayed {
		t.Fatalf("an older record replayed into the slot was accepted: %s %v", why, ok)
	}
	// The mark is per vantage: another prober's older clock is not a replay.
	if _, why, ok := v.Open("lan", sealPaths(t, ring(), "lan", t0)); !ok {
		t.Fatalf("another vantage's record was refused as a replay: %s", why)
	}
}

func TestResultNoKeyReadsNothing(t *testing.T) {
	now := t0
	v := NewResultVerifier(NewKeyring(nil, clock(t0)), KindProbePaths, time.Minute, func() time.Time { return now }, nil, nil)
	if _, why, ok := v.Open("prober", sealPaths(t, ring(), "prober", t0)); ok || why != ReasonNoKey {
		t.Fatalf("a verifier with no key accepted a record: %s %v", why, ok)
	}
	var nilV *ResultVerifier
	if _, why, ok := nilV.Open("prober", pathsBody); ok || why != ReasonNoKey {
		t.Fatalf("a nil verifier accepted a record: %s %v", why, ok)
	}
}

func TestResultLegacySwitchAcceptsUnsignedButNeverABadSignature(t *testing.T) {
	now := t0
	v := verifierAt(&now, true, nil)
	o, why, ok := v.Open("prober", pathsBody)
	if !ok || why != ReasonUnsignedAccepted || o.Signed || o.Vantage != "" {
		t.Fatalf("the legacy switch did not accept the unsigned form as unproven: %+v %s %v", o, why, ok)
	}
	forged := strings.Replace(sealPaths(t, ring(), "prober", t0), `t_acme`, `t_other`, 1)
	if _, why, ok := v.Open("prober", forged); ok || why != ReasonBadSignature {
		t.Fatalf("the legacy switch let a bad signature through: %s %v", why, ok)
	}
	if _, why, ok := v.Open("prober", "not json"); ok || why != ReasonUnsigned {
		t.Fatalf("the legacy switch accepted a non-JSON record: %s %v", why, ok)
	}
}

func TestResultReportsOnlyOnChange(t *testing.T) {
	now := t0
	rep := &reportLog{}
	v := verifierAt(&now, false, rep)
	good := sealPaths(t, ring(), "prober", t0)
	v.Open("prober", good) // the normal first state: not reported
	v.Open("prober", pathsBody)
	v.Open("prober", pathsBody) // same refusal again: not reported again
	v.Open("prober", good)      // recovery: reported
	want := []string{"probe-paths|prober|unsigned", "probe-paths|prober|verified"}
	if strings.Join(rep.got, ",") != strings.Join(want, ",") {
		t.Fatalf("reports = %v, want %v", rep.got, want)
	}
}

func TestResultMetricsNameEveryReason(t *testing.T) {
	now := t0
	v := verifierAt(&now, false, nil)
	v.Open("prober", pathsBody)
	var b bytes.Buffer
	v.WriteMetrics(&b)
	out := b.String()
	for _, r := range resultReasons {
		if !strings.Contains(out, `netops_prober_results_total{kind="probe-paths",reason="`+string(r)+`"}`) {
			t.Errorf("metric series for %s is missing:\n%s", r, out)
		}
	}
	if !strings.Contains(out, `reason="unsigned"} 1`) {
		t.Errorf("the refusal was not exposed:\n%s", out)
	}
}

func TestSealResultRefusesABadInput(t *testing.T) {
	if _, err := SealResult(ring(), KindProbePaths, "", []byte(pathsBody), t0); err == nil {
		t.Error("a record with no vantage was sealed")
	}
	if _, err := SealResult(ring(), KindProbePaths, "prober", []byte("not json"), t0); err == nil {
		t.Error("a non-JSON body was sealed")
	}
}

func TestResultReplayMarksAreBounded(t *testing.T) {
	now := t0
	v := verifierAt(&now, false, nil)
	for i := 0; i < maxResultVantages+10; i++ {
		vant := "v" + strconv.Itoa(i)
		v.Open(vant, sealPaths(t, ring(), vant, t0))
	}
	v.mu.Lock()
	n, m := len(v.high), len(v.last)
	v.mu.Unlock()
	if n > maxResultVantages || m > maxResultVantages {
		t.Fatalf("per-vantage state grew past its bound: high=%d last=%d", n, m)
	}
}

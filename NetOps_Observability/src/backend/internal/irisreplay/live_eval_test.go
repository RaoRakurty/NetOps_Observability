// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

//go:build nlqmodeleval

package irisreplay

// live_eval_test.go — Incident Replay's LIVE leg against a REAL provider, over
// the committed corpus (ai/testdata/golden_incidents). Same build tag and
// environment as every other live model eval, so CI never compiles it and never
// calls a provider. Run it by hand, with a key you are allowed to spend:
//
//	NLQ_EVAL_PROVIDER=gemini NLQ_EVAL_API_KEY=... NLQ_EVAL_MODEL=gemini-3.5-flash-lite \
//	  go test -tags nlqmodeleval ./internal/irisreplay -run TestReplayLiveProvider -v -timeout 60m
//
// IRIS_REPLAY_LIVE_REPORT=<path> also writes the JSON report there (0600), to
// `irisreplay compare` with a scripted run. The test fails only on a FAIL the
// guards produce (a prohibited tool, a forbidden citation, a cross-tenant
// leak) — a live model saying something different from the scripted reply is
// the point of the run, reported, not failed.

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

func TestReplayLiveProvider(t *testing.T) {
	leg, err := LiveLegFromEnv(os.Getenv)
	if err != nil {
		t.Skip(err.Error())
	}
	rep, err := Run(context.Background(), loadCorpus(t), Options{Leg: leg})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("live leg %s: %d cases, results %v, fingerprint %s", rep.ModelLeg, rep.Aggregate.Cases, rep.Aggregate.Results, rep.Fingerprint.SHA256)
	for _, cr := range rep.Cases {
		if cr.Result == ResultFail {
			t.Errorf("case %s FAILED under the live model: %v", cr.ID, cr.Failures)
		}
	}
	if path := os.Getenv("IRIS_REPLAY_LIVE_REPORT"); path != "" {
		blob, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := writePrivate(path, blob); err != nil {
			t.Fatal(err)
		}
	}
}

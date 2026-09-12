// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package licence_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/entitlement"
	"netops/backend/internal/licence"
)

// overage_unmeasured_test.go — the difference between "counted, and under the
// limit" and "nobody counted".
//
// State.Overages omits a ceiling for BOTH reasons. The register used to read
// that omission as "the episode ended" and delete `overage_since` — the one
// fact in this package that a restart cannot recover — so a single failed read
// during a live overage silently destroyed durable state and restarted the
// clock at the next successful one.

// TestOverageClosesOnlyWhatWasMeasured is the regression. Three observations of
// one live episode: measured-and-over, NOT MEASURED, measured-and-over again.
// The start time must be the first one throughout.
func TestOverageClosesOnlyWhatWasMeasured(t *testing.T) {
	path := filepath.Join(t.TempDir(), "licence-overage.json")
	st := overState(t, entitlement.TierTeam, 250)
	t0 := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	tr := licence.NewOverageTracker(path, nil)
	if first := tr.Observe(st, licence.Usage{entitlement.CeilingDevices: 260}, t0); len(first) != 1 || !first[0].Since.Equal(t0) {
		t.Fatalf("the episode must open at t0: %+v", first)
	}

	// The failed read. licence.Usage says "not measured" by OMITTING the key,
	// so this is exactly the map licenceUsage builds when the count errors or
	// runs out of scrape budget — indistinguishable, at this layer, from the
	// map it builds when the ceiling is comfortably under its limit.
	if got := tr.Observe(st, licence.Usage{}, t0.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("an unmeasured ceiling reports no overage this round: %+v", got)
	}
	since, ok := tr.Since(entitlement.CeilingDevices)
	if !ok {
		t.Fatal("a failed measurement must NOT close a live episode — overage_since is durable state and nobody looked")
	}
	if !since.Equal(t0) {
		t.Fatalf("since = %s after an unmeasured round, want the original %s", since, t0)
	}

	// The next successful read is the SAME episode, not a new one starting now.
	back := tr.Observe(st, licence.Usage{entitlement.CeilingDevices: 265}, t0.Add(2*time.Hour))
	if len(back) != 1 {
		t.Fatalf("still over: %+v", back)
	}
	if !back[0].Since.Equal(t0) {
		t.Fatalf("since = %s, want %s — the clock must not have restarted at the unmeasured round", back[0].Since, t0)
	}

	// And the on-disk register agrees: the durable value survived, so a restart
	// after a run of failed reads still recovers the real start time.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Records []struct {
			Ceiling string    `json:"ceiling"`
			Since   time.Time `json:"since"`
			Peak    int       `json:"peak"`
		} `json:"records"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("register unreadable: %v (%s)", err, raw)
	}
	if len(f.Records) != 1 || f.Records[0].Ceiling != entitlement.CeilingDevices || !f.Records[0].Since.Equal(t0) {
		t.Fatalf("the file must still hold the original start: %s", raw)
	}
	if f.Records[0].Peak != 265 {
		t.Fatalf("peak = %d, want 265", f.Records[0].Peak)
	}

	// A brand-new tracker over the same file — the restart case.
	reborn := licence.NewOverageTracker(path, nil)
	got, ok := reborn.Since(entitlement.CeilingDevices)
	if !ok || !got.Equal(t0) {
		t.Fatalf("after a reload since = %s (ok=%v), want %s", got, ok, t0)
	}
}

// TestOverageStillClosesOnAMeasuredReturn is the other half, and the reason the
// fix is a distinction rather than "never forget": a ceiling that was COUNTED
// and is under its limit still ends its episode immediately.
func TestOverageStillClosesOnAMeasuredReturn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "licence-overage.json")
	st := overState(t, entitlement.TierTeam, 250)
	t0 := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	tr := licence.NewOverageTracker(path, nil)
	tr.Observe(st, licence.Usage{entitlement.CeilingDevices: 260}, t0)
	if _, ok := tr.Since(entitlement.CeilingDevices); !ok {
		t.Fatal("an open episode must have a since")
	}
	// MEASURED, and within limit.
	if got := tr.Observe(st, licence.Usage{entitlement.CeilingDevices: 249}, t0.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("back under the ceiling there is no overage: %+v", got)
	}
	if _, ok := tr.Since(entitlement.CeilingDevices); ok {
		t.Fatal("a measured return to within the ceiling closes the episode")
	}
	if recs := tr.Records(); len(recs) != 0 {
		t.Fatalf("a closed episode is forgotten, not archived: %+v", recs)
	}
}

// TestOverageSinceSeriesSurvivesAnUnmeasuredScrape is the metrics half. When a
// scrape cannot count a ceiling, `netops_licence_overage_since_seconds` must
// keep reporting the episode the register still holds. Emitting 0 would
// announce "the overage is over" on every timed-out read — the same false
// all-clear, one layer up.
func TestOverageSinceSeriesSurvivesAnUnmeasuredScrape(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	svc := licence.NewService(licence.NewStaticStore(overState(t, entitlement.TierTeam, 250)))
	svc.SetOverageTracker(licence.NewOverageTracker(filepath.Join(t.TempDir(), "o.json"), nil))

	var b bytes.Buffer
	svc.WriteUsageMetrics(&b, licence.Usage{entitlement.CeilingDevices: 262}, t0)
	want := `netops_licence_overage_since_seconds{ceiling="devices"} ` + strconv.FormatInt(t0.Unix(), 10)
	if !strings.Contains(b.String(), want) {
		t.Fatalf("the episode must open on the metrics path too:\n%s", b.String())
	}

	// The scrape that could not count devices.
	b.Reset()
	svc.WriteUsageMetrics(&b, licence.Usage{}, t0.Add(time.Hour))
	out := b.String()
	if strings.Contains(out, `netops_licence_usage{ceiling="devices"`) {
		t.Fatalf("an unmeasured ceiling has no usage series:\n%s", out)
	}
	if !strings.Contains(out, want) {
		t.Fatalf("overage_since must still name the live episode when the ceiling could not be counted; got:\n%s", out)
	}
}

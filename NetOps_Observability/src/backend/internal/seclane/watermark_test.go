// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package seclane

// watermark_test.go — the DETECTION WINDOW must be continuous.
//
// The window used to be [now-interval, now] recomputed on every pass, while the
// real spacing between passes is a jittered interval plus the scan's own
// duration. Every tick left a sliver unread; a skipped tick left a whole
// interval unread; a restart left the entire outage unread — and none of it was
// ever reported. These tests pin the two acceptable answers and nothing else:
// the next pass COVERS the gap, or it says the gap was NOT assessed.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/secapi"
)

// errSearchDown models the device-log source being unreachable.
var errSearchDown = errors.New("opensearch unreachable")

// windowDeps is the minimal valid Deps for constructing a lane directly (the
// New-refuses test needs a Deps, not a built lane).
func windowDeps(t *testing.T, store Watermarks) Deps {
	t.Helper()
	return Deps{
		Now:        func() time.Time { return fixedNow },
		Tenants:    func() []string { return []string{"acme"} },
		Devices:    func(string) []Device { return nil },
		RuleStates: func(context.Context, string) (map[string]bool, error) { return nil, nil },
		Publish:    func(context.Context, string, []Record) (int, error) { return 0, nil },
		Search:     func(string, string, any) (*http.Response, error) { return osResponse(), nil },
		CHQuery:    func(context.Context, string, string) ([]map[string]any, error) { return nil, nil },
		Seams:      func(context.Context, string) ([]SeamRow, error) { return nil, nil },
		Authz: func(http.ResponseWriter, *http.Request, secapi.Gate) (secapi.Principal, bool) {
			return secapi.Principal{}, false
		},
		WriteJSON:  func(http.ResponseWriter, int, any) {},
		WriteError: func(http.ResponseWriter, int, error) {},
		LogWarn:    func(string, map[string]any) {},
		LogError:   func(string, map[string]any) {},
		Scrub:      func(s string) string { return s },
		TenantSeg:  TenantSeg,
		Watermarks: store,
	}
}

// searchWindow is the [gte, lt) range clause the device-log reader sends.
type searchWindow struct {
	gte, lt time.Time
}

// windowsOf pulls the range clause out of every recorded OpenSearch body.
func windowOf(t *testing.T, body any) searchWindow {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal search body: %v", err)
	}
	var parsed struct {
		Query struct {
			Bool struct {
				Filter []struct {
					Range struct {
						Timestamp struct {
							GTE string `json:"gte"`
							LT  string `json:"lt"`
						} `json:"timestamp"`
					} `json:"range"`
				} `json:"filter"`
			} `json:"bool"`
		} `json:"query"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("decode search body: %v", err)
	}
	for _, f := range parsed.Query.Bool.Filter {
		if f.Range.Timestamp.GTE == "" {
			continue
		}
		gte, err := time.Parse(time.RFC3339, f.Range.Timestamp.GTE)
		if err != nil {
			t.Fatalf("gte %q: %v", f.Range.Timestamp.GTE, err)
		}
		lt, err := time.Parse(time.RFC3339, f.Range.Timestamp.LT)
		if err != nil {
			t.Fatalf("lt %q: %v", f.Range.Timestamp.LT, err)
		}
		return searchWindow{gte: gte.UTC(), lt: lt.UTC()}
	}
	t.Fatal("no timestamp range clause in the device-log search body")
	return searchWindow{}
}

// windowFixture is a lane with a MOVABLE clock that records every device-log
// window it asked for.
type windowFixture struct {
	*laneFixture
	now     time.Time
	windows []searchWindow
}

func newWindowFixture(t *testing.T, store Watermarks) *windowFixture {
	t.Helper()
	wf := &windowFixture{now: fixedNow}
	wf.laneFixture = newFixture(t, func(d *Deps) {
		d.Now = func() time.Time { return wf.now }
		d.Interval = time.Hour
		d.Watermarks = store
		d.Search = func(_, _ string, body any) (*http.Response, error) {
			wf.windows = append(wf.windows, windowOf(t, body))
			return osResponse(), nil
		}
	})
	wf.devices["acme"] = []Device{dev("acme-core", "acme")}
	return wf
}

func (wf *windowFixture) scan(at time.Time) {
	wf.now = at
	wf.lane.ScanTenant(context.Background(), "acme", "test")
}

func (wf *windowFixture) lastWindow(t *testing.T) searchWindow {
	t.Helper()
	if len(wf.windows) == 0 {
		t.Fatal("the lane read no device-log window at all")
	}
	return wf.windows[len(wf.windows)-1]
}

// unassessedDetections counts the honest non-verdicts the last pass emitted.
func unassessedDetections(fx *laneFixture) []sentRecord {
	var out []sentRecord
	for _, r := range fx.pub.sent {
		if strings.Contains(strings.ToLower(rawOf(r)), "detection-window-unassessed") {
			out = append(out, r)
		}
	}
	return out
}

func rawOf(r sentRecord) string {
	b, err := json.Marshal(r.Value)
	if err != nil {
		return ""
	}
	return string(b)
}

// TestDetectionWindowResumesFromTheLastPass is the whole contract.
func TestDetectionWindowResumesFromTheLastPass(t *testing.T) {
	t.Run("a skipped tick is covered by the next pass", func(t *testing.T) {
		dir := t.TempDir()
		wf := newWindowFixture(t, NewFileWatermarks(filepath.Join(dir, "marks.json")))
		wf.scan(fixedNow)
		first := wf.lastWindow(t)
		if !first.lt.Equal(fixedNow.UTC()) {
			t.Fatalf("first window ends at %s, want now (%s)", first.lt, fixedNow)
		}

		// Two ticks are missed: the next pass lands three hours later. The
		// window it reads must start where the last one stopped, not one
		// interval before now.
		wf.scan(fixedNow.Add(3 * time.Hour))
		got := wf.lastWindow(t)
		if !got.gte.Equal(fixedNow.UTC()) {
			t.Fatalf("second window starts at %s, want %s (the end of the first window); "+
				"a window recomputed as now-interval leaves the skipped ticks unread",
				got.gte, fixedNow.UTC())
		}
		if n := len(unassessedDetections(wf.laneFixture)); n != 0 {
			t.Fatalf("the gap was covered, so nothing should be reported unassessed; got %d", n)
		}
	})

	t.Run("an outage too long to re-read is reported UNASSESSED", func(t *testing.T) {
		dir := t.TempDir()
		wf := newWindowFixture(t, NewFileWatermarks(filepath.Join(dir, "marks.json")))
		wf.scan(fixedNow)

		// Ten hours later, with a one-hour interval, is far past the bounded
		// catch-up. The read is clamped — and the stretch it could not reach is
		// stated, not passed over.
		back := fixedNow.Add(10 * time.Hour)
		wf.scan(back)
		got := wf.lastWindow(t)
		floor := back.Add(-time.Hour * maxLookbackIntervals).UTC()
		if !got.gte.Equal(floor) {
			t.Fatalf("clamped window starts at %s, want the %d-interval floor %s", got.gte, maxLookbackIntervals, floor)
		}
		if len(unassessedDetections(wf.laneFixture)) == 0 {
			t.Fatal("the lane clamped the window and said nothing — a skipped stretch must produce an " +
				"UNASSESSED verdict, never silence")
		}
		logged := false
		for _, w := range wf.warns {
			if strings.Contains(w, "window gap") {
				logged = true
			}
		}
		if !logged {
			t.Fatalf("a detection gap must also reach the log (§10); warnings = %v", wf.warns)
		}
	})

	t.Run("a restart resumes from the persisted mark", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "marks.json")
		before := newWindowFixture(t, NewFileWatermarks(path))
		before.scan(fixedNow)

		// A brand-new lane over the same file is what a restart looks like.
		after := newWindowFixture(t, NewFileWatermarks(path))
		after.scan(fixedNow.Add(2 * time.Hour))
		got := after.lastWindow(t)
		if !got.gte.Equal(fixedNow.UTC()) {
			t.Fatalf("after a restart the window starts at %s, want %s — the outage across the "+
				"restart would otherwise be assessed by nothing", got.gte, fixedNow.UTC())
		}
	})

	t.Run("an unreadable mark store refuses to start the lane", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "marks.json")
		if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := New(windowDeps(t, NewFileWatermarks(path)))
		if err == nil {
			t.Fatal("New accepted an unreadable watermark store; starting empty would silently " +
				"discard every tenant's resume point")
		}
		if !strings.Contains(err.Error(), "watermark") {
			t.Fatalf("the refusal must name what could not be read, got %v", err)
		}
	})

	t.Run("an absent mark store is a first run, not a failure", func(t *testing.T) {
		dir := t.TempDir()
		w := NewFileWatermarks(filepath.Join(dir, "never-written.json"))
		marks, err := w.Load()
		if err != nil {
			t.Fatalf("an absent store is the first-run condition, not an error: %v", err)
		}
		if len(marks) != 0 {
			t.Fatalf("absent store returned %d marks", len(marks))
		}
	})

	t.Run("with no mark store the lane says the earlier window is unassessed", func(t *testing.T) {
		wf := newWindowFixture(t, nil)
		wf.scan(fixedNow)
		if len(unassessedDetections(wf.laneFixture)) == 0 {
			t.Fatal("a lane that cannot remember where the last pass stopped must say so, " +
				"not imply the interval before it was clean")
		}
	})

	t.Run("a failed read does not advance the mark", func(t *testing.T) {
		dir := t.TempDir()
		wf := newWindowFixture(t, NewFileWatermarks(filepath.Join(dir, "marks.json")))
		wf.lane.deps.Search = func(string, string, any) (*http.Response, error) {
			return nil, errSearchDown
		}
		wf.scan(fixedNow)
		// Restore the reader and scan again: the window must still start one
		// interval before the FIRST attempt, because nothing was ever read.
		wf.lane.deps.Search = func(_, _ string, body any) (*http.Response, error) {
			wf.windows = append(wf.windows, windowOf(t, body))
			return osResponse(), nil
		}
		wf.scan(fixedNow.Add(30 * time.Minute))
		got := wf.lastWindow(t)
		want := fixedNow.Add(-time.Hour).UTC()
		if !got.gte.Equal(want) {
			t.Fatalf("after a failed read the next window starts at %s, want %s — advancing the "+
				"mark on a failure steps over telemetry nobody looked at", got.gte, want)
		}
	})
}

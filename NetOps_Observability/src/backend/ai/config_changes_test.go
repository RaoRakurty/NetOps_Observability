// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// config_changes_test.go — get_recent_changes / get_config_diff (design item 10).
//
// What is pinned: the tools register only with a wired seam; arguments are
// validated before any seam call; a device the caller cannot see is not-found
// (never "no changes"); "no change recorded" is never worded as "nothing
// changed"; the seam's rows are ordered and capped by the tool itself; and a
// diff is labelled, redaction-noted and truncation-honest.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func changeDeps(changes []DeviceChange) (TroubleshootDeps, *ChangeQuery) {
	d := tsDeps()
	var seen ChangeQuery
	d.RecentChanges = func(_ context.Context, _ Principal, q ChangeQuery) (ChangeReport, error) {
		seen = q
		return ChangeReport{Changes: changes}, nil
	}
	d.ConfigDiff = func(_ context.Context, _ Principal, req ConfigDiffRequest) (ConfigDiffReport, error) {
		return ConfigDiffReport{
			DeviceID: req.DeviceID, DeviceName: "edge-1",
			FromSHA: "aaaaaaaaaaaaaaaa", ToSHA: "bbbbbbbbbbbbbbbb",
			FromLabel: "the capture before it", ToLabel: "latest capture",
			ToAt: time.Date(2026, 9, 21, 10, 12, 0, 0, time.UTC), Added: 1, Removed: 1,
			Unified: "- preferred_transport: AT&T\n+ preferred_transport: Comcast",
		}, nil
	}
	return d, &seen
}

func TestChangeToolsRegisterOnlyWhenWired(t *testing.T) {
	reg := tsRegistry(t, tsDeps())
	for _, name := range []string{"get_recent_changes", "get_config_diff"} {
		if _, ok := reg.Get(name); ok {
			t.Errorf("%s registered with a nil seam — it could only ever answer nothing", name)
		}
	}
	d, _ := changeDeps(nil)
	reg = tsRegistry(t, d)
	for _, name := range []string{"get_recent_changes", "get_config_diff"} {
		tool, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s must register with a wired seam", name)
		}
		if tool.Capability() != CapRead {
			t.Errorf("%s must be CapRead", name)
		}
	}
}

func TestRecentChangesWindowAndDeviceValidation(t *testing.T) {
	d, seen := changeDeps(nil)
	tool := bgpTool(t, d, "get_recent_changes")
	if _, err := tool.Run(context.Background(), tsPrincipal(), ToolArgs{"window": "1y"}); err == nil {
		t.Fatal("a window outside the closed vocabulary must be refused")
	}
	if _, err := tool.Run(context.Background(), tsPrincipal(), ToolArgs{"device": "leaf-2"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another tenant's device must be not-found, got %v", err)
	}
	if _, err := tool.Run(context.Background(), tsPrincipal(), ToolArgs{"device": "edge-1", "window": "24h"}); err != nil {
		t.Fatal(err)
	}
	if seen.DeviceID != "dev-a" || seen.SinceSeconds != 24*3600 || seen.Limit != MaxDeviceChangeVersions {
		t.Fatalf("seam got %+v — the device must be the RESOLVED id and the window the closed-vocabulary value", *seen)
	}
	if _, err := tool.Run(context.Background(), tsPrincipal(), ToolArgs{}); err != nil {
		t.Fatal(err)
	}
	if seen.DeviceID != "" || seen.SinceSeconds != 7*24*3600 || seen.Limit != MaxRecentChanges {
		t.Fatalf("estate read got %+v — want default 7d window and the estate cap", *seen)
	}
}

func TestRecentChangesNoRowsIsNotAHealthyAnswer(t *testing.T) {
	d, _ := changeDeps(nil)
	res, err := bgpTool(t, d, "get_recent_changes").Run(context.Background(), tsPrincipal(), ToolArgs{"device": "edge-1"})
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(res.Notes, " ")
	if len(res.Items) != 0 || !strings.Contains(notes, "RECORDED") || !strings.Contains(notes, "edge-1") {
		t.Fatalf("an empty history must say no change was RECORDED for that device: %+v", res)
	}
}

func TestRecentChangesNotWiredIsDisclosed(t *testing.T) {
	d, _ := changeDeps(nil)
	d.RecentChanges = func(context.Context, Principal, ChangeQuery) (ChangeReport, error) {
		return ChangeReport{NotWired: "configuration backup is not enabled"}, nil
	}
	res, err := bgpTool(t, d, "get_recent_changes").Run(context.Background(), tsPrincipal(), ToolArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 0 || !strings.Contains(strings.Join(res.Notes, " "), "not enabled") {
		t.Fatalf("an unwired source must be disclosed: %+v", res)
	}
}

func TestRecentChangesOrderedCappedAndCited(t *testing.T) {
	base := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	var rows []DeviceChange
	for i := 0; i < MaxRecentChanges+5; i++ {
		rows = append(rows, DeviceChange{
			DeviceID: "dev-a", DeviceName: "edge-1", State: "changed",
			SHA: strings.Repeat(string(rune('a'+i%6)), 16), ChangedAt: base.Add(time.Duration(i) * time.Minute),
		})
	}
	d, _ := changeDeps(rows)
	res, err := bgpTool(t, d, "get_recent_changes").Run(context.Background(), tsPrincipal(), ToolArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != MaxRecentChanges || !res.Truncated {
		t.Fatalf("want %d items and truncation, got %d truncated=%v", MaxRecentChanges, len(res.Items), res.Truncated)
	}
	newest := base.Add(time.Duration(MaxRecentChanges+4) * time.Minute).Format(time.RFC3339)
	if !strings.Contains(res.Items[0].Text, newest) {
		t.Fatalf("the newest change must come first; first row %q", res.Items[0].Text)
	}
	if !strings.HasPrefix(res.Items[0].CitationID, "config:dev-a:") {
		t.Fatalf("citation = %q", res.Items[0].CitationID)
	}
}

func TestChangeLineNeverCallsUncapturedUnchanged(t *testing.T) {
	never := changeLine(DeviceChange{DeviceName: "edge-1", State: "unknown"})
	if !strings.Contains(never, "never been captured") {
		t.Fatalf("got %q", never)
	}
	failed := changeLine(DeviceChange{DeviceName: "edge-1", State: "unknown", Error: "ssh timeout"})
	if !strings.Contains(failed, "last capture failed: ssh timeout") {
		t.Fatalf("got %q", failed)
	}
}

func TestConfigDiffValidation(t *testing.T) {
	d, _ := changeDeps(nil)
	tool := bgpTool(t, d, "get_config_diff")
	cases := []ToolArgs{
		{},                                     // device required
		{"device": "edge-1", "from": "HEAD~1"}, // not an anchor, not a version id
		{"device": "edge-1", "from": "latest", "to": "latest"},
		{"device": "edge-1", "to": "zzzzzzzz"},
	}
	for _, args := range cases {
		if _, err := tool.Run(context.Background(), tsPrincipal(), args); err == nil {
			t.Errorf("args %v must be refused before any seam call", args)
		}
	}
	if _, err := tool.Run(context.Background(), tsPrincipal(), ToolArgs{"device": "leaf-2"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another tenant's device must be not-found, got %v", err)
	}
}

func TestConfigDiffRendersLabelledRedactedDiff(t *testing.T) {
	d, _ := changeDeps(nil)
	res, err := bgpTool(t, d, "get_config_diff").Run(context.Background(), tsPrincipal(), ToolArgs{"device": "edge-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 2 {
		t.Fatalf("want a header and a diff item, got %+v", res.Items)
	}
	if !strings.Contains(res.Items[0].Text, "the capture before it vs latest capture: +1/-1") {
		t.Fatalf("header %q", res.Items[0].Text)
	}
	if !strings.Contains(res.Items[1].Text, "+ preferred_transport: Comcast") {
		t.Fatalf("diff body %q", res.Items[1].Text)
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "redacted") {
		t.Fatal("the answer must say values are redacted")
	}
}

func TestConfigDiffTruncatesAndSaysSo(t *testing.T) {
	d, _ := changeDeps(nil)
	d.ConfigDiff = func(_ context.Context, _ Principal, req ConfigDiffRequest) (ConfigDiffReport, error) {
		return ConfigDiffReport{DeviceID: req.DeviceID, FromSHA: "a1b2c3d4e5", ToSHA: "f6a7b8c9d0",
			Added: 900, Unified: strings.Repeat("+ line\n", 1000)}, nil
	}
	res, err := bgpTool(t, d, "get_config_diff").Run(context.Background(), tsPrincipal(), ToolArgs{"device": "edge-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || len(res.Items[1].Text) > MaxConfigDiffChars {
		t.Fatalf("diff must be clipped to %d chars and flagged", MaxConfigDiffChars)
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "truncated") {
		t.Fatal("truncation must be disclosed")
	}
}

func TestConfigDiffUnavailableIsAStateNotAnError(t *testing.T) {
	d, _ := changeDeps(nil)
	d.ConfigDiff = func(context.Context, Principal, ConfigDiffRequest) (ConfigDiffReport, error) {
		return ConfigDiffReport{Unavailable: "no golden baseline is marked for this device"}, nil
	}
	res, err := bgpTool(t, d, "get_config_diff").Run(context.Background(), tsPrincipal(), ToolArgs{"device": "edge-1", "from": "golden"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 0 || !strings.Contains(strings.Join(res.Notes, " "), "no golden baseline") {
		t.Fatalf("got %+v", res)
	}
}

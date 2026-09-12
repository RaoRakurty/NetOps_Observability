// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package parsercov

// mining_test.go — the miner's contract.
//
// DETERMINISM IS THE LOAD-BEARING PROPERTY. The propose route hands a
// template_id back to the client and must resolve it on a later run, so "same
// lines in, same ids and same order out" is not a nicety — it is the thing that
// makes the second half of the feature work at all. It is tested by running the
// same corpus twice and by running it through a fresh miner in a second
// process-independent order-sensitive pass.

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// corpus is a small, realistic mixed estate: two Cisco shapes on several
// interfaces and hosts, one Junos firewall shape, one shape that differs only
// in its verb (so it must NOT merge with its neighbour).
func corpus() []Line {
	return []Line{
		{Message: "%LINK-3-UPDOWN: Interface GigabitEthernet0/3, changed state to down", AppName: "%LINK-3-UPDOWN", Mnemonic: "UPDOWN", Host: "rtr-1", Severity: 3, Time: at("2026-08-27T04:11:00Z")},
		{Message: "%LINK-3-UPDOWN: Interface GigabitEthernet0/7, changed state to up", AppName: "%LINK-3-UPDOWN", Mnemonic: "UPDOWN", Host: "rtr-2", Severity: 3, Time: at("2026-08-28T04:11:00Z")},
		{Message: "%LINK-3-UPDOWN: Interface TenGigE0/0/0/1, changed state to down", AppName: "%LINK-3-UPDOWN", Mnemonic: "UPDOWN", Host: "rtr-1", Severity: 3, Time: at("2026-08-29T04:11:00Z")},
		{Message: "PFE_FW_SYSLOG_IP: FW: ge-0/0/1.0 A icmp 10.1.1.5 -> 10.9.9.9", AppName: "PFE", Mnemonic: "", Host: "srx-1", Severity: 5, Time: at("2026-09-01T22:02:00Z")},
		{Message: "PFE_FW_SYSLOG_IP: FW: ge-0/0/2.0 A icmp 10.1.1.9 -> 10.9.9.1", AppName: "PFE", Mnemonic: "", Host: "srx-2", Severity: 5, Time: at("2026-09-02T08:58:00Z")},
		{Message: "process bgpd terminated abnormally", AppName: "PFE", Mnemonic: "", Host: "srx-1", Severity: 2, Time: at("2026-09-02T09:00:00Z")},
	}
}

func mine(lines []Line, cfg MinerConfig) MineResult {
	m := NewMiner(cfg)
	for _, l := range lines {
		m.Add(l)
	}
	return m.Result()
}

func TestMiningIsDeterministic(t *testing.T) {
	a := mine(corpus(), MinerConfig{})
	b := mine(corpus(), MinerConfig{})
	if len(a.Items) != len(b.Items) {
		t.Fatalf("shape count differs: %d vs %d", len(a.Items), len(b.Items))
	}
	for i := range a.Items {
		if a.Items[i] != b.Items[i] {
			t.Fatalf("item %d differs across runs:\n  %+v\n  %+v", i, a.Items[i], b.Items[i])
		}
	}
	// And the ids are a function of CONTENT, not of position: mining only the
	// Junos subset must yield the same id for the shape it shares.
	sub := mine(corpus()[3:5], MinerConfig{})
	if len(sub.Items) != 1 {
		t.Fatalf("expected 1 shape from the Junos subset, got %d", len(sub.Items))
	}
	var found bool
	for _, it := range a.Items {
		if it.TemplateID == sub.Items[0].TemplateID {
			found = true
		}
	}
	if !found {
		t.Fatalf("template id %q from the subset run does not appear in the full run", sub.Items[0].TemplateID)
	}
}

func TestMiningGroupsVariantsAndSeparatesShapes(t *testing.T) {
	res := mine(corpus(), MinerConfig{})
	// The three %LINK lines are one shape; the two firewall lines are one; the
	// "process terminated" line is its own (different token count).
	if len(res.Items) != 3 {
		for _, it := range res.Items {
			t.Logf("shape: %q count=%d", it.Template, it.Count)
		}
		t.Fatalf("expected 3 shapes, got %d", len(res.Items))
	}
	top := res.Items[0]
	if top.Count != 3 {
		t.Fatalf("largest shape count = %d, want 3", top.Count)
	}
	// Ordering is count DESC.
	for i := 1; i < len(res.Items); i++ {
		if res.Items[i-1].Count < res.Items[i].Count {
			t.Fatalf("items are not sorted by count desc: %+v", res.Items)
		}
	}
	// The %FAC-N-MNEMONIC classifier survives; the instance details do not.
	if !strings.HasPrefix(top.Template, "%LINK-3-UPDOWN:") {
		t.Fatalf("classifier prefix lost: %q", top.Template)
	}
	if strings.Contains(top.Template, "GigabitEthernet0/3") || strings.Contains(top.Template, "TenGigE0/0/0/1") {
		t.Fatalf("interface name survived masking: %q", top.Template)
	}
	if !strings.Contains(top.Template, Wildcard) {
		t.Fatalf("expected a wildcard in %q", top.Template)
	}
	// "down"/"up"/"down" disagree at one position, so that position generalises
	// but the rest of the sentence does not.
	if !strings.Contains(top.Template, "changed state to") {
		t.Fatalf("shared text was over-generalised: %q", top.Template)
	}
	if top.Devices != 2 {
		t.Fatalf("distinct devices = %d, want 2", top.Devices)
	}
	if top.SeverityMax != 3 {
		t.Fatalf("severity_max = %d, want 3 (most severe of the group)", top.SeverityMax)
	}
	if top.FirstSeen != "2026-08-27T04:11:00Z" || top.LastSeen != "2026-08-29T04:11:00Z" {
		t.Fatalf("window = %s .. %s", top.FirstSeen, top.LastSeen)
	}
	if top.Sample != "%LINK-3-UPDOWN: Interface GigabitEthernet0/3, changed state to down" {
		t.Fatalf("sample is not the first raw line: %q", top.Sample)
	}
}

// TestSeverityMaxIsTheMostSevere pins the direction of the word "max": syslog
// severities count DOWN, so the most severe line in a group wins.
func TestSeverityMaxIsTheMostSevere(t *testing.T) {
	lines := []Line{
		{Message: "widget failed on port alpha", AppName: "APP", Host: "h1", Severity: 6, Time: at("2026-09-01T00:00:00Z")},
		{Message: "widget failed on port beta", AppName: "APP", Host: "h1", Severity: 2, Time: at("2026-09-01T00:01:00Z")},
	}
	res := mine(lines, MinerConfig{})
	if len(res.Items) != 1 {
		t.Fatalf("expected 1 shape, got %d", len(res.Items))
	}
	if res.Items[0].SeverityMax != 2 {
		t.Fatalf("severity_max = %d, want 2", res.Items[0].SeverityMax)
	}
}

func TestMaskTokenRules(t *testing.T) {
	keep := []string{
		"Interface", "changed", "state", "to", "down,", "%LINK-3-UPDOWN:",
		"%BGP-5-ADJCHANGE:", "FW:", "icmp", "->", "facade", "abnormally",
	}
	for _, tok := range keep {
		if got := maskToken(tok); got != tok {
			t.Errorf("maskToken(%q) = %q, want it kept verbatim", tok, got)
		}
	}
	mask := []string{
		// numbers, with and without units
		"42", "-1", "3.14", "1,024", "10ms", "55%", "0",
		// addresses
		"10.1.1.5", "10.1.1.5:443", "192.168.0.0/16", "fe80::1",
		"00:11:22:33:44:55", "0011.2233.4455",
		// interfaces
		"GigabitEthernet0/3", "ge-0/0/1.0", "Eth1/1", "Vlan10",
		"xe-0/0/0:1", "Port-channel12", "irb.100", "TenGigE0/0/0/1",
		// hex blobs (a bare blob needs a digit; "facade" above is a word)
		"0xdeadbeef", "deadbeef0", "0x0",
		// digit catch-all
		"pid=12345", "session-9f",
	}
	for _, tok := range mask {
		if got := maskToken(tok); got != Wildcard {
			t.Errorf("maskToken(%q) = %q, want %q", tok, got, Wildcard)
		}
	}
}

// TestSyslogTagIsNeverMasked is called out separately because it is the rule
// that keeps the mined template readable: %FAC-N-MNEMONIC is a CLASSIFIER, and
// masking it (it does contain a digit) would collapse every Cisco shape in the
// estate into one meaningless row.
func TestSyslogTagIsNeverMasked(t *testing.T) {
	for _, tok := range []string{"%LINK-3-UPDOWN:", "%OSPF-5-ADJCHG:", "%BGP-4-MAXPFX"} {
		if got := maskToken(tok); got != tok {
			t.Fatalf("maskToken(%q) = %q — the classifier must survive", tok, got)
		}
	}
}

func TestSimilarityThresholdBehaviour(t *testing.T) {
	// Four-token messages sharing the same bucket (same appname, mnemonic,
	// count and first token) but disagreeing on 2 of 4 positions → agreement
	// 0.5, exactly at the default threshold, so they MERGE.
	half := []Line{
		{Message: "alpha bravo charlie delta", AppName: "APP", Host: "h1", Time: at("2026-09-01T00:00:00Z")},
		{Message: "alpha bravo echo foxtrot", AppName: "APP", Host: "h1", Time: at("2026-09-01T00:01:00Z")},
	}
	if got := len(mine(half, MinerConfig{}).Items); got != 1 {
		t.Fatalf("at agreement 0.5 with threshold 0.5 the lines must merge, got %d shapes", got)
	}
	// Raise the bar above the agreement and they must split.
	if got := len(mine(half, MinerConfig{Similarity: 0.75}).Items); got != 2 {
		t.Fatalf("at agreement 0.5 with threshold 0.75 the lines must split, got %d shapes", got)
	}
	// Below the agreement, three-of-four disagreement still merges.
	quarter := []Line{
		{Message: "alpha bravo charlie delta", AppName: "APP", Host: "h1", Time: at("2026-09-01T00:00:00Z")},
		{Message: "alpha whisky xray yankee", AppName: "APP", Host: "h1", Time: at("2026-09-01T00:01:00Z")},
	}
	if got := len(mine(quarter, MinerConfig{}).Items); got != 2 {
		t.Fatalf("at agreement 0.25 with threshold 0.5 the lines must split, got %d shapes", got)
	}
	if got := len(mine(quarter, MinerConfig{Similarity: 0.2}).Items); got != 1 {
		t.Fatalf("at agreement 0.25 with threshold 0.2 the lines must merge, got %d shapes", got)
	}
}

// TestBucketKeySeparatesLanes: two lines whose masked tokens are IDENTICAL but
// whose appname/mnemonic differ must never share a template — the bucket is
// part of the identity, and merging them would attribute one vendor's shape to
// another.
func TestBucketKeySeparatesByAppAndMnemonic(t *testing.T) {
	lines := []Line{
		{Message: "link state changed", AppName: "A", Mnemonic: "X", Host: "h1", Time: at("2026-09-01T00:00:00Z")},
		{Message: "link state changed", AppName: "B", Mnemonic: "X", Host: "h1", Time: at("2026-09-01T00:01:00Z")},
		{Message: "link state changed", AppName: "A", Mnemonic: "Y", Host: "h1", Time: at("2026-09-01T00:02:00Z")},
	}
	res := mine(lines, MinerConfig{})
	if len(res.Items) != 3 {
		t.Fatalf("expected 3 shapes (one per app/mnemonic pair), got %d", len(res.Items))
	}
	seen := map[string]bool{}
	for _, it := range res.Items {
		if seen[it.TemplateID] {
			t.Fatalf("template ids collided across buckets: %q", it.TemplateID)
		}
		seen[it.TemplateID] = true
	}
}

func TestGroupCapIsEnforcedAndReported(t *testing.T) {
	var lines []Line
	for i := 0; i < 30; i++ {
		lines = append(lines, Line{
			// A distinct first token per line puts each in its own bucket, so
			// each one wants its own cluster.
			Message: fmt.Sprintf("word%c alpha bravo charlie", rune('a'+i%26)) + strings.Repeat(" x", i),
			AppName: fmt.Sprintf("APP%d", i),
			Host:    "h1",
			Time:    at("2026-09-01T00:00:00Z"),
		})
	}
	res := mine(lines, MinerConfig{MaxGroups: 5})
	if len(res.Items) != 5 {
		t.Fatalf("group cap not enforced: %d shapes", len(res.Items))
	}
	if !res.GroupsCapped {
		t.Fatal("group cap reached but GroupsCapped is false — a truncated answer must say so")
	}
	if res.LinesScanned != 30 {
		t.Fatalf("LinesScanned = %d, want 30 (capping stops grouping, not counting)", res.LinesScanned)
	}
}

func TestDeviceSetIsBounded(t *testing.T) {
	m := NewMiner(MinerConfig{})
	for i := 0; i < maxDevicesPerGroup+50; i++ {
		m.Add(Line{
			Message: "widget failed on port alpha",
			AppName: "APP",
			Host:    fmt.Sprintf("host-%d", i),
			Time:    at("2026-09-01T00:00:00Z"),
		})
	}
	res := m.Result()
	if len(res.Items) != 1 {
		t.Fatalf("expected 1 shape, got %d", len(res.Items))
	}
	if res.Items[0].Devices != maxDevicesPerGroup {
		t.Fatalf("device count = %d, want the cap %d", res.Items[0].Devices, maxDevicesPerGroup)
	}
	if !res.DevicesCapped {
		t.Fatal("device cap reached but DevicesCapped is false")
	}
}

func TestLongMessageTemplateIsBounded(t *testing.T) {
	long := strings.Repeat("alpha ", maxTemplateTokens*3)
	res := mine([]Line{{Message: long, AppName: "APP", Host: "h1", Time: at("2026-09-01T00:00:00Z")}}, MinerConfig{})
	got := len(strings.Fields(res.Items[0].Template))
	if got != maxTemplateTokens+1 {
		t.Fatalf("template token count = %d, want %d (cap + one trailing wildcard)", got, maxTemplateTokens+1)
	}
	if len(res.Items[0].Sample) > maxSampleBytes {
		t.Fatalf("sample is %d bytes, cap is %d", len(res.Items[0].Sample), maxSampleBytes)
	}
}

func TestBlankAndTimelessLinesAreHandledHonestly(t *testing.T) {
	res := mine([]Line{
		{Message: "   ", AppName: "APP", Host: "h1", Time: at("2026-09-01T00:00:00Z")},
		{Message: "widget failed", AppName: "APP", Host: "h1"}, // zero time
	}, MinerConfig{})
	if res.LinesScanned != 2 {
		t.Fatalf("LinesScanned = %d, want 2", res.LinesScanned)
	}
	if len(res.Items) != 1 {
		t.Fatalf("expected the blank line to produce no shape, got %d", len(res.Items))
	}
	if res.Items[0].FirstSeen != "" || res.Items[0].LastSeen != "" {
		t.Fatalf("a line with no usable timestamp must not invent one: %q .. %q",
			res.Items[0].FirstSeen, res.Items[0].LastSeen)
	}
}

func TestValidTemplateID(t *testing.T) {
	good := TemplateID("APP", "MN", "some <*> template")
	if !ValidTemplateID(good) {
		t.Fatalf("TemplateID produced %q, which its own validator rejects", good)
	}
	if !ValidTemplateID("t-0123456789") {
		t.Fatal(`ValidTemplateID("t-0123456789") = false, want true`)
	}
	// The id reaches a map lookup and a path segment, so the validator refuses
	// anything that is not exactly `t-` + 10 lower-case hex digits — wrong
	// length, wrong prefix, upper-case hex, traversal and whitespace alike.
	for _, bad := range []string{
		"", "t-", "t-0123456789a", "x-0123456789", "T-0123456789",
		"t-0123456ABC", "t-../../etc", "t-0123456 89", "t-01234-6789",
		"../t-0123456789",
	} {
		if ValidTemplateID(bad) {
			t.Errorf("ValidTemplateID(%q) = true, want false", bad)
		}
	}
}

func TestSeverityResolutionMirrorsTheEngine(t *testing.T) {
	cases := []struct {
		keyword, app string
		want         int
	}{
		{"warning", "", 4},
		{"warn", "", 4},
		{"emerg", "", 0},
		{"", "%LINK-3-UPDOWN", 3},
		// the tag digit wins when it is more severe than the keyword
		{"notice", "%LINK-3-UPDOWN", 3},
		// and the keyword wins when IT is more severe
		{"critical", "%LINK-5-UPDOWN", 2},
		{"", "", severityNone},
		{"nonsense", "not-a-tag", severityNone},
	}
	for _, c := range cases {
		if got := mostSevere(c.keyword, c.app); got != c.want {
			t.Errorf("mostSevere(%q, %q) = %d, want %d", c.keyword, c.app, got, c.want)
		}
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package sitecollect

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func fixed() time.Time { return time.Unix(1800000000, 0) }

func render(p *Publisher) string {
	var b strings.Builder
	p.WriteMetrics(&b)
	return b.String()
}

func TestRefreshPublishesOneSeriesPerSitedDevice(t *testing.T) {
	p := New(func(context.Context) ([]Membership, error) {
		return []Membership{
			{Device: "cedge-40-fdf7b64f", Tenant: "T_A", Site: "t_a/vmanage/40", SiteLabel: "Site 40 · from vManage"},
			{Device: "vedge-51-79fbba30", Tenant: "t_a", Site: "t_a/vmanage/50", SiteLabel: "Site 50 · from vManage"},
			{Device: "vedge-52-bf77ee2c", Tenant: "t_a", Site: "t_a/vmanage/50", SiteLabel: "Site 50 · from vManage"},
			{Device: "loose-1", Tenant: "t_a", Site: ""},            // no site: not counted anywhere
			{Device: "vedge-51-79fbba30", Tenant: "t_b", Site: "x"}, // duplicate id: first wins
		}, nil
	}, fixed)
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	out := render(p)
	for _, want := range []string{
		`netops_device_site_refresh_ok 1`,
		`netops_device_site_refresh_timestamp_seconds 1800000000`,
		`netops_device_site_info{device="cedge-40-fdf7b64f",tenant_id="t_a",site="t_a/vmanage/40",site_label="Site 40 · from vManage"} 1`,
		`netops_device_site_info{device="vedge-52-bf77ee2c",tenant_id="t_a",site="t_a/vmanage/50",site_label="Site 50 · from vManage"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "loose-1") {
		t.Error("a device with no site must not be published")
	}
	if n := strings.Count(out, `device="vedge-51-79fbba30"`); n != 1 {
		t.Errorf("one series per device, got %d", n)
	}
	if strings.Contains(out, `tenant_id="t_b"`) {
		t.Error("the duplicate id must not create a second owner")
	}
}

// §3a: an alert's (tenant_id, site) labels are believed only when the api
// itself published that pair — never another tenant's site, never a guess.
func TestOwnsOnlyPublishedPairs(t *testing.T) {
	p := New(func(context.Context) ([]Membership, error) {
		return []Membership{{Device: "d1", Tenant: "t_a", Site: "t_a/vmanage/50"}}, nil
	}, fixed)
	if p.Owns("t_a", "t_a/vmanage/50") {
		t.Fatal("nothing is owned before the first refresh")
	}
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		tenant, site string
		want         bool
	}{
		{"t_a", "t_a/vmanage/50", true},
		{" T_A ", "t_a/vmanage/50", true},
		{"t_b", "t_a/vmanage/50", false}, // another tenant naming t_a's site
		{"t_a", "t_a/vmanage/60", false}, // a site t_a does not have
		{"", "t_a/vmanage/50", false},
		{"t_a", "", false},
	}
	for _, c := range cases {
		if got := p.Owns(c.tenant, c.site); got != c.want {
			t.Errorf("Owns(%q,%q) = %v, want %v", c.tenant, c.site, got, c.want)
		}
	}
	var nilP *Publisher
	if nilP.Owns("t_a", "t_a/vmanage/50") {
		t.Error("a nil publisher owns nothing")
	}
}

// A failed resolution keeps the previous snapshot (a transient error must not
// make every site vanish and resolve its alert) and says so on refresh_ok.
func TestFailedRefreshKeepsTheLastSnapshotAndSaysSo(t *testing.T) {
	fail := false
	p := New(func(context.Context) ([]Membership, error) {
		if fail {
			return nil, errors.New("site store unavailable")
		}
		return []Membership{{Device: "d1", Tenant: "t_a", Site: "s1"}}, nil
	}, fixed)
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail = true
	err := p.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), "site store unavailable") {
		t.Fatalf("the cause must surface, got %v", err)
	}
	out := render(p)
	if !strings.Contains(out, "netops_device_site_refresh_ok 0") {
		t.Errorf("refresh_ok must read 0 after a failure:\n%s", out)
	}
	if !strings.Contains(out, `device="d1"`) || !p.Owns("t_a", "s1") {
		t.Error("the previous snapshot must survive a failed refresh")
	}
}

func TestRefreshGaugesExistBeforeTheFirstRefresh(t *testing.T) {
	out := render(New(func(context.Context) ([]Membership, error) { return nil, nil }, fixed))
	if !strings.Contains(out, "netops_device_site_refresh_ok 0") ||
		!strings.Contains(out, "netops_device_site_refresh_timestamp_seconds 0") {
		t.Errorf("the refresh gauges must be written on every scrape:\n%s", out)
	}
}

// Site labels are operator- or controller-supplied text: they are escaped the
// way the Prometheus text format defines, so a quote cannot break the scrape.
func TestLabelValuesAreEscaped(t *testing.T) {
	p := New(func(context.Context) ([]Membership, error) {
		return []Membership{{Device: "d1", Tenant: "t", Site: `a"b`, SiteLabel: "line\\one\ntwo"}}, nil
	}, fixed)
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := `netops_device_site_info{device="d1",tenant_id="t",site="a\"b",site_label="line\\one\ntwo"} 1`
	if out := render(p); !strings.Contains(out, want) {
		t.Errorf("want %s in:\n%s", want, out)
	}
}

func TestRunReportsEveryFailureAndStopsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 4)
	p := New(func(context.Context) ([]Membership, error) { return nil, errors.New("boom") }, fixed)
	done := make(chan struct{})
	go func() { p.Run(ctx, 10*time.Millisecond, func(e error) { errs <- e }); close(done) }()
	select {
	case e := <-errs:
		if !strings.Contains(e.Error(), "boom") {
			t.Fatalf("unexpected error %v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a failing refresh was not reported")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop with its context")
	}
}

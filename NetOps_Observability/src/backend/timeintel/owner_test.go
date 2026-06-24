package timeintel

import "testing"

func TestClassifyOwnerDomain(t *testing.T) {
	cases := []struct {
		owner    string
		group    map[string]string
		want     OwnerDomain
		internal bool
	}{
		{"isp", nil, DomainISP, false},
		{"carrier", nil, DomainISP, false},
		{"sdwan_vendor", nil, DomainSDWAN, false},
		{"cloud_provider", nil, DomainCloud, false},
		{"app_team", nil, DomainApp, false},
		{"netops", nil, DomainLAN, false},
		{"", nil, DomainUnknown, false},
		{"platform", nil, DomainInternal, true},
		// unambiguous platform-service objects are self-monitoring — WINS over owner
		{"isp", map[string]string{"app_path": "api->clickhouse"}, DomainInternal, true},
		{"netops", map[string]string{"device": "netbox"}, DomainInternal, true},
		{"cloud_provider", map[string]string{"app_path": "prober->netbox"}, DomainInternal, true},
		// real fabric (no platform token) keeps its engine owner
		{"isp", map[string]string{"device": "spine1"}, DomainISP, false},
		{"netops", map[string]string{"device": "spine1"}, DomainLAN, false},
		{"cloud_provider", map[string]string{"device": "wan-r2"}, DomainCloud, false},
	}
	for _, c := range cases {
		got, internal := ClassifyOwnerDomain(c.owner, c.group)
		if got != c.want || internal != c.internal {
			t.Errorf("Classify(%q,%v) = (%s,%v), want (%s,%v)", c.owner, c.group, got, internal, c.want, c.internal)
		}
	}
}

func TestRollupByDomain(t *testing.T) {
	mk := func(dom OwnerDomain, tti int64, driver TimeLossDriver) IncidentSummary {
		return IncidentSummary{
			OwnerDomain: dom, Durations: map[MetricName]int64{MetricTTI: tti},
			TimeLossDriver: driver, Group: map[string]string{"device": "d"}, OccurredAt: day(1),
		}
	}
	stats := RollupByDomain([]IncidentSummary{
		mk(DomainISP, 1000, DriverProviderRepair),
		mk(DomainISP, 3000, DriverProviderRepair),
		mk(DomainLAN, 500, DriverDetection),
	})
	// ISP first (stable order), 2 incidents, p90 tti = 3000, top delay provider_repair
	if len(stats) != 2 || stats[0].Domain != DomainISP {
		t.Fatalf("want ISP first, got %+v", stats)
	}
	if stats[0].IncidentCount != 2 || stats[0].MTTIp90ms != 3000 || stats[0].TopDelay != DriverProviderRepair {
		t.Fatalf("ISP stat wrong: %+v", stats[0])
	}
	if stats[1].Domain != DomainLAN || stats[1].IncidentCount != 1 {
		t.Fatalf("LAN stat wrong: %+v", stats[1])
	}
}

func TestRollupByDomainRecoveryHonestZero(t *testing.T) {
	// No recovery durations → Recovery p90 stays 0 (no fabrication).
	stats := RollupByDomain([]IncidentSummary{{
		OwnerDomain: DomainISP, Durations: map[MetricName]int64{MetricTTI: 1000},
		Group: map[string]string{"device": "d"}, OccurredAt: day(1),
	}})
	if stats[0].RecoveryP90ms != 0 {
		t.Fatalf("recovery must be 0 without evidence, got %d", stats[0].RecoveryP90ms)
	}
}

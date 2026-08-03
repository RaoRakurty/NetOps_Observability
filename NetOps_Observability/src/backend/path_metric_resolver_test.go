package backend

import "testing"

// The 5-tier taxonomy maps every source to the right rank, and — the key change —
// agent probes (Tier 2) now outrank STAMP (Tier 3), and app synthetics (Tier 1)
// outrank both.
func TestPathSourceTiers(t *testing.T) {
	cases := []struct {
		src  PathSource
		tier MeasurementTier
	}{
		{SrcHTTPSynthetic, Tier1AppExperience},
		{SrcDNSSynthetic, Tier1AppExperience},
		{SrcTLSHandshake, Tier1AppExperience},
		{SrcEcho, Tier2AgentActive},
		{SrcSynthetic, Tier2AgentActive},
		{SrcSyntheticTCP, Tier2AgentActive},
		{SrcTraceroute, Tier2AgentActive},
		{SrcSTAMP, Tier3DeviceNative},
		{SrcIPSLA, Tier3DeviceNative},
		{SrcTWAMP, Tier3DeviceNative},
		{SrcInterface, Tier4Passive},
		{SrcTunnel, Tier4Passive},
		{SrcRouting, Tier4Passive},
		{SrcFlow, Tier5FlowDerived},
		{SrcNone, TierUnknown},
	}
	for _, c := range cases {
		if got := c.src.Tier(); got != c.tier {
			t.Errorf("%q.Tier() = %d, want %d", c.src, got, c.tier)
		}
		if c.src.Label() == "" {
			t.Errorf("%q has no customer-facing label", c.src)
		}
	}
	if !(SrcHTTPSynthetic.Tier() < SrcEcho.Tier() && SrcEcho.Tier() < SrcSTAMP.Tier()) {
		t.Error("expected app-experience < agent-active < device-native (HTTP < echo < STAMP)")
	}
}

func TestResolvedMetricHeadlineSource(t *testing.T) {
	m := &ResolvedPathMetric{LatencySource: SrcEcho, LossSource: SrcSTAMP}
	if m.Source() != SrcEcho || m.Source().Tier() != Tier2AgentActive {
		t.Errorf("headline should be latency's source (echo/Tier2), got %s/%d", m.Source(), m.Source().Tier())
	}
	m2 := &ResolvedPathMetric{AvailabilitySource: SrcHTTPSynthetic, LossSource: SrcTraceroute}
	if m2.Source() != SrcHTTPSynthetic {
		t.Errorf("no latency -> availability headline, got %s", m2.Source())
	}
	m3 := &ResolvedPathMetric{LossSource: SrcSTAMP}
	if m3.Source() != SrcSTAMP {
		t.Errorf("total-loss path -> loss headline, got %s", m3.Source())
	}
}

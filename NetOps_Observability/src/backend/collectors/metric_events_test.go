package collectors

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// The RCA allowlist is the bus filter: in-list families build an event; anything
// else (e.g. the broadcast/multicast/unicast packet counters) is dropped from
// the bus and stays in VictoriaMetrics only.
func TestBuildMetricEvent_FilterAllowlist(t *testing.T) {
	forwarded := []string{
		"device_if_in_octets", "device_if_out_octets",
		"device_if_oper_status", "device_if_admin_status",
		"device_if_in_errors", "device_if_out_errors",
		"device_if_in_discards", "device_if_out_discards", "device_if_speed",
		"device_bgp_peer_state", "device_bgp_fsm_transitions",
		"device_cpu_percent", "device_mem_percent", "device_temp_celsius",
	}
	for _, name := range forwarded {
		if _, ok := buildMetricEvent(name, "leaf1", "arista", "1", "Ethernet1", 5, 1_700_000_000_000); !ok {
			t.Errorf("RCA family %q should be forwarded to the bus", name)
		}
	}
	dropped := []string{
		"device_if_in_ucast_pkts", "device_if_out_mcast_pkts",
		"device_if_in_bcast_pkts", "device_sysuptime",
		"device_disk_used_mb", "collector_up", "gnmi_anything",
	}
	for _, name := range dropped {
		if _, ok := buildMetricEvent(name, "leaf1", "arista", "1", "Ethernet1", 5, 1_700_000_000_000); ok {
			t.Errorf("non-RCA metric %q must NOT reach the bus", name)
		}
	}
}

// Interface families carry ifName + index; the provenance stamp is constant.
func TestBuildMetricEvent_InterfaceIdentity(t *testing.T) {
	ev, ok := buildMetricEvent("device_if_in_octets", "spine1", "nokia", "12", "ethernet-1/1", 42, 1_700_000_000_000)
	if !ok {
		t.Fatal("expected interface event")
	}
	if ev.ObserverType != "device" || ev.ModalityClass != "device_telemetry" || ev.CollectionPath != "snmp_poll" {
		t.Errorf("bad provenance stamp: %+v", ev)
	}
	if ev.SignalFamily != "interface" || ev.IfName != "ethernet-1/1" || ev.Index != "12" {
		t.Errorf("bad interface identity: %+v", ev)
	}
	if ev.Peer != "" {
		t.Errorf("interface event must not carry a peer: %q", ev.Peer)
	}
	if ev.Value != 42 || ev.Unit != "bytes" || ev.Metric != "device_if_in_octets" {
		t.Errorf("bad signal fields: %+v", ev)
	}
	if ev.TS == "" {
		t.Error("event must carry an event-time stamp")
	}
}

// BGP families map the table index to the remote peer identity (BGP4-MIB).
func TestBuildMetricEvent_BGPPeerIdentity(t *testing.T) {
	ev, ok := buildMetricEvent("device_bgp_peer_state", "leaf2", "arista", "10.0.0.5", "", 6, 1_700_000_000_000)
	if !ok {
		t.Fatal("expected bgp event")
	}
	if ev.SignalFamily != "bgp" || ev.Peer != "10.0.0.5" {
		t.Errorf("bgp index should map to peer identity: %+v", ev)
	}
	if ev.IfName != "" {
		t.Errorf("bgp event must not carry an ifName: %q", ev.IfName)
	}
}

// Resource scalars (cpu/mem/temp) carry no interface/peer identity.
func TestBuildMetricEvent_ResourceScalar(t *testing.T) {
	ev, ok := buildMetricEvent("device_cpu_percent", "wan-r2", "arista", "", "", 17, 1_700_000_000_000)
	if !ok {
		t.Fatal("expected resource event")
	}
	if ev.SignalFamily != "device_resource" || ev.Unit != "percent" {
		t.Errorf("bad resource event: %+v", ev)
	}
	if ev.IfName != "" || ev.Peer != "" {
		t.Errorf("resource scalar must not carry interface/peer identity: %+v", ev)
	}
}

// The wire format is NDJSON (one JSON object per line) so the Vector
// http_server source (codec json + newline_delimited framing) emits one event
// per sample rather than a single array event.
func TestEncodeMetricNDJSON_OneObjectPerLine(t *testing.T) {
	evs := []MetricEvent{}
	for _, m := range []string{"device_if_in_octets", "device_bgp_peer_state", "device_cpu_percent"} {
		ev, _ := buildMetricEvent(m, "leaf1", "arista", "1", "Ethernet1", 3, 1_700_000_000_000)
		evs = append(evs, ev)
	}
	body, err := encodeMetricNDJSON(evs)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	sc := bufio.NewScanner(bytes.NewReader(body))
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var got MetricEvent
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("line %d not valid JSON: %v", n, err)
		}
		if got.Metric == "" || got.Device != "leaf1" {
			t.Errorf("line %d missing canonical fields: %s", n, line)
		}
		n++
	}
	if n != 3 {
		t.Errorf("expected 3 NDJSON lines, got %d", n)
	}
}

// METRIC_EVENT_SINK_URL=off disables the bus lane without touching the VM path.
func TestMetricEventSink_Disable(t *testing.T) {
	t.Setenv("METRIC_EVENT_SINK_URL", "off")
	if metricEventSink() != "" {
		t.Error("METRIC_EVENT_SINK_URL=off should disable the bus lane")
	}
	t.Setenv("METRIC_EVENT_SINK_URL", "")
	if metricEventSink() != "http://vector-aggregator:8690/" {
		t.Errorf("default sink wrong: %q", metricEventSink())
	}
}

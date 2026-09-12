// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"strings"
	"testing"
)

// Sample UniFi /stat/device response (trimmed to the fields we normalize): one
// AP (uap) and one switch (usw).
const unifiSample = `{"data":[
  {"name":"AP-Lobby","model":"U6-Pro","type":"uap","state":1,"num_sta":37,"uptime":864000,"satisfaction":94,"system-stats":{"cpu":"6.2","mem":"41.0"}},
  {"name":"SW-Core","model":"USW-Pro-48","type":"usw","state":1,"num_sta":210,"uptime":1728000,"satisfaction":99,"system-stats":{"cpu":"12.5","mem":"55.3"}},
  {"name":"","model":"ghost","type":"uap","state":0,"num_sta":0}
]}`

func TestNormalizeUniFiDevices(t *testing.T) {
	lines, err := normalizeUniFiDevices([]byte(unifiSample), 1700000000000)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	j := strings.Join(lines, "\n")
	// AP client count + satisfaction + cpu/mem.
	if !strings.Contains(j, `device_unifi_clients{device="AP-Lobby",model="U6-Pro",type="uap"} 37`) {
		t.Errorf("AP client count missing:\n%s", j)
	}
	if !strings.Contains(j, `device_unifi_satisfaction_pct{device="AP-Lobby",model="U6-Pro",type="uap"} 94`) {
		t.Errorf("AP satisfaction missing:\n%s", j)
	}
	if !strings.Contains(j, `device_unifi_cpu_pct{device="AP-Lobby",model="U6-Pro",type="uap"} 6.2`) {
		t.Errorf("AP cpu missing:\n%s", j)
	}
	// Switch present too.
	if !strings.Contains(j, `device_unifi_clients{device="SW-Core",model="USW-Pro-48",type="usw"} 210`) {
		t.Errorf("switch client count missing:\n%s", j)
	}
	// The nameless device is skipped (no stable label).
	if strings.Contains(j, `device=""`) {
		t.Errorf("nameless device must be skipped:\n%s", j)
	}
	// Cardinality law: no MAC/serial labels.
	if strings.Contains(j, "mac") || strings.Contains(j, "serial") {
		t.Errorf("UniFi series must not carry identity labels:\n%s", j)
	}
}

func TestNormalizeUniFiEmptyAndBad(t *testing.T) {
	if lines, err := normalizeUniFiDevices([]byte(`{"data":[]}`), 1); err != nil || len(lines) != 0 {
		t.Fatalf("empty data → no lines, no error: %v %v", lines, err)
	}
	if _, err := normalizeUniFiDevices([]byte(`not json`), 1); err == nil {
		t.Fatal("bad JSON must error")
	}
}

func TestUnifiConfigGate(t *testing.T) {
	t.Setenv("FEATURE_UNIFI", "")
	if _, ok := unifiConfigFromEnv(); ok {
		t.Fatal("disabled without FEATURE_UNIFI")
	}
	t.Setenv("FEATURE_UNIFI", "true")
	t.Setenv("UNIFI_URL", "")
	if _, ok := unifiConfigFromEnv(); ok {
		t.Fatal("disabled without a URL")
	}
	t.Setenv("UNIFI_URL", "https://unifi.local:8443")
	t.Setenv("UNIFI_USER", "ro")
	t.Setenv("UNIFI_PASSWORD", "secret")
	c, ok := unifiConfigFromEnv()
	if !ok || c.Site != "default" {
		t.Fatalf("enabled with url+creds, default site: %+v ok=%v", c, ok)
	}
}

func TestParseNum(t *testing.T) {
	if parseNum("6.2") != 6.2 || parseNum("") != -1 || parseNum("nan-ish!") == 6.2 {
		t.Fatal("parseNum wrong")
	}
}

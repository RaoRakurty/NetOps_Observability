// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flownames

import (
	"encoding/json"
	"strings"
	"testing"

	"netops/backend/internal/iana"
)

// The platform's addresses come from configuration, and only parsed values
// reach SQL: a malformed or hostile entry is dropped, never interpolated.
func TestParsePlatformAddrs(t *testing.T) {
	p := ParsePlatformAddrs(" 10.70.245.122 , 10.99.0.0/16, bogus, 1.2.3.4') OR 1=1 --",
		"prober=10.70.245.123,lan-vantage-1:172.40.40.200,v6=2001:db8::1")
	if strings.Join(p.ips, ",") != "10.70.245.122,10.70.245.123,172.40.40.200,2001:db8::1" {
		t.Errorf("ips = %v", p.ips)
	}
	if len(p.nets) != 1 || p.nets[0].String() != "10.99.0.0/16" {
		t.Errorf("nets = %v", p.nets)
	}
	cond := p.SQLCond()
	if strings.Contains(cond, "bogus") || strings.Contains(cond, "1=1") {
		t.Fatalf("configuration text reached SQL: %s", cond)
	}
	for _, want := range []string{"src_addr IN ('10.70.245.122'", "dst_addr IN (", "isIPAddressInRange(src_addr, '10.99.0.0/16')"} {
		if !strings.Contains(cond, want) {
			t.Errorf("cond missing %q: %s", want, cond)
		}
	}
	if !p.Contains("10.99.4.5") || !p.Contains("10.70.245.122") || p.Contains("10.70.245.124") {
		t.Error("contains() disagrees with the configured set")
	}
	if !ParsePlatformAddrs("", "").Empty() || ParsePlatformAddrs("", "").SQLCond() != "" {
		t.Error("unconfigured must classify nothing")
	}
}

// The Logs page labels a platform-monitoring flow and deletes nothing.
func TestLogsFlowDocsLabelPlatformMonitoring(t *testing.T) {
	resp := map[string]any{}
	if err := json.Unmarshal([]byte(`{"hits":{"hits":[
	  {"_source":{"src_addr":"10.70.245.122","dst_addr":"10.70.245.104","proto":17,"src_port":50000,"dst_port":161}},
	  {"_source":{"src_addr":"192.0.2.1","dst_addr":"192.0.2.2","proto":6,"src_port":50000,"dst_port":443}}
	]}}`), &resp); err != nil {
		t.Fatal(err)
	}
	AnnotateHits(resp, nil, iana.Default(), ParsePlatformAddrs("10.70.245.122", ""))
	hits := resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 {
		t.Fatalf("a document was dropped: %d", len(hits))
	}
	r0 := hits[0].(map[string]any)["_resolved"].(map[string]any)
	r1 := hits[1].(map[string]any)["_resolved"].(map[string]any)
	if r0["traffic_class"] != TrafficClassPlatform {
		t.Errorf("our own poll not labelled: %v", r0)
	}
	if _, ok := r1["traffic_class"]; ok {
		t.Errorf("customer traffic labelled platform: %v", r1)
	}
}

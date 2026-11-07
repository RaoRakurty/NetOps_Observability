// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// tracker 367: the region topology view never shows a credential carried as
// URL userinfo — neither the local stack's env URLs nor a per-region override.
func TestDisplayDataPlaneNeverShowsUserinfo(t *testing.T) {
	t.Setenv("VICTORIA_URL", "https://svc-api:Sup3rS3cretPw@vmauth:8427")
	t.Setenv("OPENSEARCH_URL", "https://svc_api:Sup3rS3cretPw@opensearch:9200")
	t.Setenv("REGION_DATAPLANE_EU_WEST", "ch=https://u:Sup3rS3cretPw@ch-eu:8443;vm=https://v:Sup3rS3cretPw@vm-eu:8427")
	for _, region := range []string{"us-east", "eu-west"} {
		raw, err := json.Marshal(displayDataPlane(dataPlaneFor(region)))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "Sup3rS3cretPw") {
			t.Fatalf("%s: credential shown: %s", region, raw)
		}
	}
	local := displayDataPlane(dataPlaneFor("us-east"))
	if local.VictoriaMetrics != "https://vmauth:8427" {
		t.Errorf("host/port must survive: %q", local.VictoriaMetrics)
	}
	// The resolver itself is untouched — its value stays usable for a connection.
	if dp := dataPlaneFor("us-east"); !strings.Contains(dp.VictoriaMetrics, "@vmauth") {
		t.Errorf("resolver must not strip: %q", dp.VictoriaMetrics)
	}
}

// tracker 367: a malformed METRICS_URL must not echo itself (userinfo
// included) to a tenant caller of the metrics proxy.
func TestProxyMetricsBadURLErrorIsGeneric(t *testing.T) {
	t.Setenv("METRICS_URL", "http://svc-api:Sup3rS3cretPw@bad host:8427")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/metrics/query?query=up", nil)
	(&server{}).proxyMetrics(rec, req, "/api/v1/query", "query")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, "Sup3rS3cretPw") || strings.Contains(body, "svc-api") {
		t.Fatalf("credential echoed to the caller: %s", body)
	}
}

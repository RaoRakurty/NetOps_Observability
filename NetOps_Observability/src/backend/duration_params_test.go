// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// duration_params_test.go — tracker 428: the three non-flow routes that read a
// relative window through durationQuery answer 400 for a malformed,
// non-positive or over-30-day value and send nothing to ClickHouse; they used
// to substitute their default behind a 200.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDurationParamsFailClosed(t *testing.T) {
	sqls, _ := corrFakeCH(t)
	s := corrTestServer(t)
	bad := []string{"45d", "721h", "bogus", "0s", "-1h", "604800"}
	routes := []struct {
		path, key string
		h         http.HandlerFunc
		claims    jwtClaims
	}{
		{"/api/events/feed", "from", s.handleEventsFeed, acme()},
		{"/api/correlations/undetermined-frequency", "since", s.handleUndeterminedFrequency, acme()},
		{"/api/ai/feedback", "since", s.handleAIFeedbackStats, superA()},
	}
	for _, rt := range routes {
		for _, v := range bad {
			before := len(*sqls)
			w := httptest.NewRecorder()
			rt.h(w, req(http.MethodGet, rt.path+"?"+rt.key+"="+v, "", rt.claims))
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s?%s=%s: status %d, want 400 (body %s)", rt.path, rt.key, v, w.Code, w.Body.String())
			}
			if len(*sqls) != before {
				t.Errorf("%s?%s=%s: sent %d statements; want none", rt.path, rt.key, v, len(*sqls)-before)
			}
		}
	}
	// A good window is still answered.
	for _, path := range []string{"/api/events/feed?from=24h", "/api/correlations/undetermined-frequency?since=168h"} {
		w := httptest.NewRecorder()
		h := s.handleEventsFeed
		if path != "/api/events/feed?from=24h" {
			h = s.handleUndeterminedFrequency
		}
		h(w, req(http.MethodGet, path, "", acme()))
		if w.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200 (body %s)", path, w.Code, w.Body.String())
		}
	}
}

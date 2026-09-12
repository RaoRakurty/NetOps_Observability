// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package quarantine

// metrics_test.go — F-11 D6: the depth/age sampler and restore counters.
// The load-bearing rules: refresh at most every 60s (lazily, on render), and
// on an OpenSearch error the gauges are ABSENT — "a zero is a lie"
// (internal/secobs/metrics.go): an absent series is a visible failure, a zero
// reads as an empty quarantine.

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func cannedResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

// t0 is an arbitrary fixed render time; the sampler works off the injected
// clock only.
var t0 = time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)

// oldestMillis is one hour before t0, as OpenSearch reports epoch-millis min
// aggregations.
var oldestMillis = t0.Add(-time.Hour).UnixMilli()

func samplerReply(total int64, oldest int64) string {
	b := &strings.Builder{}
	b.WriteString(`{"hits":{"total":{"value":`)
	writeInt(b, total)
	b.WriteString(`,"relation":"eq"},"hits":[]},"aggregations":{"oldest_received":{"value":`)
	writeInt(b, oldest)
	b.WriteString(`}}}`)
	return b.String()
}

func writeInt(b *strings.Builder, v int64) {
	var buf [20]byte
	i := len(buf)
	neg := v < 0
	if neg {
		v = -v
	}
	for {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
		if v == 0 {
			break
		}
	}
	if neg {
		i--
		buf[i] = '-'
	}
	b.Write(buf[i:])
}

func TestMetricsSamplerEmitsAndCaches(t *testing.T) {
	calls := 0
	now := t0
	m := NewMetrics(func(method, path string, body any) (*http.Response, error) {
		calls++
		if method != http.MethodPost || !strings.Contains(path, "netops-quarantine-*") {
			t.Errorf("unexpected fetch %s %s", method, path)
		}
		return cannedResp(200, samplerReply(7, oldestMillis)), nil
	}, func() time.Time { return now })

	var b strings.Builder
	m.Write(&b)
	out := b.String()
	if !strings.Contains(out, "netops_sec_quarantine_depth 7\n") {
		t.Fatalf("depth gauge missing:\n%s", out)
	}
	if !strings.Contains(out, "netops_sec_quarantine_oldest_seconds 3600\n") {
		t.Fatalf("oldest gauge missing (want 3600):\n%s", out)
	}
	for _, fam := range []string{"netops_sec_quarantine_depth", "netops_sec_quarantine_oldest_seconds"} {
		if !strings.Contains(out, "# TYPE "+fam+" gauge") {
			t.Errorf("missing TYPE for %s", fam)
		}
		if !strings.Contains(out, "# HELP "+fam+" ") {
			t.Errorf("missing HELP for %s", fam)
		}
	}

	// A second render inside the refresh window must NOT hit OpenSearch.
	b.Reset()
	m.Write(&b)
	if calls != 1 {
		t.Fatalf("sampler refreshed inside the 60s window: %d calls", calls)
	}
	// Past the window it refreshes.
	now = t0.Add(61 * time.Second)
	b.Reset()
	m.Write(&b)
	if calls != 2 {
		t.Fatalf("sampler did not refresh after the window: %d calls", calls)
	}
}

func TestMetricsEmitNothingOnFetchError(t *testing.T) {
	m := NewMetrics(func(string, string, any) (*http.Response, error) {
		return nil, errors.New("opensearch unreachable")
	}, func() time.Time { return t0 })
	m.RecordRestore(2, 1)

	var b strings.Builder
	m.Write(&b)
	out := b.String()
	if strings.Contains(out, "netops_sec_quarantine_depth") || strings.Contains(out, "netops_sec_quarantine_oldest_seconds") {
		t.Fatalf("gauges emitted despite a failed sample — a zero (or stale value presented as fresh) is a lie:\n%s", out)
	}
	// The counters are process-local truth and must survive an OS outage.
	if !strings.Contains(out, `netops_sec_quarantine_restored_total{outcome="restored"} 2`) ||
		!strings.Contains(out, `netops_sec_quarantine_restored_total{outcome="failed"} 1`) {
		t.Fatalf("restore counters missing:\n%s", out)
	}
}

func TestMetricsNonOKStatusIsAnError(t *testing.T) {
	m := NewMetrics(func(string, string, any) (*http.Response, error) {
		return cannedResp(500, `{"error":"boom"}`), nil
	}, func() time.Time { return t0 })
	var b strings.Builder
	m.Write(&b)
	if strings.Contains(b.String(), "netops_sec_quarantine_depth") {
		t.Fatalf("gauges emitted from a non-2xx sample:\n%s", b.String())
	}
}

func TestMetricsEmptyQuarantine(t *testing.T) {
	// No docs: depth 0 and age 0 are the TRUE values (the min agg is null).
	m := NewMetrics(func(string, string, any) (*http.Response, error) {
		return cannedResp(200, `{"hits":{"total":{"value":0},"hits":[]},"aggregations":{"oldest_received":{"value":null}}}`), nil
	}, func() time.Time { return t0 })
	var b strings.Builder
	m.Write(&b)
	out := b.String()
	if !strings.Contains(out, "netops_sec_quarantine_depth 0\n") {
		t.Fatalf("empty quarantine must report depth 0:\n%s", out)
	}
	if !strings.Contains(out, "netops_sec_quarantine_oldest_seconds 0\n") {
		t.Fatalf("empty quarantine must report age 0:\n%s", out)
	}
}

func TestMetricsCounterContract(t *testing.T) {
	m := NewMetrics(func(string, string, any) (*http.Response, error) {
		return cannedResp(200, samplerReply(0, 0)), nil
	}, func() time.Time { return t0 })
	var b strings.Builder
	m.Write(&b)
	out := b.String()
	if !strings.Contains(out, "# TYPE netops_sec_quarantine_restored_total counter") {
		t.Fatalf("counter TYPE line missing:\n%s", out)
	}
	// Both outcome series exist from the start so rate() has a base.
	if !strings.Contains(out, `outcome="restored"} 0`) || !strings.Contains(out, `outcome="failed"} 0`) {
		t.Fatalf("counter series must be pre-declared at 0:\n%s", out)
	}
}

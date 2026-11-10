// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flownames

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// The lab's geoip_country (FAILED, FILE_DOESNT_EXIST) and a loaded ip_asn read
// as what they are; a dictionary converge never created reads absent.
func TestDatasetWatchClassifies(t *testing.T) {
	w := NewDatasetWatch()
	q := func(context.Context, string) ([]map[string]any, error) {
		return []map[string]any{
			{"name": "geoip_country", "status": "FAILED", "element_count": "0", "has_error": float64(1)},
			{"name": "ip_asn", "status": "LOADED", "element_count": "1013901", "has_error": float64(0)},
			{"name": "not_ours", "status": "LOADED", "element_count": "5", "has_error": float64(0)},
		}, nil
	}
	if err := w.Measure(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if w.Status("geoip") != DatasetFailed || w.Status("asn") != DatasetLoaded {
		t.Fatalf("geoip=%s asn=%s", w.Status("geoip"), w.Status("asn"))
	}
	var buf bytes.Buffer
	w.WriteMetrics(&buf)
	for _, want := range []string{
		`netops_flow_dataset_status{dataset="asn",status="loaded"} 1`,
		`netops_flow_dataset_status{dataset="geoip",status="failed"} 1`,
		`netops_flow_dataset_elements{dataset="asn"} 1013901`,
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("metrics lack %q:\n%s", want, buf.String())
		}
	}
	if strings.Contains(buf.String(), "not_ours") {
		t.Error("a dictionary we do not watch reached a label")
	}
	empty := func(context.Context, string) ([]map[string]any, error) { return nil, nil }
	if err := w.Measure(context.Background(), empty); err != nil || w.Status("asn") != DatasetAbsent {
		t.Fatalf("no dictionary rows must read absent, got %s", w.Status("asn"))
	}
	bad := func(context.Context, string) ([]map[string]any, error) { return nil, errors.New("ch down") }
	if err := w.Measure(context.Background(), bad); err == nil || w.Status("asn") != DatasetUnknown {
		t.Fatalf("an unread state must read unknown, never the last value: %s", w.Status("asn"))
	}
}

func TestDatasetClassify(t *testing.T) {
	for _, c := range []struct {
		status string
		n      int64
		errd   bool
		want   string
	}{
		{"LOADED", 10, false, DatasetLoaded},
		{"LOADED", 0, false, DatasetLoadedEmpty},
		{"LOADED", 10, true, DatasetFailed},
		{"FAILED", 0, true, DatasetFailed},
		{"NOT_LOADED", 0, false, DatasetNotLoaded},
		{"WEIRD", 0, false, DatasetUnknown},
	} {
		if got := classify(c.status, c.n, c.errd); got != c.want {
			t.Errorf("classify(%s,%d,%v) = %s, want %s", c.status, c.n, c.errd, got, c.want)
		}
	}
}

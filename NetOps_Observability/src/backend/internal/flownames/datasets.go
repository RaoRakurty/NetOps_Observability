// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flownames

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// datasets.go: whether the operator-prepared flow datasets actually load
// (tracker 387 PR 13d). netops.ip_asn (iptoasn, scripts/asn-prepare.py) and
// netops.geoip_country (scripts/geoip-prepare.py) are FILE dictionaries: with
// no file they read FAILED/FILE_DOESNT_EXIST, which the lab's geoip_country did
// for its whole life with nobody told. This makes the state a number.

// datasetDicts are the dictionaries watched, name → metric label.
func datasetDicts() map[string]string {
	return map[string]string{"ip_asn": "asn", "geoip_country": "geoip"}
}

// Dataset statuses, a closed set.
const (
	DatasetLoaded      = "loaded"       // loaded with rows
	DatasetLoadedEmpty = "loaded_empty" // loaded, no rows: an empty file
	DatasetFailed      = "failed"       // the load failed (no file, bad file)
	DatasetNotLoaded   = "not_loaded"   // lazy and never asked for yet
	DatasetAbsent      = "absent"       // no such dictionary (converge has not run)
	DatasetUnknown     = "unknown"      // not measured, or the read failed
)

// DatasetsSQL reads the dictionaries' state. Platform-scope worker read.
const DatasetsSQL = `SELECT name, status, element_count, last_exception != '' AS has_error
  FROM system.dictionaries
 WHERE database = 'netops' AND name IN ('ip_asn', 'geoip_country')
 FORMAT JSON`

// datasetState is one dictionary's measured state.
type datasetState struct {
	status   string
	elements int64
}

// DatasetWatch holds the last measurement.
type DatasetWatch struct {
	mu    sync.Mutex
	state map[string]datasetState // label → state
}

// NewDatasetWatch starts every dataset at unknown.
func NewDatasetWatch() *DatasetWatch {
	w := &DatasetWatch{state: map[string]datasetState{}}
	for _, label := range datasetDicts() {
		w.state[label] = datasetState{status: DatasetUnknown}
	}
	return w
}

// classify maps a system.dictionaries row to a status.
func classify(status string, elements int64, hasError bool) string {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "LOADED", "LOADED_AND_RELOADING":
		if hasError {
			return DatasetFailed // a reload failed; the old data may still serve
		}
		if elements == 0 {
			return DatasetLoadedEmpty
		}
		return DatasetLoaded
	case "FAILED", "FAILED_AND_RELOADING":
		return DatasetFailed
	case "NOT_LOADED", "LOADING":
		return DatasetNotLoaded
	}
	return DatasetUnknown
}

// Measure refreshes the state. A read failure marks every dataset unknown: a
// stale "loaded" would hide exactly the failure this exists to show.
func (w *DatasetWatch) Measure(ctx context.Context, query Query) error {
	rows, err := query(ctx, DatasetsSQL)
	next := map[string]datasetState{}
	for _, label := range datasetDicts() {
		next[label] = datasetState{status: DatasetAbsent}
		if err != nil {
			next[label] = datasetState{status: DatasetUnknown}
		}
	}
	if err == nil {
		for _, r := range rows {
			name, _ := r["name"].(string)
			label, ok := datasetDicts()[name]
			if !ok {
				continue
			}
			st, _ := r["status"].(string)
			n := toInt64(r["element_count"])
			next[label] = datasetState{status: classify(st, n, toInt64(r["has_error"]) != 0), elements: n}
		}
	}
	w.mu.Lock()
	w.state = next
	w.mu.Unlock()
	return err
}

// Status is one dataset's last measured status ("asn" or "geoip").
func (w *DatasetWatch) Status(label string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if st, ok := w.state[label]; ok {
		return st.status
	}
	return DatasetUnknown
}

func toInt64(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return 0
		}
		return n
	case bool:
		if x {
			return 1
		}
	}
	return 0
}

// WriteMetrics renders one series per dataset at value 1 for its status, and
// the row count. No tenant label: the datasets are platform-wide.
func (w *DatasetWatch) WriteMetrics(out io.Writer) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	labels := make([]string, 0, len(w.state))
	for l := range w.state {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	fmt.Fprintf(out, "# HELP netops_flow_dataset_status Whether an operator-prepared flow dataset loads (1 on its current status).\n")
	fmt.Fprintf(out, "# TYPE netops_flow_dataset_status gauge\n")
	for _, l := range labels {
		fmt.Fprintf(out, "netops_flow_dataset_status{dataset=%q,status=%q} 1\n", l, w.state[l].status)
	}
	fmt.Fprintf(out, "# HELP netops_flow_dataset_elements Rows a flow dataset holds once loaded.\n")
	fmt.Fprintf(out, "# TYPE netops_flow_dataset_elements gauge\n")
	for _, l := range labels {
		fmt.Fprintf(out, "netops_flow_dataset_elements{dataset=%q} %d\n", l, w.state[l].elements)
	}
}

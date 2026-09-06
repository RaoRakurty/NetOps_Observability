// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"fmt"
	"io"
	"netops/backend/internal/incident"
	"sync/atomic"
)

// incidents_metrics.go — Prometheus counters for the incident system, emitted via
// /metrics alongside the report/export gauges.

type incidentMetrics struct {
	created  [5]atomic.Int64 // indexed by severity rank (info..critical)
	deduped  atomic.Int64
	resolved atomic.Int64
	syncOK   atomic.Int64
	syncFail atomic.Int64
}

func (s *server) incidentCreated(inc Incident) {
	if s.incMetrics != nil {
		s.incMetrics.created[incident.SeverityRank(inc.Severity)].Add(1)
	}
}
func (s *server) incidentDeduped() {
	if s.incMetrics != nil {
		s.incMetrics.deduped.Add(1)
	}
}
func (s *server) incidentResolved() {
	if s.incMetrics != nil {
		s.incMetrics.resolved.Add(1)
	}
}
func (s *server) incidentSync(ok bool) {
	if s.incMetrics == nil {
		return
	}
	if ok {
		s.incMetrics.syncOK.Add(1)
	} else {
		s.incMetrics.syncFail.Add(1)
	}
}

func (m *incidentMetrics) write(w io.Writer) {
	fmt.Fprintf(w, "# HELP netops_incidents_created_total Incidents created, by severity.\n")
	fmt.Fprintf(w, "# TYPE netops_incidents_created_total counter\n")
	for i, sev := range incident.Severities {
		fmt.Fprintf(w, "netops_incidents_created_total{severity=%q} %d\n", sev, m.created[i].Load())
	}
	fmt.Fprintf(w, "# HELP netops_incidents_deduplicated_total Detections folded into an existing incident.\n")
	fmt.Fprintf(w, "# TYPE netops_incidents_deduplicated_total counter\n")
	fmt.Fprintf(w, "netops_incidents_deduplicated_total %d\n", m.deduped.Load())
	fmt.Fprintf(w, "# HELP netops_incidents_resolved_total Incidents resolved.\n")
	fmt.Fprintf(w, "# TYPE netops_incidents_resolved_total counter\n")
	fmt.Fprintf(w, "netops_incidents_resolved_total %d\n", m.resolved.Load())
	fmt.Fprintf(w, "# HELP netops_incident_sync_success_total ITSM projections that succeeded.\n")
	fmt.Fprintf(w, "# TYPE netops_incident_sync_success_total counter\n")
	fmt.Fprintf(w, "netops_incident_sync_success_total %d\n", m.syncOK.Load())
	fmt.Fprintf(w, "# HELP netops_incident_sync_failure_total ITSM projections that failed.\n")
	fmt.Fprintf(w, "# TYPE netops_incident_sync_failure_total counter\n")
	fmt.Fprintf(w, "netops_incident_sync_failure_total %d\n", m.syncFail.Load())
}

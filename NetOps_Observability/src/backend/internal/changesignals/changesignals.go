// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package changesignals is the ClickHouse side of the change ledger's signal
// bridge (Iris N-D2): the keyset read of the change-shaped rows of
// netops.corr_signals, and the adaptation of one row onto
// changeledger.SignalChange. It sits apart from internal/changeledger, which
// imports no other domain, because reading a cloud row needs the cloud package's
// own classification.
//
// The bridge spans every tenant, so its read runs at the platform scope. Each row
// keeps the tenant_id column the engine's verified_tenant adjudicated, and that
// column is the ONLY tenant a ledger row is stamped with. A tenant_id inside attrs
// (device or provider text) is never read.
package changesignals

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"netops/backend/cloud"
	"netops/backend/internal/changeledger"
	"netops/backend/internal/chschema"
)

var signalIDRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// SQL is one keyset page of change signals. The bridge's lanes are named here and
// again by the producer's allowlist, which refuses anything else. corr_signals is
// append-only and the cloud ingester re-emits an event every poll, so the read
// collapses to one row per signal_id at its earliest time. Every literal is
// server-formatted; the cursor id is checked before it is quoted.
func SQL(p changeledger.SignalPage) (string, error) {
	having := ""
	if p.AfterID != "" {
		if !signalIDRe.MatchString(p.AfterID) {
			return "", fmt.Errorf("change-ledger bridge: cursor id %q is not a signal id", p.AfterID)
		}
		at := p.AfterAt.UTC().Format("2006-01-02 15:04:05.000")
		having = fmt.Sprintf(`HAVING first_ts > toDateTime64('%[1]s', 3, 'UTC') OR (first_ts = toDateTime64('%[1]s', 3, 'UTC') AND signal_id_s > '%[2]s')
 `, at, p.AfterID)
	}
	const layout = "2006-01-02 15:04:05"
	return fmt.Sprintf(`
SELECT tenant_id                         AS tenant_id_s,
       toString(signal_id)               AS signal_id_s,
       min(ts)                           AS first_ts,
       `+chschema.ISO("min(ts)")+`       AS ts_s,
       `+chschema.ISO("min(ingest_ts)")+` AS ingest_ts_s,
       toString(any(source))             AS source_s,
       any(kind)                         AS kind_s,
       toString(any(entity_type))        AS entity_type_s,
       any(entity_id)                    AS entity_id_s,
       any(site)                         AS site_s,
       any(metric_name)                  AS metric_name_s,
       any(attrs)                        AS attrs_s
  FROM (
       SELECT tenant_id, signal_id, ts, ingest_ts, source, kind, entity_type, entity_id, site, metric_name, attrs
         FROM netops.corr_signals
        WHERE ts >= toDateTime('%s','UTC') AND ts <= toDateTime('%s','UTC')
          AND ((source IN ('trap','syslog') AND kind = '%s')
            OR (source = 'cloud' AND kind IN ('%s','%s','%s')))
  )
 GROUP BY tenant_id, signal_id
 %sORDER BY first_ts ASC, signal_id_s ASC
 LIMIT %d
 FORMAT JSON`, p.Since.UTC().Format(layout), p.Until.UTC().Add(time.Second).Format(layout),
		changeledger.KindDeviceConfigChange,
		changeledger.KindCloudChange, changeledger.KindCloudAudit, changeledger.KindSecurityPolicyChange,
		having, p.Limit), nil
}

// FromRow adapts one row. It is an error only when the row has no readable time,
// which the keyset could not advance past. Attributes that do not parse leave the
// optional fields empty and are reported through warn: a device that said nothing
// stays that way, and the fact that it reported a change is kept.
func FromRow(row map[string]any, warn func(msg string, fields map[string]any)) (changeledger.SignalChange, error) {
	at, err := time.Parse(time.RFC3339Nano, str(row["ts_s"]))
	if err != nil {
		return changeledger.SignalChange{}, fmt.Errorf("change signal time: %w", err)
	}
	detected, err := time.Parse(time.RFC3339Nano, str(row["ingest_ts_s"]))
	if err != nil {
		detected = at
	}
	raw := str(row["attrs_s"])
	in := changeledger.SignalChange{
		Tenant: str(row["tenant_id_s"]), SignalID: str(row["signal_id_s"]),
		At: at, DetectedAt: detected, Source: str(row["source_s"]), Kind: str(row["kind_s"]),
		Entity: str(row["entity_id_s"]), EntityType: str(row["entity_type_s"]),
	}
	if in.Source == changeledger.SignalSourceCloud {
		a := cloud.ParseAttrs(raw)
		sr := cloud.SignalRow{EntityType: in.EntityType, EntityID: in.Entity}
		in.EventName = str(row["metric_name_s"])
		in.EventSource, in.RequestID, in.Provider = a.EventSource, a.RequestID, a.Provider
		in.App = cloud.AppOf(sr, a)
		if a.Actor != "" {
			in.Actor = cloud.ShortActor(a.Actor)
		}
		in.ChangeClass = cloud.ChangeType(in.Kind, in.EventName)
		return in, nil
	}
	in.Site = str(row["site_s"])
	// Fields are `any` and read one by one below: a mistyped attribute must not
	// lose the fact that the device reported a change.
	var d struct {
		User, Source, Line, Method, Destination, Authenticated any
	}
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &d); err != nil && warn != nil {
			warn("a change signal's attributes did not parse — it is recorded without who or where",
				map[string]any{"signal": in.SignalID, "error": err.Error()})
		}
	}
	in.User, in.Origin, in.Line = attrWord(d.User), attrWord(d.Source), attrWord(d.Line)
	in.Method, in.Destination = attrWord(d.Method), attrWord(d.Destination)
	if b, ok := d.Authenticated.(bool); ok {
		in.Authenticated = &b
	}
	return in, nil
}

func str(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// attrWord keeps a string attribute and drops anything else: the catalog's
// `unknown` placeholder is not a reported value.
func attrWord(v any) string {
	s := strings.TrimSpace(str(v))
	if strings.EqualFold(s, "unknown") {
		return ""
	}
	return s
}

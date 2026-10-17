// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

import (
	"strconv"
	"strings"
)

// exporter_appid.go — the exporter's own application classification carried
// on a flow record (IPFIX / NetFlow v9 IE 95 applicationId, IE 96
// applicationName), as vector-router stores it: "<engine>:<selector>" or, for
// engine 20 (PANA-L7-PEN), "20:<pen>:<selector>" (RFC 6759).
//
// It is NOT fused into the address verdict (Fuse): exporter vocabularies
// ("ms-office-365") and catalog names ("Microsoft 365") differ, and the
// fusion's contradiction rule would demote an address name the screen shows
// today. It is reported beside it, with its provenance, until vendor-name
// canonicalisation exists.

// Exporter classification kinds.
const (
	ExporterKindApp          = "app"           // an application (L7 / user-defined / PEN registry)
	ExporterKindServiceClass = "service_class" // a protocol or port number — a service class, not the app
	ExporterKindUnclassified = "unclassified"  // the exporter classified nothing (selector 0)
	ExporterKindUnknown      = "unknown"       // an engine RFC 6759 does not define
)

// ExporterAppID is a parsed IE 95 value.
type ExporterAppID struct {
	Engine   int
	PEN      int64 // engine 20 only
	Selector int64
	Kind     string
}

// ParseExporterAppID parses the stored id. ok=false for anything malformed.
func ParseExporterAppID(s string) (ExporterAppID, bool) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	num := func(p string) (int64, bool) {
		n, err := strconv.ParseInt(p, 10, 64)
		return n, err == nil && n >= 0
	}
	var out ExporterAppID
	switch len(parts) {
	case 2:
		e, ok1 := num(parts[0])
		sel, ok2 := num(parts[1])
		if !ok1 || !ok2 || e <= 0 || e > 255 || e == 20 {
			return ExporterAppID{}, false
		}
		out = ExporterAppID{Engine: int(e), Selector: sel}
	case 3:
		e, ok1 := num(parts[0])
		pen, ok2 := num(parts[1])
		sel, ok3 := num(parts[2])
		if !ok1 || !ok2 || !ok3 || e != 20 || pen > 0xffffffff {
			return ExporterAppID{}, false
		}
		out = ExporterAppID{Engine: 20, PEN: pen, Selector: sel}
	default:
		return ExporterAppID{}, false
	}
	switch {
	case out.Selector == 0:
		out.Kind = ExporterKindUnclassified
	case out.Engine == 1 || out.Engine == 3 || out.Engine == 18 || out.Engine == 19:
		// IANA-L3 / IANA-L4 / ETHERTYPE / LLC: a protocol or port number.
		out.Kind = ExporterKindServiceClass
	case out.Engine == 2 || out.Engine == 4 || out.Engine == 6 || out.Engine == 12 || out.Engine == 13 || out.Engine == 20:
		out.Kind = ExporterKindApp
	default:
		out.Kind = ExporterKindUnknown
	}
	return out, true
}

// ExporterAppName returns the exporter-sent name, or "" when it carries no
// information ("unknown", "unclassified" and the like are not names).
func ExporterAppName(s string) string {
	n := strings.TrimSpace(s)
	switch strings.ToLower(n) {
	case "", "unknown", "unclassified", "unclassified-traffic", "none", "n/a":
		return ""
	}
	return n
}

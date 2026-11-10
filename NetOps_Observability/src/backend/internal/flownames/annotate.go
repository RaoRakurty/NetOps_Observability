// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flownames

import (
	"fmt"
	"strconv"
	"strings"

	"netops/backend/internal/iana"
)

// annotate.go: names on the Logs page's sampled flow documents
// (tracker 387 PR 13b). The flows API names interfaces in SQL; the Logs page
// reads OpenSearch, so the same rows (Exporter's in-memory copy of
// netops.iface_names) name each document here, beside the stored record.
//
// The names ride on the hit as `_resolved`, never inside `_source`: the Raw
// tab shows what was stored, and these were not. Each lookup uses the
// DOCUMENT's own tenant_id, the same key rule the SQL join uses, so a name can
// only come from the tenant that owns the document, which logsScope has
// already proven the caller may read.

// Resolver is what the annotation needs; *Exporter is it.
type Resolver interface {
	Lookup(tenant, exporter string, ifindex uint32) (string, bool)
}

// IfaceName names one interface of one flow document, with its basis.
func IfaceName(names Resolver, tenant, exporter string, v any) (name, basis string, ok bool) {
	idx, ok := IndexValue(v)
	if !ok {
		return "", "", false // no index on the document: nothing to say
	}
	if idx == SentinelZero || idx == SentinelNone {
		return "", "sentinel", true
	}
	if names != nil {
		if n, hit := names.Lookup(tenant, exporter, idx); hit {
			return n, "resolved", true
		}
	}
	return "", "absent", true
}

// IndexValue reads an ifIndex from a decoded JSON value.
func IndexValue(v any) (uint32, bool) {
	var s string
	switch x := v.(type) {
	case float64:
		if x < 0 || x > 4294967295 || x != float64(uint64(x)) {
			return 0, false
		}
		return uint32(x), true
	case string:
		s = strings.TrimSpace(x)
	case nil:
		return 0, false
	default:
		s = fmt.Sprint(x)
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// AnnotateHits adds `_resolved` names to every flow hit of a parsed
// OpenSearch search response. It changes nothing else.
//
// A document whose source or destination is one of the platform's own
// addresses also gets traffic_class=platform_monitoring (platform.go).
func AnnotateHits(resp map[string]any, names Resolver, tables iana.Names, platform PlatformAddrs) {
	outer, _ := resp["hits"].(map[string]any)
	hits, _ := outer["hits"].([]any)
	for _, h := range hits {
		hit, _ := h.(map[string]any)
		src, _ := hit["_source"].(map[string]any)
		if src == nil {
			continue
		}
		tenant, _ := src["tenant_id"].(string)
		exporter, _ := src["sampler_address"].(string)
		res := map[string]any{}
		for _, col := range []string{"in_if", "out_if"} {
			if n, basis, ok := IfaceName(names, tenant, exporter, src[col]); ok {
				res[col+"_name"], res[col+"_name_basis"] = n, basis
			}
		}
		if p, ok := IndexValue(src["proto"]); ok && p <= 255 {
			if name := tables.Protocol(uint8(p)); name != "" {
				res["proto_name"] = name
			}
			// The likely service end, as the flows API's service_port: the lower
			// of the two ports. A port HEURISTIC, labelled so in the UI.
			sp, okS := IndexValue(src["src_port"])
			dp, okD := IndexValue(src["dst_port"])
			if okS && okD && sp <= 65535 && dp <= 65535 {
				port := min(sp, dp)
				if name := tables.Service(uint8(p), uint16(port)); name != "" && port > 0 {
					res["service_name"], res["service_port"] = name, port
				}
			}
		}
		srcAddr, _ := src["src_addr"].(string)
		dstAddr, _ := src["dst_addr"].(string)
		if platform.Contains(srcAddr) || platform.Contains(dstAddr) {
			res["traffic_class"] = TrafficClassPlatform
		}
		if len(res) > 0 {
			hit["_resolved"] = res
		}
	}
}

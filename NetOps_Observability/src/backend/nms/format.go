// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import "strconv"

// small stdlib formatting helpers kept local so model.go stays dependency-free.

func formatFloat(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }
func formatInt(i int64) string     { return strconv.FormatInt(i, 10) }

// sanitizeLabelValue makes a tag value safe for a Prometheus-exposition line:
// backslash and double-quote escaped, newlines stripped. (Metric names/keys are
// framework-controlled, so only values need sanitizing.)
func sanitizeLabelValue(v string) string {
	out := make([]rune, 0, len(v))
	for _, r := range v {
		switch r {
		case '\\':
			out = append(out, '\\', '\\')
		case '"':
			out = append(out, '\\', '"')
		case '\n', '\r':
			out = append(out, ' ')
		default:
			out = append(out, r)
		}
	}
	return string(out)
}

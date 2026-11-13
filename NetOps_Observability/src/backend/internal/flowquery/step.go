// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flowquery

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// Steps is the allowlist of bucket widths in seconds. Each divides a UTC day,
// so buckets line up with the clock (86400 and 21600 align to UTC midnight).
var Steps = []int64{60, 300, 900, 3600, 21600, 86400}

const (
	// MaxAutoPoints is the most buckets an automatically chosen step yields.
	MaxAutoPoints = 240
	// MaxPoints is the most buckets an explicitly requested step may yield.
	MaxPoints = 1500
)

// PickStep chooses the bucket width for a span. With no request (or "auto") it
// is the smallest allowlisted step giving at most MaxAutoPoints buckets. A
// requested step must be in Steps (as a duration such as 5m, or seconds) and
// give at most MaxPoints buckets; anything else is an error.
func PickStep(span time.Duration, requested string) (int64, error) {
	secs := int64(span / time.Second)
	requested = strings.TrimSpace(requested)
	if requested == "" || strings.EqualFold(requested, "auto") {
		for _, s := range Steps {
			if buckets(secs, s) <= MaxAutoPoints {
				return s, nil
			}
		}
		return Steps[len(Steps)-1], nil
	}
	var s int64
	if isDigits(requested) {
		n, err := strconv.ParseInt(requested, 10, 64)
		if err != nil {
			return 0, errStep
		}
		s = n
	} else {
		d, err := time.ParseDuration(requested)
		if err != nil || d%time.Second != 0 {
			return 0, errStep
		}
		s = int64(d / time.Second)
	}
	allowed := false
	for _, a := range Steps {
		if a == s {
			allowed = true
		}
	}
	if !allowed {
		return 0, errStep
	}
	if buckets(secs, s) > MaxPoints {
		return 0, errors.New("that step gives too many points for this window; choose a longer step")
	}
	return s, nil
}

var errStep = errors.New("step must be one of 1m, 5m, 15m, 1h, 6h or 1d")

func buckets(secs, step int64) int64 { return (secs + step - 1) / step }

// Snap widens [from, to) outward to whole buckets, so the first and last bucket
// are never a fraction of a bucket that would read as a drop in traffic.
func Snap(from, to time.Time, step int64) (time.Time, time.Time) {
	f := from.Unix() - mod(from.Unix(), step)
	t := to.Unix()
	if r := mod(t, step); r != 0 {
		t += step - r
	}
	return time.Unix(f, 0).UTC(), time.Unix(t, 0).UTC()
}

func mod(a, b int64) int64 {
	m := a % b
	if m < 0 {
		m += b
	}
	return m
}

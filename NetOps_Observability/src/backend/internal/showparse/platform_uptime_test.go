// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package showparse

// platform_uptime_test.go — the Junos `show system uptime` header line.
//
// Junos prints FreeBSD's `w` header, and FreeBSD prints the SINGULAR "1 user"
// when exactly one session is open. On a device the platform has just logged in
// to collect from, that one session is very often the collector's own — so the
// singular is the COMMON case in production, not the edge one. The parser used
// to cut on " users" and fall back to dropping the last whitespace field, which
// turned the whole rest of the line into the recorded uptime.

import "testing"

func TestParseJunosUptime_UserClauseSpellings(t *testing.T) {
	const booted = "System booted: 2026-08-23 07:29:00 UTC (1w2d 02:31 ago)\n"
	cases := []struct {
		name string
		line string
		want string
	}{
		{
			// The case that was broken: one open session, singular noun.
			name: "one session, singular",
			line: "10:00AM  up 10 days,  2:31, 1 user, load averages: 0.10, 0.15, 0.20",
			want: "10 days, 2:31",
		},
		{
			name: "several sessions, plural",
			line: "10:00AM  up 10 days,  2:31, 4 users, load averages: 0.10, 0.15, 0.20",
			want: "10 days, 2:31",
		},
		{
			name: "no session, plural zero",
			line: "10:00AM  up 10 days,  2:31, 0 users, load averages: 0.10, 0.15, 0.20",
			want: "10 days, 2:31",
		},
		{
			// Under a day, FreeBSD prints no "days," clause at all.
			name: "sub-day uptime",
			line: "10:00AM  up 15 mins, 1 user, load averages: 0.00, 0.01, 0.05",
			want: "15 mins",
		},
		{
			// Defensive: a header with no session clause keeps the uptime it has
			// rather than losing its last field to the old fallback.
			name: "no session clause",
			line: "10:00AM  up 10 days,  2:31, load averages: 0.10, 0.15, 0.20",
			want: "10 days, 2:31",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := mustParse(t, CmdPlatformUptime, DialectJunos, booted+tc.line+"\n")
			if res.Platform == nil {
				t.Fatal("no platform health parsed")
			}
			wantStrP(t, "Uptime", res.Platform.Uptime, tc.want)
		})
	}
}

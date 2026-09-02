package showparse

// logs.go — device log-buffer parsers (CmdLogs).
//
// Log lines are the one place where a "close enough" parse is actively
// dangerous: a mis-split facility turns %LINK-3-UPDOWN into evidence about OSPF.
// Every parser here therefore recognizes a line only by its dialect's exact
// grammar marker (Cisco's "%FACILITY-SEVERITY-MNEMONIC:", Junos's
// "process[pid]: TAG:", Huawei's "%%ddMODULE/severity/BRIEF"), and a line that
// does not carry it is dropped rather than half-parsed.
//
// Timestamps are carried as TEXT. Device buffers routinely omit the year and the
// timezone; parsing them into a time.Time would mean inventing both.

import "strings"

func registerLogParsers(l *Library) {
	l.register(CmdLogs, parseCiscoSyslog,
		DialectCiscoIOS, DialectCiscoIOSXE, DialectCiscoIOSXR, DialectCiscoNXOS, DialectAristaEOS)
	l.register(CmdLogs, parseJunosSyslog, DialectJunos)
	l.register(CmdLogs, parseVRPLogbuffer, DialectHuaweiVRP)
	l.register(CmdLogs, parseSROSEventLog, DialectNokiaSROS)
}

// parseCiscoSyslog parses the "%FACILITY-SEVERITY-MNEMONIC: message" grammar
// shared by IOS, IOS-XE, IOS-XR, NX-OS and EOS.
func parseCiscoSyslog(lines []string) Result {
	var res Result
	for _, ln := range lines {
		if trim(ln) == "" {
			continue
		}
		pct := strings.Index(ln, "%")
		if pct < 0 {
			continue
		}
		rest := ln[pct+1:]
		tag, msg, ok := strings.Cut(rest, ": ")
		if !ok {
			continue
		}
		parts := strings.SplitN(tag, "-", 3)
		if len(parts) != 3 {
			continue
		}
		sev, sevOK := atoiOK(parts[1])
		if !sevOK || sev < 0 || sev > 7 {
			continue
		}
		if parts[0] == "" || parts[2] == "" {
			continue
		}
		entry := LogLine{
			Raw:      ln,
			Facility: strPtr(parts[0]),
			Severity: intPtr(int(sev)),
			Mnemonic: strPtr(parts[2]),
			Message:  trim(msg),
		}
		if ts := trim(strings.TrimLeft(ln[:pct], "*")); ts != "" {
			entry.Timestamp = strPtr(strings.TrimRight(ts, ":"))
		}
		res.Logs = append(res.Logs, entry)
	}
	return res
}

// parseJunosSyslog parses "<mon> <day> <time> <host> <process>[<pid>]: TAG: msg".
// Junos carries no numeric severity in the buffer, so Severity stays nil.
func parseJunosSyslog(lines []string) Result {
	var res Result
	for _, ln := range lines {
		fs := fields(ln)
		if len(fs) < 6 {
			continue
		}
		proc := fs[4]
		open := strings.Index(proc, "[")
		if open <= 0 || !strings.HasSuffix(proc, "]:") {
			continue
		}
		name := proc[:open]
		rest := strings.Join(fs[5:], " ")
		tag, msg, ok := strings.Cut(rest, ": ")
		if !ok || tag == "" || strings.ContainsAny(tag, " ") {
			continue
		}
		res.Logs = append(res.Logs, LogLine{
			Raw:       ln,
			Timestamp: strPtr(strings.Join(fs[0:3], " ")),
			Facility:  strPtr(name),
			Mnemonic:  strPtr(tag),
			Message:   trim(msg),
		})
	}
	return res
}

// parseVRPLogbuffer parses the Huawei grammar
// "<timestamp> <host> %%ddMODULE/severity/BRIEF(l)[n]:message".
func parseVRPLogbuffer(lines []string) Result {
	var res Result
	for _, ln := range lines {
		idx := strings.Index(ln, "%%")
		if idx < 0 {
			continue
		}
		rest := ln[idx+2:]
		head, msg, ok := strings.Cut(rest, ":")
		if !ok {
			continue
		}
		// Strip the "(l)[123]" decoration the brief carries.
		if p := strings.IndexAny(head, "(["); p >= 0 {
			head = head[:p]
		}
		parts := strings.Split(head, "/")
		if len(parts) != 3 {
			continue
		}
		mod := strings.TrimLeft(parts[0], "0123456789")
		sev, sevOK := atoiOK(parts[1])
		if mod == "" || !sevOK || sev < 0 || sev > 7 || parts[2] == "" {
			continue
		}
		entry := LogLine{
			Raw:      ln,
			Facility: strPtr(mod),
			Severity: intPtr(int(sev)),
			Mnemonic: strPtr(parts[2]),
			Message:  trim(msg),
		}
		if ts := trim(ln[:idx]); ts != "" {
			entry.Timestamp = strPtr(ts)
		}
		res.Logs = append(res.Logs, entry)
	}
	return res
}

// srosSeverityWord is the closed SR OS event severity set.
func srosSeverityWord(tok string) bool {
	switch strings.ToUpper(strings.TrimSuffix(trim(tok), ":")) {
	case "CLEARED", "INDETERMINATE", "CRITICAL", "MAJOR", "MINOR", "WARNING":
		return true
	}
	return false
}

// parseSROSEventLog parses an SR OS memory-log record:
//
//	122 2026/09/02 09:58:12.34 UTC MINOR: OSPF #2005 Base VR 1: message
//
// SR OS severities are WORDS, not the 0-7 syslog numbers, so Severity is left
// nil rather than mapped onto a scale the device never used; the word is carried
// in Facility's companion field Mnemonic only when the record names an event.
func parseSROSEventLog(lines []string) Result {
	var res Result
	for _, ln := range lines {
		fs := fields(ln)
		if len(fs) < 6 {
			continue
		}
		if !isDigits(fs[0]) {
			continue
		}
		sevIdx := -1
		for i := 1; i < len(fs) && i < 6; i++ {
			if srosSeverityWord(fs[i]) && strings.HasSuffix(fs[i], ":") {
				sevIdx = i
				break
			}
		}
		if sevIdx < 0 || sevIdx+1 >= len(fs) {
			continue
		}
		app := fs[sevIdx+1]
		entry := LogLine{
			Raw:       ln,
			Timestamp: strPtr(strings.Join(fs[1:sevIdx], " ")),
			Facility:  strPtr(app),
			Message:   trim(strings.Join(fs[sevIdx+2:], " ")),
		}
		if sevIdx+2 < len(fs) && strings.HasPrefix(fs[sevIdx+2], "#") {
			entry.Mnemonic = strPtr(strings.TrimPrefix(fs[sevIdx+2], "#"))
		}
		res.Logs = append(res.Logs, entry)
	}
	return res
}

package main

import (
	"encoding/binary"
	"testing"
	"time"
)

// TestSanitizeSystemNetwork: DNS must be valid IPs, NTP a host/IP, deduped.
func TestSanitizeSystemNetwork(t *testing.T) {
	in := SystemNetworkConfig{
		DNSServers:    []string{"1.1.1.1", " 8.8.8.8 ", "1.1.1.1", "not-an-ip"},
		NTPServers:    []string{"pool.ntp.org", "10.0.0.5", "pool.ntp.org"},
		SearchDomains: []string{"corp.local.", "corp.local"},
	}
	// invalid DNS ip → error
	if _, err := sanitizeSystemNetwork(in); err == nil {
		t.Fatal("expected an error for the invalid DNS IP")
	}
	in.DNSServers = []string{"1.1.1.1", " 8.8.8.8 ", "1.1.1.1"}
	out, err := sanitizeSystemNetwork(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.DNSServers) != 2 || out.DNSServers[0] != "1.1.1.1" || out.DNSServers[1] != "8.8.8.8" {
		t.Fatalf("DNS not deduped/trimmed: %v", out.DNSServers)
	}
	if len(out.NTPServers) != 2 {
		t.Fatalf("NTP not deduped: %v", out.NTPServers)
	}
	if len(out.SearchDomains) != 1 || out.SearchDomains[0] != "corp.local" {
		t.Fatalf("search domains not normalized: %v", out.SearchDomains)
	}
}

// TestParseNTPResponse checks the offset math against a synthesized response.
func TestParseNTPResponse(t *testing.T) {
	// Construct a response where the server clock is exactly 1s AHEAD of local.
	t1 := time.Unix(1_700_000_000, 0).UTC()                     // client transmit
	t4 := t1.Add(20 * time.Millisecond)                         // client receive (20ms RTT)
	serverMid := t1.Add(10 * time.Millisecond).Add(time.Second) // server is +1s, midway in RTT

	resp := make([]byte, 48)
	resp[1] = 2                          // stratum 2
	writeNTPTime(resp[32:40], serverMid) // T2 receive
	writeNTPTime(resp[40:48], serverMid) // T3 transmit

	offset, stratum, err := parseNTPResponse(resp, t1, t4)
	if err != nil {
		t.Fatal(err)
	}
	if stratum != 2 {
		t.Errorf("stratum = %d, want 2", stratum)
	}
	// offset ≈ +1s (server ahead of local); allow a few ms of rounding.
	ms := offset.Milliseconds()
	if ms < 995 || ms > 1005 {
		t.Errorf("offset = %dms, want ~1000ms", ms)
	}
}

func TestParseNTPResponseShort(t *testing.T) {
	if _, _, err := parseNTPResponse(make([]byte, 10), time.Now(), time.Now()); err == nil {
		t.Fatal("expected error on a short NTP response")
	}
}

// writeNTPTime is the test inverse of ntpTime (encode a time as an NTP timestamp).
func writeNTPTime(b []byte, tm time.Time) {
	secs := uint32(tm.Unix() + ntpEpochOffset)
	frac := uint32((int64(tm.Nanosecond()) << 32) / 1e9)
	binary.BigEndian.PutUint32(b[0:4], secs)
	binary.BigEndian.PutUint32(b[4:8], frac)
}

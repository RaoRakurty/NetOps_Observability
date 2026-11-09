// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

// snmptrap_community_test.go — the v1/v2c community is a shared device
// credential. It is checked on receipt and goes no further: not to the bus, not
// to a log, not into an error, not into a trace.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/parsetrace"
)

const fabricatedCommunity = "fabricated-community-7f3a"

// buildV1Trap builds a v1 Trap-PDU the decoder accepts.
func buildV1Trap(community string) []byte {
	pdu := berOID([]int{1, 3, 6, 1, 4, 1, 9})                          // enterprise
	pdu = append(pdu, berTLV(0x40, []byte{10, 0, 0, 5})...)            // agent-addr
	pdu = append(pdu, berInt(2)...)                                    // generic = linkDown
	pdu = append(pdu, berInt(0)...)                                    // specific
	pdu = append(pdu, berTLV(0x43, []byte{0x00, 0x00, 0x01, 0x00})...) // time-stamp
	ifIndex := berTLV(0x30, append(berOID([]int{1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 2}), berInt(2)...))
	pdu = append(pdu, berTLV(0x30, ifIndex)...) // varbinds
	msg := berInt(0)
	msg = append(msg, berTLV(0x04, []byte(community))...)
	msg = append(msg, berTLV(0xA4, pdu)...)
	return berTLV(0x30, msg)
}

// published decodes one datagram the way Run does and returns exactly what
// forward would put on the wire.
func published(t *testing.T, r *trapReceiver, pkt []byte) (*TrapEvent, map[string]any, string) {
	t.Helper()
	ev, err := r.decodePacket(pkt, "10.0.0.5")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	deriveEnvelope(ev)
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return ev, doc, string(raw)
}

func TestTrapEventCarriesPresenceNotTheCommunity(t *testing.T) {
	cases := map[string]func(string) []byte{"v1": buildV1Trap, "v2c": buildV2cTrap}
	for version, build := range cases {
		// "public" is a credential like any other: no value-based exception.
		for _, community := range []string{fabricatedCommunity, "public"} {
			t.Run(version+"/"+community, func(t *testing.T) {
				r := &trapReceiver{}
				ev, doc, raw := published(t, r, build(community))
				if ev.Version != version {
					t.Fatalf("version = %q, want %q", ev.Version, version)
				}
				if strings.Contains(raw, community) && community != "public" {
					t.Fatalf("event JSON holds the community: %s", raw)
				}
				if _, ok := doc["snmp_community"]; ok {
					t.Fatalf("event JSON has snmp_community: %s", raw)
				}
				if doc["snmp_community_present"] != true {
					t.Fatalf("snmp_community_present = %v: %s", doc["snmp_community_present"], raw)
				}
				if ev.community != "" {
					t.Fatal("decodePacket must clear the community once the checks ran")
				}
				if s := fmt.Sprintf("%+v %#v", *ev, *ev); strings.Contains(s, community) && community != "public" {
					t.Fatalf("formatted event holds the community: %s", s)
				}
			})
		}
	}
}

func TestEmptyCommunityIsNotReportedPresent(t *testing.T) {
	_, doc, raw := published(t, &trapReceiver{}, buildV2cTrap(""))
	if _, ok := doc["snmp_community_present"]; ok {
		t.Fatalf("an empty community presents no credential: %s", raw)
	}
}

func TestV3EventHasNeitherCommunityNorFlag(t *testing.T) {
	ev := &TrapEvent{Signal: "snmptrap", Version: "v3", User: "monitor"}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "snmp_community") {
		t.Fatalf("v3 event must carry neither field: %s", raw)
	}
	// The real decoder path too, so a future v3 branch cannot start setting it.
	eid := []byte{0x80, 0x00, 0x1f, 0x88, 0x02, 0xde, 0xad, 0xbe, 0xef}
	clear := snmpCreds{Version: 3, Level: "noAuthNoPriv", User: "monitor"}
	sess := &v3Session{creds: clear, engineID: eid, boots: 1, etime: 1}
	trapOID := []int{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}
	coldStart := []int{1, 3, 6, 1, 6, 3, 1, 1, 5, 1}
	vb := berTLV(0x30, berTLV(0x30, append(berOID(trapOID), berOID(coldStart)...)))
	pkt := buildV3Message(1, clear, sess, buildScopedPDU(eid, "", buildPDU(0xA7, 1, vb)), nil)
	got, err := (&trapReceiver{}).decodePacket(pkt, "10.0.0.5")
	if err != nil {
		t.Fatalf("decode v3: %v", err)
	}
	raw, err = json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "v3" || strings.Contains(string(raw), "snmp_community") {
		t.Fatalf("v3 decoder output: %s", raw)
	}
}

// The identity decision still runs on the raw value: clearing it afterwards must
// not change who a trap is attributed to.
func TestGuardStillDecidesOnTheRawCommunity(t *testing.T) {
	tg := Target{ID: "leaf1", Address: "10.0.0.5:161", Community: fabricatedCommunity}
	r := &trapReceiver{targets: func() []Target { return []Target{tg} }}

	ev, err := r.decodePacket(buildV2cTrap(fabricatedCommunity), "10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Device != "leaf1" || ev.EnrichmentStatus != "inventory_matched" {
		t.Fatalf("right community: device=%q status=%q", ev.Device, ev.EnrichmentStatus)
	}
	ev, err = r.decodePacket(buildV2cTrap("wrong-value"), "10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Device != "" || ev.EnrichmentStatus != "inventory_missing" {
		t.Fatalf("wrong community must lose the claim: device=%q status=%q", ev.Device, ev.EnrichmentStatus)
	}
	if !ev.CommunityPresent {
		t.Fatal("a wrong community is still a presented one")
	}
}

// captureOutput collects everything written to the standard logger, stdout and
// stderr while fn runs.
func captureOutput(t *testing.T, fn func()) string {
	t.Helper()
	var logged bytes.Buffer
	oldLog := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(oldLog)

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = pw, pw
	var piped bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&piped, pr)
	}()
	fn()
	os.Stdout, os.Stderr = oldOut, oldErr
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	return logged.String() + piped.String()
}

// recordingSink captures parser-trace emissions.
type recordingSink struct {
	mu    sync.Mutex
	lines []string
}

func (s *recordingSink) sink(_, component, msg string, fields map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, fmt.Sprintf("%s %s %v", component, msg, fields))
}

// Every receiver path that writes somewhere: a delivered trap, a refused one, an
// unreachable sink, an armed parser trace and malformed datagrams whose errors
// reach the collector's status.
func TestCommunityNeverAppearsInLogsErrorsOrTraces(t *testing.T) {
	var sinkBodies []string
	var mu sync.Mutex
	status := http.StatusOK
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		mu.Lock()
		sinkBodies = append(sinkBodies, string(b))
		code := status
		mu.Unlock()
		w.WriteHeader(code)
	}))
	defer sink.Close()

	tg := Target{ID: "leaf1", Address: "10.0.0.5:161", Community: fabricatedCommunity}
	r := &trapReceiver{
		sinkURL: sink.URL,
		targets: func() []Target { return []Target{tg} },
		events:  make(chan *TrapEvent, 8),
	}

	trace := &recordingSink{}
	f := parsetrace.Default()
	f.SetSink(trace.sink)
	defer f.SetSink(nil)
	if _, err := f.Arm("ifIndex", time.Minute); err != nil {
		t.Fatal(err)
	}
	defer f.Disarm()

	client := &http.Client{Timeout: 2 * time.Second}
	var errs []string
	out := captureOutput(t, func() {
		for _, build := range []func(string) []byte{buildV1Trap, buildV2cTrap} {
			ev, err := r.decodePacket(build(fabricatedCommunity), "10.0.0.5")
			if err != nil {
				t.Errorf("decode: %v", err)
				continue
			}
			r.recordDecoded(ev, "10.0.0.5")
			r.forward(context.Background(), client, ev) // delivered

			mu.Lock()
			status = http.StatusForbidden
			mu.Unlock()
			r.forward(context.Background(), client, ev) // refused by the sink
			mu.Lock()
			status = http.StatusOK
			mu.Unlock()

			sinkURL := r.sinkURL
			r.sinkURL = "http://127.0.0.1:1/unreachable"
			r.forward(context.Background(), client, ev) // transport failure
			r.sinkURL = sinkURL
			if st := r.status.LastError; strings.Contains(st, fabricatedCommunity) {
				t.Errorf("status LastError holds the community: %s", st)
			}
		}
		// The community decodes, then the PDU does not: the error path of both
		// versions, plus a panic-free truncation.
		for _, pkt := range [][]byte{
			truncatedAfterCommunity(0),
			truncatedAfterCommunity(1),
			buildV2cTrap(fabricatedCommunity)[:len(fabricatedCommunity)+8],
		} {
			if _, err := r.decodePacket(pkt, "10.0.0.5"); err != nil {
				errs = append(errs, err.Error())
			}
		}
	})

	if len(errs) == 0 {
		t.Fatal("the malformed datagrams must exercise the error path")
	}
	haystacks := map[string]string{
		"logs/stdout/stderr": out,
		"decode errors":      strings.Join(errs, "\n"),
		"status":             r.status.LastError,
		"sink bodies":        strings.Join(sinkBodies, "\n"),
		"parser trace":       strings.Join(trace.snapshot(), "\n"),
	}
	for where, text := range haystacks {
		if strings.Contains(text, fabricatedCommunity) {
			t.Errorf("%s holds the community:\n%s", where, text)
		}
	}
	if len(sinkBodies) == 0 {
		t.Fatal("no trap reached the sink: the test proved nothing")
	}
	for _, body := range sinkBodies {
		if !strings.Contains(body, `"snmp_community_present":true`) {
			t.Errorf("published trap lost the presence flag: %s", body)
		}
	}
	if len(trace.snapshot()) == 0 {
		t.Fatal("the armed parser trace emitted nothing: the test proved nothing")
	}
}

func (s *recordingSink) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lines...)
}

// truncatedAfterCommunity builds a datagram whose community decodes and whose
// PDU tag is wrong for the version.
func truncatedAfterCommunity(version int) []byte {
	msg := berInt(version)
	msg = append(msg, berTLV(0x04, []byte(fabricatedCommunity))...)
	msg = append(msg, berTLV(0x02, []byte{0x01})...)
	return berTLV(0x30, msg)
}

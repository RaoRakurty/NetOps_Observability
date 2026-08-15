package collectors

// snmpv3_secfix_test.go — second-pass review regressions on the SNMPv3 poll
// trust boundary.
//
// H3: the priv msgFlag is read from the PACKET (attacker-controlled). A session
// that never negotiated privacy has no localized priv key, so honouring the
// flag walked decrypt into privKeyL[:16] on a nil slice — a remote panic from
// one forged/misconfigured UDP reply, on a bare worker goroutine that nothing
// recovered (process-wide outage). Locks: parseScoped refuses the flag,
// decrypt refuses a short key, and the poll fan-out survives a panicking
// worker (safego).
//
// M2: exchange discarded the echoed msgID/request-id/OID, so a stale
// retransmit or an off-path blind spoof was consumed as the current sample.
// Locks the v3 analogue of the v2c TestFirstVarbindRejectsMismatchedAndErroredReplies.

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// ---- H3: priv flag on a session without priv creds --------------------------

// TestH3ParseScopedRejectsPrivFlagWithoutPrivCreds forges a priv-flagged reply
// at a noAuthNoPriv and an authNoPriv session. Without the guard, parseScoped
// calls decrypt with an empty privKeyL and panics (which fails this test run);
// with it, both return an error and no panic.
func TestH3ParseScopedRejectsPrivFlagWithoutPrivCreds(t *testing.T) {
	for _, level := range []string{"noAuthNoPriv", "authNoPriv"} {
		t.Run(level, func(t *testing.T) {
			// The attacker mints a priv-flagged message. Worst case for
			// authNoPriv: the sender KNOWS the auth password (a compromised or
			// misconfigured agent — authSession shares it), so the HMAC verifies
			// and the packet reaches the priv branch.
			rx, _ := authSession(t, level, "SHA", "")
			as, attacker := authSession(t, "authPriv", "SHA", "AES")
			pkt := mintResponse(t, as, attacker, sampleScoped(as))

			out, err := rx.parseScoped(pkt)
			if err == nil {
				t.Fatalf("%s session accepted a priv-flagged reply (returned %d bytes)", level, len(out))
			}
			if !strings.Contains(err.Error(), "priv-flagged") {
				t.Fatalf("unexpected error (want the priv-flag refusal): %v", err)
			}
		})
	}
}

// TestH3DecryptRefusesShortPrivKey locks the defensive floor: even if a future
// caller forgets the parseScoped guard, decrypt itself must refuse a missing/
// short localized key instead of panicking on privKeyL[:16].
func TestH3DecryptRefusesShortPrivKey(t *testing.T) {
	for _, proto := range []string{"AES", "DES"} {
		t.Run(proto, func(t *testing.T) {
			s := &v3Session{creds: snmpCreds{
				Version: 3, Level: "authPriv",
				AuthProto: "SHA", AuthKey: "a", PrivProto: proto, PrivKey: "p",
			}} // privKeyL deliberately nil (never localized)
			ct := make([]byte, 16)
			if _, err := s.decrypt(s.creds, ct, make([]byte, 8)); err == nil {
				t.Fatalf("%s decrypt with nil privKeyL must error, not slice-panic", proto)
			}
		})
	}
}

// TestH3PollOnceSurvivesPanickingWorker proves the per-device poll workers run
// under safego: a panic in one device's poll body costs that device's cycle
// (recorded as an honest per-device error) — without the wrap the panic kills
// the whole test process, since the worker is a bare goroutine.
func TestH3PollOnceSurvivesPanickingWorker(t *testing.T) {
	c := NewSNMPMetrics(func() []Target {
		return []Target{{ID: "poisoned", Address: "127.0.0.1"}}
	}).(*metricsCollector)
	c.pollFn = func(context.Context, Target) deviceOutcome {
		panic("simulated poisoned SNMP reply")
	}

	done := make(chan struct{})
	go func() { defer close(done); c.pollOnce(context.Background()) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pollOnce did not complete after a worker panic")
	}
	st := c.Status()
	if !strings.Contains(st.LastError, "panic") {
		t.Fatalf("worker panic not surfaced in status (LastError=%q) — silent failure", st.LastError)
	}
}

// ---- shared fake agent -----------------------------------------------------

// fakeV3Reply is called with the msgID the client actually sent and must return
// the raw datagram(s) the fake agent answers with.
type fakeV3Reply func(t *testing.T, clientMsgID int) [][]byte

// runV3Exchange stands up a one-shot fake UDP agent and runs a single GET
// exchange (reqID 99, sysUpTime OID) against it with an established authNoPriv
// session, returning the exchange result.
func runV3Exchange(t *testing.T, reply fakeV3Reply) (byte, []byte, error) {
	t.Helper()
	oid := []int{1, 3, 6, 1, 2, 1, 1, 3, 0}
	cs, _ := authSession(t, "authNoPriv", "SHA", "")

	srv, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srv.Close()
	go func() {
		buf := make([]byte, 4096)
		n, addr, rerr := srv.ReadFrom(buf)
		if rerr != nil {
			return
		}
		mid, merr := v3MsgID(buf[:n])
		if merr != nil {
			return
		}
		for _, pkt := range reply(t, mid) {
			_, _ = srv.WriteTo(pkt, addr)
		}
	}()

	c, err := net.Dial("udp", srv.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	valTag, val, _, err := cs.exchange(c, 0xA0, oid, 99)
	return valTag, val, err
}

// mintGetResponse builds an authenticated authNoPriv GetResponse from the fake
// agent's side: msgID/reqID/OID as given, INTEGER value 42.
func mintGetResponse(t *testing.T, msgID, reqID int, oid []int) []byte {
	t.Helper()
	ss, creds := authSession(t, "authNoPriv", "SHA", "")
	ss.msgID = msgID
	vb := berTLV(0x30, berTLV(0x30, append(berOID(oid), berTLV(0x02, []byte{42})...)))
	scoped := buildScopedPDU(ss.engineID, "", buildPDU(0xA2, reqID, vb))
	return mintResponse(t, ss, creds, scoped)
}

// ---- M2: request-id / msgID / OID echo validation ---------------------------

// TestM2V3ExchangeValidatesReplyIdentity is the v3 analogue of the v2c
// TestFirstVarbindRejectsMismatchedAndErroredReplies: a reply that does not
// echo the request's msgID, request-id and (for a GET) OID is a stale
// retransmit or an off-path forgery and must be discarded, never consumed as
// the answer. The matching reply must still be accepted.
func TestM2V3ExchangeValidatesReplyIdentity(t *testing.T) {
	oid := []int{1, 3, 6, 1, 2, 1, 1, 3, 0}
	otherOID := []int{1, 3, 6, 1, 2, 1, 1, 5, 0}
	repeat := func(pkt []byte) [][]byte { return [][]byte{pkt, pkt, pkt, pkt} } // outlast the stale-read loop

	cases := []struct {
		name    string
		reply   fakeV3Reply
		wantErr bool
	}{
		{"matching reply accepted", func(t *testing.T, mid int) [][]byte {
			return [][]byte{mintGetResponse(t, mid, 99, oid)}
		}, false},
		{"mismatched request-id rejected", func(t *testing.T, mid int) [][]byte {
			return repeat(mintGetResponse(t, mid, 7, oid))
		}, true},
		{"mismatched msgID rejected", func(t *testing.T, mid int) [][]byte {
			return repeat(mintGetResponse(t, mid+1, 99, oid))
		}, true},
		{"mismatched GET OID rejected", func(t *testing.T, mid int) [][]byte {
			return repeat(mintGetResponse(t, mid, 99, otherOID))
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			valTag, val, err := runV3Exchange(t, tc.reply)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("forged/stale reply was accepted as a sample (tag %#x val %v)", valTag, val)
				}
				if !errors.Is(err, errStaleResponse) {
					// A timeout after discarding every stale copy is also a
					// correct refusal; anything else is unexpected.
					var ne net.Error
					if !errors.As(err, &ne) || !ne.Timeout() {
						t.Fatalf("unexpected error kind: %v", err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("valid reply rejected: %v", err)
			}
			if valTag != 0x02 || len(val) != 1 || val[0] != 42 {
				t.Fatalf("valid reply mangled: tag %#x val %v", valTag, val)
			}
		})
	}
}

// TestH3ExchangeSurvivesPrivFlaggedReply drives the full poll read path against
// a fake agent that answers a plain authNoPriv GET with a priv-flagged
// datagram: before the fix this was a remote panic (nil priv key slice), now it
// is an error and the caller lives.
func TestH3ExchangeSurvivesPrivFlaggedReply(t *testing.T) {
	oid := []int{1, 3, 6, 1, 2, 1, 1, 3, 0}
	_, _, err := runV3Exchange(t, func(t *testing.T, mid int) [][]byte {
		// Attacker with auth-key knowledge (worst case) flips on privacy.
		as, _ := authSession(t, "authPriv", "SHA", "AES")
		as.msgID = mid
		scoped := buildScopedPDU(as.engineID, "", buildPDU(0xA2, 99, berTLV(0x30, berTLV(0x30, append(berOID(oid), berTLV(0x05, nil)...)))))
		return [][]byte{mintResponse(t, as, as.creds, scoped)}
	})
	if err == nil {
		t.Fatal("priv-flagged reply on an authNoPriv session must be refused")
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package probercontrol

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A record verifies only under the key that signed it AND as the kind it was
// signed as; changing one byte of the payload or the signature fails.
func TestSealOpenBindsKeyKindAndBytes(t *testing.T) {
	r := ring()
	raw, err := r.Seal(KindSwitches, []byte(`{"v":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := r.Open(KindSwitches, raw); err != nil || string(got) != `{"v":2}` {
		t.Fatalf("good record: %q %v", got, err)
	}
	if _, err := r.Open(KindTargets, raw); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a switches record must not verify as targets: %v", err)
	}
	other := NewKeyring(&keyVal{v: strings.Repeat("z", 43)}, clock(t0))
	if _, err := other.Open(KindSwitches, raw); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("another key must not verify it: %v", err)
	}
	tampered := strings.Replace(raw, `{\"v\":2}`, `{\"v\":3}`, 1)
	if tampered == raw {
		t.Fatalf("the payload is embedded as an escaped string; test setup is wrong: %s", raw)
	}
	if _, err := r.Open(KindSwitches, tampered); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a tampered payload must not verify: %v", err)
	}
	var env envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatal(err)
	}
	flip := []byte(env.Sig)
	if flip[0] == 'a' {
		flip[0] = 'b'
	} else {
		flip[0] = 'a'
	}
	env.Sig = string(flip)
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Open(KindSwitches, string(b)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a flipped signature must not verify: %v", err)
	}
	if _, err := r.Open(KindSwitches, `{"v":2,"switches":{}}`); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("a bare record is unsigned: %v", err)
	}
	if _, err := r.Open(KindSwitches, `{"v":1,"payload":"{\"v\":2}","sig":"not-hex"}`); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a non-hex signature is bad: %v", err)
	}
	// The pre-fix envelope (payload as a raw JSON object, no version) is not
	// this envelope: refused as unsigned, which reads OFF.
	if _, err := r.Open(KindSwitches, `{"payload":{"v":2},"sig":"00"}`); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("a versionless raw-object envelope must be refused: %v", err)
	}
}

// Regression (review of #310): every payload byte survives the envelope. The
// RawMessage envelope HTML-escaped &, <, > and compacted whitespace, so the
// prober verified different bytes than the api signed and refused the record.
func TestSealOpenIsByteExactForAnyPayload(t *testing.T) {
	r := ring()
	big := `{"targets":[` + strings.Repeat(`{"id":"dem-x","addr":"203.0.113.1","site":"Branch 40 & HQ"},`, 2000) + `{}]}`
	for name, payload := range map[string]string{
		"ampersand query":  `{"url":"https://a/?x=1&y=2"}`,
		"whitespace":       "{\"a\": 1,\n\t\"b\" : [ 1 , 2 ] }",
		"angle brackets":   `{"n":"<b>bold</b>"}`,
		"unicode":          `{"site":"Zürich — 東京 🚀","esc":"é "}`,
		"escaped quotes":   `{"q":"say \"hi\" \\ there","u":"é "}`,
		"compact baseline": `{"a":1}`,
		"large":            big,
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := r.Seal(KindTargets, []byte(payload))
			if err != nil {
				t.Fatal(err)
			}
			got, err := r.Open(KindTargets, raw)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if string(got) != payload {
				t.Fatalf("payload changed in transit:\n got %q\nwant %q", got, payload)
			}
		})
	}
	// Signed bytes that are not JSON are never handed to a reader.
	k := NewKeyring(&keyVal{v: testKey}, clock(t0))
	notJSON := `not json`
	env, err := json.Marshal(envelope{V: envelopeVersion, Payload: notJSON, Sig: hex.EncodeToString(mac(testKey, KindTargets, []byte(notJSON)))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Open(KindTargets, string(env)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("signed non-JSON must be refused: %v", err)
	}
}

// No key, an unreadable key, or a key too short to be a generated secret: the
// api seals nothing and the prober opens nothing.
func TestNoUsableKeyRefusesBothWays(t *testing.T) {
	for name, src := range map[string]KeySource{
		"nil source": nil,
		"unreadable": &keyVal{err: errors.New("credential has never loaded")},
		"too short":  &keyVal{v: "short"},
	} {
		t.Run(name, func(t *testing.T) {
			k := NewKeyring(src, clock(t0))
			if _, err := k.Seal(KindSwitches, []byte(`{}`)); !errors.Is(err, ErrNoKey) {
				t.Fatalf("seal: %v", err)
			}
			raw, err := ring().Seal(KindSwitches, []byte(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := k.Open(KindSwitches, raw); !errors.Is(err, ErrNoKey) {
				t.Fatalf("open: %v", err)
			}
		})
	}
	var nilRing *Keyring
	if _, err := nilRing.Seal(KindSwitches, []byte(`{}`)); !errors.Is(err, ErrNoKey) {
		t.Fatalf("nil keyring: %v", err)
	}
}

// Rotation: after the prober's key file changes, a record signed under the
// PREVIOUS key still verifies for RotationGrace, and is refused after it.
func TestRotationAcceptsThePreviousKeyForTheGraceWindow(t *testing.T) {
	now := t0
	src := &keyVal{v: testKey}
	prober := NewKeyring(src, func() time.Time { return now })
	raw, err := NewKeyring(&keyVal{v: testKey}, clock(t0)).Seal(KindSwitches, []byte(`{"v":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prober.Open(KindSwitches, raw); err != nil {
		t.Fatalf("before rotation: %v", err)
	}
	src.v = strings.Repeat("n", 43) // the prober's file is re-rendered first
	if _, err := prober.Open(KindSwitches, raw); err != nil {
		t.Fatalf("inside the grace window the old key must verify: %v", err)
	}
	now = now.Add(RotationGrace + time.Second)
	if _, err := prober.Open(KindSwitches, raw); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("after the grace window the old key must be refused: %v", err)
	}
	fresh, err := NewKeyring(&keyVal{v: strings.Repeat("n", 43)}, clock(t0)).Seal(KindSwitches, []byte(`{"v":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prober.Open(KindSwitches, fresh); err != nil {
		t.Fatalf("the new key verifies: %v", err)
	}
}

// The reader names each signature failure, and every one reads OFF — even
// with the prober's own environment saying on.
func TestReaderSignatureReasons(t *testing.T) {
	good, err := json.Marshal(Record{V: SchemaVersion, IssuedAt: t0, Switches: map[string]bool{EnvTraceroute: true}})
	if err != nil {
		t.Fatal(err)
	}
	forged, err := NewKeyring(&keyVal{v: strings.Repeat("x", 43)}, clock(t0)).Seal(KindSwitches, good)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		ring *Keyring
		val  string
		want Decision
	}{
		{"forged under another key", ring(), forged, Decision{false, ReasonBadSignature}},
		{"unsigned record", ring(), string(good), Decision{false, ReasonUnsigned}},
		{"prober holds no key", NewKeyring(nil, clock(t0)), forged, Decision{false, ReasonNoKey}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kv := newKV()
			kv.vals[Key] = c.val
			r := NewReader(kv, c.ring, envOf(map[string]string{EnvTraceroute: "true"}), clock(t0), nil)
			if got := r.Decide(context.Background(), EnvTraceroute); got != c.want {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

// The api with no key publishes NOTHING (never an unsigned record) and says so
// once; the recovery is logged once too. A transport failure is not repeated
// here (the transport counts and logs it).
func TestPublisherWithoutKeyPublishesNothingAndSaysSo(t *testing.T) {
	kv := newKV()
	src := &keyVal{err: errors.New("credential has never loaded")}
	var lines []string
	logf := func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }
	p := NewPublisher(kv, func(string) bool { return true }, NewKeyring(src, clock(t0)), clock(t0), logf)
	for i := 0; i < 3; i++ {
		p.noteErr(p.PublishOnce(context.Background()))
	}
	if len(kv.vals) != 0 {
		t.Fatalf("nothing may be published without a key: %v", kv.vals)
	}
	src.v, src.err = testKey, nil
	p.noteErr(p.PublishOnce(context.Background()))
	if kv.vals[Key] == "" {
		t.Fatal("with the key back the record is published")
	}
	kv.setErr = errors.New("NOAUTH")
	p.noteErr(p.PublishOnce(context.Background()))
	if len(lines) != 2 || !strings.Contains(lines[0], "NOT being published") || !strings.Contains(lines[1], "again") {
		t.Fatalf("lines = %q", lines)
	}
}

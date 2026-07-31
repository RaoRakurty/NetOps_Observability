package sealing

// vrl_parity_test.go — the test that makes two implementations of one cipher
// safe to ship.
//
// Sealing runs at the edge in VRL; unsealing runs here in Go. Nothing in the
// type system connects them. If they ever disagree — a different MAC input, a
// different base64 alphabet, a padding byte — the failure is silent at write
// time and permanent at read time: tenants accumulate tokens that no longer
// open, and nobody finds out until someone tries to reveal one.
//
// So this test runs the REAL pinned Vector binary over the REAL generated VRL,
// and unseals what it produces with the production Go path. No VRL emulator, no
// hand-written expected string: those would only prove that my model of VRL
// agrees with itself.

import (
	"bytes"
	"context"
	"crypto/aes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// vectorImage is the image pinned in deployment/docker/docker-compose.yml. It
// is pinned by digest THERE; the tag is enough here because a mismatch shows up
// as a parity failure, which is exactly the signal this test exists to give.
const vectorImage = "timberio/vector:0.40.0-alpine"

// runVRL executes a VRL program against one event, returning the result.
func runVRL(t *testing.T, program string, event map[string]any) map[string]any {
	t.Helper()
	return runVRLBatch(t, program, []map[string]any{event})[0]
}

// runVRLBatch executes a VRL program against several events in ONE Vector
// invocation, returning a result per input event in order.
//
// Batching is not premature optimisation: each container start costs ~9s, so a
// per-case invocation turned this file into 90s of Docker startup and nothing
// else. A slow test gets skipped, and a skipped parity test is the same as not
// having one.
func runVRLBatch(t *testing.T, program string, events []map[string]any) []map[string]any {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("SKIPPED: docker not available — VRL/Go cipher parity is UNVERIFIED in this run")
	}
	// `docker image inspect` rather than a pull: a test must not silently drag
	// 185 MB over the network on a developer's laptop.
	if err := exec.Command("docker", "image", "inspect", vectorImage).Run(); err != nil {
		t.Skipf("SKIPPED: %s not present locally (docker pull %s) — cipher parity UNVERIFIED",
			vectorImage, vectorImage)
	}

	dir := t.TempDir()
	progPath := filepath.Join(dir, "prog.vrl")
	evPath := filepath.Join(dir, "event.json")

	// Two adjustments, both harness-only:
	//   - the generator emits `$$` where a literal `$` is wanted because Vector
	//     un-escapes during CONFIG interpolation; the `vrl` CLI does not
	//     interpolate, so undo it or we would be testing a string the router
	//     never executes;
	//   - the CLI prints the program's RESULT, so a trailing `.` is appended to
	//     yield the event. In a real remap the event is returned implicitly.
	src := strings.ReplaceAll(program, "$$", "$") + "\n.\n"
	if err := os.WriteFile(progPath, []byte(src), 0o600); err != nil {
		t.Fatalf("write program: %v", err)
	}
	var buf strings.Builder
	for _, e := range events {
		ev, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal event: %v", err)
		}
		buf.Write(ev)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(evPath, []byte(buf.String()), 0o600); err != nil {
		t.Fatalf("write events: %v", err)
	}

	cmd := exec.Command("docker", "run", "-i", "--rm",
		"-v", dir+":/w:ro", vectorImage,
		"vrl", "-p", "/w/prog.vrl", "-i", "/w/event.json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("vector vrl failed: %v\nprogram:\n%s\noutput:\n%s", err, program, out)
	}

	// The CLI prints an info banner, then one JSON object per input event.
	var results []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		var got map[string]any
		if json.Unmarshal([]byte(line), &got) == nil && got != nil {
			results = append(results, got)
		}
	}
	if len(results) != len(events) {
		t.Fatalf("expected %d events back, got %d\nprogram:\n%s\noutput:\n%s",
			len(events), len(results), src, out)
	}
	return results
}

// sealedKeysFor asks the PROVIDER for edge material, exactly as the router's
// secret backend does, and encodes it the way that backend serves it. Deriving
// the keys independently here would let the real delivery path break while the
// parity test kept passing.
func sealedKeysFor(t *testing.T, p CryptoProvider, tenant string) (sealB64, macB64 string, version int) {
	t.Helper()
	m, err := p.EdgeKey(context.Background(), tenant)
	if err != nil {
		t.Fatalf("edge key: %v", err)
	}
	// Padded standard base64: VRL's decode_base64 rejects unpadded input.
	return base64.StdEncoding.EncodeToString(m.SealKey),
		base64.StdEncoding.EncodeToString(m.MACKey), m.Version
}

// injectSecrets replaces the SECRET[…] references with literals, standing in for
// Vector's config-load interpolation (the `vrl` CLI does not interpolate).
func injectSecrets(program, tenant, sealB64, macB64 string) string {
	return strings.NewReplacer(
		EdgeSecretRef(EdgeSealBackend, tenant), sealB64,
		EdgeSecretRef(EdgeMACBackend, tenant), macB64,
	).Replace(program)
}

// TestVRLSealsWhatGoUnseals is the parity contract: Vector seals, Go opens it.
func TestVRLSealsWhatGoUnseals(t *testing.T) {
	p, _ := newProvider("acme")
	ctx := context.Background()
	c := Context{Tenant: "acme", ProcessorID: "proc-1", Field: "message", DataType: "card"}

	prog, err := SealVRL(EdgeSealSpec{Context: c, KeyVersion: 1, Path: ".message"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	sealB64, macB64, _ := sealedKeysFor(t, p, "acme")

	plaintexts := []string{
		"4111111111111111",
		"jsmith@example.org",
		"café-naïve — multibyte ✓",
		`quotes " and \ backslash and $dollar`,
		strings.Repeat("x", 2048),
	}
	events := make([]map[string]any, 0, len(plaintexts))
	for _, pt := range plaintexts {
		events = append(events, map[string]any{"message": pt})
	}
	results := runVRLBatch(t, injectSecrets(prog, "acme", sealB64, macB64), events)

	for i, plaintext := range plaintexts {
		got := results[i]
		sealed, _ := got["message"].(string)
		if !IsSealed(sealed) {
			t.Errorf("[%d] edge did not seal the field: %q", i, sealed)
			continue
		}
		if strings.Contains(sealed, plaintext) {
			t.Errorf("[%d] EDGE TOKEN LEAKS PLAINTEXT: %q", i, sealed)
		}
		// A VRL local must never surface as an event field — one of them is the
		// plaintext, and an event field gets indexed.
		for k := range got {
			if strings.HasPrefix(k, "_cx_seal") {
				t.Errorf("[%d] edge left an intermediate on the event: %q", i, k)
			}
		}
		opened, err := p.Unseal(ctx, c, sealed)
		if err != nil {
			t.Errorf("[%d] Go could not unseal a token the EDGE produced: %v\ntoken: %s", i, err, sealed)
			continue
		}
		if opened != plaintext {
			t.Errorf("[%d] parity: edge sealed %q, Go read %q", i, plaintext, opened)
		}
	}
}

// TestVRLLeavesAbsentAndEmptyFieldsAlone: a rule whose field is missing must not
// invent one, and an empty string must not become a token wrapping nothing.
func TestVRLLeavesAbsentAndEmptyFieldsAlone(t *testing.T) {
	p, _ := newProvider("acme")
	c := Context{Tenant: "acme", ProcessorID: "proc-1", Field: "ssn", DataType: "ssn"}
	prog, err := SealVRL(EdgeSealSpec{Context: c, KeyVersion: 1, Path: ".ssn"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	sealB64, macB64, _ := sealedKeysFor(t, p, "acme")
	prog = injectSecrets(prog, "acme", sealB64, macB64)

	res := runVRLBatch(t, prog, []map[string]any{
		{"message": "nothing sensitive"},
		{"ssn": ""},
	})
	if v, ok := res[0]["ssn"]; ok {
		t.Errorf("sealing invented a field that was not present: %v", v)
	}
	if res[1]["ssn"] != "" {
		t.Errorf("empty value became %v — an empty field has nothing to protect", res[1]["ssn"])
	}
}

// TestVRLSealsNestedPaths — real sensitive values live in nested objects (a trap
// MAC under .fields.mac), not only in .message.
func TestVRLSealsNestedPaths(t *testing.T) {
	p, _ := newProvider("acme")
	c := Context{Tenant: "acme", ProcessorID: "proc-9", Field: "fields.ssn", DataType: "ssn"}
	prog, err := SealVRL(EdgeSealSpec{Context: c, KeyVersion: 1, Path: ".fields.ssn"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	sealB64, macB64, _ := sealedKeysFor(t, p, "acme")

	got := runVRL(t, injectSecrets(prog, "acme", sealB64, macB64),
		map[string]any{"fields": map[string]any{"ssn": "123-45-6789", "host": "r1"}})

	fields, ok := got["fields"].(map[string]any)
	if !ok {
		t.Fatalf("fields object lost: %#v", got)
	}
	if fields["host"] != "r1" {
		t.Fatalf("sealing disturbed a sibling field: %#v", fields)
	}
	sealed, _ := fields["ssn"].(string)
	opened, err := p.Unseal(context.Background(), c, sealed)
	if err != nil {
		t.Fatalf("unseal nested: %v", err)
	}
	if opened != "123-45-6789" {
		t.Fatalf("got %q", opened)
	}
}

// TestVRLTokenIsBoundToItsContext — the edge must bind context too, or a token
// sealed by one processor could be replayed into another.
func TestVRLTokenIsBoundToItsContext(t *testing.T) {
	p, _ := newProvider("acme")
	c := Context{Tenant: "acme", ProcessorID: "proc-1", Field: "message", DataType: "card"}
	prog, err := SealVRL(EdgeSealSpec{Context: c, KeyVersion: 1, Path: ".message"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	sealB64, macB64, _ := sealedKeysFor(t, p, "acme")
	got := runVRL(t, injectSecrets(prog, "acme", sealB64, macB64),
		map[string]any{"message": "4111111111111111"})
	sealed, _ := got["message"].(string)

	other := c
	other.ProcessorID = "proc-2"
	if _, err := p.Unseal(context.Background(), other, sealed); err == nil {
		t.Fatal("an edge-sealed token opened under a different processor — context is not bound at the edge")
	}
}

// TestCounterModeMatchesTheEdge pins the counter mode with a GOLDEN VECTOR
// captured from the pinned Vector binary.
//
// The parity tests above need Docker; this one does not, so the property they
// protect survives every environment. It exists because Go's stdlib CTR and
// VRL's CTR agree on the first 16 bytes and diverge after — a difference that
// passes any round-trip test written entirely in Go, and corrupts every sealed
// value longer than one AES block in production.
//
// Vector 0.40.0, key = bytes 0x00..0x1f, iv = 16 × 0xff, plaintext = 64 × 'A'.
// To regenerate, run the program in the comment below through `vector vrl`.
//
//	key = decode_base64!("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
//	iv  = decode_base64!("/////////////////////w==")
//	encode_base64(encrypt!("AAAA…(64)…", "AES-256-CTR", key, iv: iv))
func TestCounterModeMatchesTheEdge(t *testing.T) {
	const goldenFromVector = "qNilXA3mMZsSxlA6HM4Wr+e6mh28oTxaGbx3YDb9vp5Y7WoSR97cSGtQxZIh709mVM9r0b7tzvaSHbPPh25DSw=="

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = 0xff
	}
	plaintext := bytes.Repeat([]byte("A"), 64)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	got := base64.StdEncoding.EncodeToString(ctrXOR(block, iv, plaintext))
	if got != goldenFromVector {
		t.Fatalf("counter mode diverged from the edge — every sealed value over 16 bytes would be unreadable\n got: %s\nwant: %s", got, goldenFromVector)
	}

	// And the mode is its own inverse, across a block boundary.
	if rt := ctrXOR(block, iv, ctrXOR(block, iv, plaintext)); !bytes.Equal(rt, plaintext) {
		t.Fatal("ctrXOR is not self-inverse")
	}
}

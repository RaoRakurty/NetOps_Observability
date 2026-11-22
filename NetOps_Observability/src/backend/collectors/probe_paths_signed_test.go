// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

// probe_paths_signed_test.go — the prober's path sets are signed on every
// shared channel, and every reader verifies them (tracker 475). Before this,
// any service holding the Valkey password could SET netops:probe:paths:<v>
// with a path naming any tenant and any hops: the tenant decided who saw it,
// and the hops oriented the engine's direction enrichment.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/probercontrol"
)

type staticKey string

func (k staticKey) Value() (string, error) { return string(k), nil }

const testPathKey = staticKey("collectors-test-key-0123456789abcdefghijklmn")

func testPathRing() *probercontrol.Keyring { return probercontrol.NewKeyring(testPathKey, time.Now) }

func testPathVerifier(acceptUnsigned bool) *probercontrol.ResultVerifier {
	return probercontrol.NewResultVerifier(testPathRing(), probercontrol.KindProbePaths, ProbePathsMaxAge,
		time.Now, func() bool { return acceptUnsigned }, nil)
}

// sealPathSet signs body as vantage's path set with the test key.
func sealPathSet(t *testing.T, vantage string, body []byte) string {
	t.Helper()
	raw, err := NewPathSealer(testPathRing())(vantage, body)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return raw
}

func pathSetJSON(t *testing.T, ps ...PathResult) []byte {
	t.Helper()
	b, err := json.Marshal(ps)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A forged, unsigned set in one vantage's key contributes nothing; the signed
// vantage beside it is read as usual.
func TestFetchProbePathsAllRefusesAnUnsignedVantage(t *testing.T) {
	forged := pathSetJSON(t, PathResult{VantageID: "van-a", TenantID: "t_victim", Dst: "10.6.6.6", TS: time.Now().UTC()})
	good := pathSetJSON(t, PathResult{VantageID: "van-b", TenantID: "t_acme", Dst: "10.0.0.1", TS: time.Now().UTC()})
	fakeRedis(t,
		respArray("van-a", "van-b"),
		respBulk(string(forged)),
		respBulk(sealPathSet(t, "van-b", good)),
	)
	v := testPathVerifier(false)
	paths, err := FetchProbePathsAll(context.Background(), v)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(paths) != 1 || paths[0].Dst != "10.0.0.1" {
		t.Fatalf("paths = %+v, want only the signed vantage's path", paths)
	}
	if v.Count(probercontrol.ReasonUnsigned) != 1 || v.Count(probercontrol.ReasonVerified) != 1 {
		t.Fatalf("outcomes not counted: unsigned=%d verified=%d",
			v.Count(probercontrol.ReasonUnsigned), v.Count(probercontrol.ReasonVerified))
	}
}

// A signed set that claims another vantage on a path is that path's signer's
// word: the path is attributed to the signed vantage.
func TestFetchProbePathsAllAttributesPathsToTheSignedVantage(t *testing.T) {
	body := pathSetJSON(t, PathResult{VantageID: "van-z", Dst: "10.0.0.1", TS: time.Now().UTC()})
	fakeRedis(t, respArray("van-a"), respBulk(sealPathSet(t, "van-a", body)))
	paths, err := FetchProbePathsAll(context.Background(), testPathVerifier(false))
	if err != nil || len(paths) != 1 {
		t.Fatalf("drain: %+v %v", paths, err)
	}
	if paths[0].VantageID != "van-a" {
		t.Fatalf("path attributed to %q, want the signed vantage van-a", paths[0].VantageID)
	}
}

// A record moved from one vantage's key into another's is refused.
func TestFetchProbePathsAllRefusesARecordInAnotherVantagesKey(t *testing.T) {
	body := pathSetJSON(t, PathResult{Dst: "10.0.0.1", TS: time.Now().UTC()})
	fakeRedis(t, respArray("van-b"), respBulk(sealPathSet(t, "van-a", body)), respBulk(""))
	v := testPathVerifier(false)
	paths, err := FetchProbePathsAll(context.Background(), v)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(paths) != 0 || v.Count(probercontrol.ReasonWrongVantage) != 1 {
		t.Fatalf("a copied record was accepted: %+v (wrong_vantage=%d)", paths, v.Count(probercontrol.ReasonWrongVantage))
	}
}

func TestFetchProbePathsAllWithoutAVerifierReadsNothing(t *testing.T) {
	if _, err := FetchProbePathsAll(context.Background(), nil); err == nil {
		t.Fatal("a nil verifier read the channel")
	}
}

// The legacy switch accepts the unsigned form a pre-475 prober writes, and
// keeps today's attribution (the slot's vantage) for it.
func TestFetchProbePathsAllLegacySwitchAcceptsUnsigned(t *testing.T) {
	body := pathSetJSON(t, PathResult{Dst: "10.0.0.1", TS: time.Now().UTC()})
	fakeRedis(t, respArray("van-a"), respBulk(string(body)))
	v := testPathVerifier(true)
	paths, err := FetchProbePathsAll(context.Background(), v)
	if err != nil || len(paths) != 1 || paths[0].VantageID != "van-a" {
		t.Fatalf("legacy acceptance: %+v %v", paths, err)
	}
	if v.Count(probercontrol.ReasonUnsignedAccepted) != 1 {
		t.Fatal("an accepted unsigned set was not counted as such")
	}
}

func TestReadProbePathsFileVerifies(t *testing.T) {
	dir := t.TempDir()
	signed := filepath.Join(dir, "signed.json")
	body := pathSetJSON(t, PathResult{Dst: "10.0.0.1", TS: time.Now().UTC()})
	if err := os.WriteFile(signed, []byte(sealPathSet(t, "prober", body)), 0o600); err != nil {
		t.Fatal(err)
	}
	paths, err := ReadProbePathsFile(signed, testPathVerifier(false))
	if err != nil || len(paths) != 1 || paths[0].VantageID != "prober" {
		t.Fatalf("signed file: %+v %v", paths, err)
	}
	unsigned := filepath.Join(dir, "unsigned.json")
	if err := os.WriteFile(unsigned, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if paths, err := ReadProbePathsFile(unsigned, testPathVerifier(false)); err != nil || paths != nil {
		t.Fatalf("an unsigned file was believed: %+v %v", paths, err)
	}
	if paths, err := ReadProbePathsFile(filepath.Join(dir, "absent.json"), testPathVerifier(false)); err != nil || paths != nil {
		t.Fatalf("an absent file: %+v %v", paths, err)
	}
}

// The prober writes a signed envelope to every shared channel, and with no
// signer it writes nothing there at all.
func TestPersistSignsTheSharedFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "paths.json")
	t.Setenv("REDIS_HOST", "")
	t.Setenv("PROBE_PATHS_FILE", file)
	t.Setenv("PROBER_ID", "prober-t")
	t.Setenv("PROBE_PATHS_PUSH_URL", "")

	unsigned := &pathRegistry{m: map[string]PathResult{}}
	unsigned.set(PathResult{TenantID: "t_acme", Dst: "10.0.0.1", TS: time.Now().UTC()})
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("a registry with no signer wrote the shared file: %v", err)
	}

	reg := &pathRegistry{m: map[string]PathResult{}}
	reg.SetSealer(NewPathSealer(testPathRing()))
	reg.set(PathResult{TenantID: "t_acme", Dst: "10.0.0.1", TS: time.Now().UTC()})
	for _, f := range []string{file, file + ".prober-t"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if strings.Contains(string(raw), `"dst":"10.0.0.1"`) && !strings.Contains(string(raw), `"sig"`) {
			t.Fatalf("%s holds an unsigned path set: %s", f, raw)
		}
		paths, err := ReadProbePathsFile(f, testPathVerifier(false))
		if err != nil || len(paths) != 1 || paths[0].TenantID != "t_acme" || paths[0].VantageID != "prober-t" {
			t.Fatalf("%s did not verify as the prober's set: %+v %v", f, paths, err)
		}
	}
}

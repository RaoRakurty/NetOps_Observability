package cloud

// Connector-provenance tests (#105): the data-mode badge must be derived from
// the collection stamp the live poller writes, default-closed — no stamp, an
// unknown mode, or a resource-less topology file must never read "live".

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFixture(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestConnectors_StampDerivesKindDefaultClosed(t *testing.T) {
	dir := t.TempDir()
	// Live-poller-stamped inventory → live.
	writeFixture(t, dir, "aws.json", `{"provider":"aws","account_id":"111",
		"collection":{"mode":"live_poller","collected_at":"2026-07-15T08:00:00Z"},
		"resources":[{"resource_id":"i-1","private_ips":["10.0.0.1"]}]}`)
	// No stamp → fixture (the honest default).
	writeFixture(t, dir, "azure.json", `{"provider":"azure","account_id":"222",
		"resources":[{"resource_id":"vm-1","private_ips":["10.1.0.1"]}]}`)
	// Unrecognised mode → fixture (zero-trust on the stamp).
	writeFixture(t, dir, "gcp.json", `{"provider":"gcp","account_id":"333",
		"collection":{"mode":"totally-live-trust-me","collected_at":"2026-07-15T08:00:00Z"},
		"resources":[{"resource_id":"vm-2","private_ips":["10.2.0.1"]}]}`)
	// Topology file: valid provider header but no resources → not a connector.
	writeFixture(t, dir, "aws-topology.json", `{"provider":"aws","account_id":"111",
		"vpcs":[{"id":"vpc-1","cidr":"10.0.0.0/16"}]}`)
	// Unsupported provider → skipped, same grace as ListResources.
	writeFixture(t, dir, "oracle.json", `{"provider":"oracle","account_id":"444",
		"resources":[{"resource_id":"x"}]}`)

	conns, err := NewFixtureProvider(dir).Connectors(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byProvider := map[Provider]ConnectorInfo{}
	for _, c := range conns {
		byProvider[c.Provider] = c
	}
	if len(conns) != 3 {
		t.Fatalf("want 3 connectors (aws/azure/gcp), got %d: %+v", len(conns), conns)
	}
	aws := byProvider[AWS]
	if aws.Kind != ConnectorKindLive || aws.AccountID != "111" || aws.ResourceCount != 1 {
		t.Fatalf("stamped aws file must be live: %+v", aws)
	}
	if want := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC); !aws.CollectedAt.Equal(want) {
		t.Fatalf("collected_at not parsed: %v", aws.CollectedAt)
	}
	if got := byProvider[Azure].Kind; got != ConnectorKindFixture {
		t.Fatalf("unstamped file must be fixture, got %q", got)
	}
	gcp := byProvider[GCP]
	if gcp.Kind != ConnectorKindFixture || !gcp.CollectedAt.IsZero() {
		t.Fatalf("unknown mode must stay fixture with no collected_at: %+v", gcp)
	}
}

func TestConnectors_EmptyDirYieldsNone(t *testing.T) {
	conns, err := NewFixtureProvider(t.TempDir()).Connectors(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 0 {
		t.Fatalf("empty dir must yield no connectors, got %+v", conns)
	}
}

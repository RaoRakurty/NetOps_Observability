package licence

// keys_release_test.go — the embedded-key guard (tracker 259, owner decision
// 2026-09-05).
//
// The owner decision this implements: "the current LAB signing key must never be
// promoted to production", and a release must refuse when the only key the build
// embeds is marked lab. A licence signed with the lab key VERIFIES — that is what
// the lab key is for — so no verification test can tell the two apart. The only
// place the difference is visible is the set of keys the binary carries, which is
// what these tests pin.
//
// This is an in-package test on purpose: releaseReady's negative and positive
// answers must both be exercised, and the positive one must not require inventing
// a production key in the shipped set.

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

// testKey builds a syntactically real key from a deterministic seed. Its bytes
// are irrelevant here — only the labels are under test.
func testKey(t *testing.T, seedByte byte, role, purpose string) PublicKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("no public half")
	}
	return NewPublicKeyWithPurpose(pub, role, purpose, "test key")
}

// TestEmbeddedKeysCarryAKnownPurpose is the label-integrity test: every shipped
// key states what it may sign, from the closed vocabulary. An unlabelled entry
// would silently become "not production" and the reason would be an omission
// rather than a decision.
func TestEmbeddedKeysCarryAKnownPurpose(t *testing.T) {
	keys := EmbeddedKeys()
	if len(keys) == 0 {
		t.Fatal("the build trusts no signing key at all")
	}
	if len(keys) > 2 {
		t.Errorf("the build trusts %d keys; the rotation rule allows at most two (current + previous)", len(keys))
	}
	for _, k := range keys {
		switch k.Purpose {
		case PurposeLab, PurposeProduction:
		default:
			t.Errorf("embedded key %s (role %s) has purpose %q, want %q or %q",
				k.ID, k.Role, k.Purpose, PurposeLab, PurposeProduction)
		}
		if k.Note == "" {
			t.Errorf("embedded key %s carries no note saying where it came from", k.ID)
		}
	}
}

// TestLabKeyIsLabelledLab pins the identity of the key shipped today. If this
// fails, either the lab key was relabelled — which is the promotion the owner
// decision forbids — or it was replaced without following the rotation
// procedure in keys.go.
func TestLabKeyIsLabelledLab(t *testing.T) {
	const labKeyID = "0edbb619f9b318e0"
	var found bool
	for _, k := range EmbeddedKeys() {
		if k.ID != labKeyID {
			continue
		}
		found = true
		if k.Purpose != PurposeLab {
			t.Fatalf("the lab key %s is labelled %q. The lab private key lives on the owner's lab host "+
				"and must NEVER be promoted to production (docs/runbooks/licence-signing-ceremony.md §1); "+
				"a production key comes from the ceremony, not from relabelling this one", labKeyID, k.Purpose)
		}
	}
	if !found {
		t.Skipf("lab key %s is no longer embedded — the production key has presumably landed; "+
			"drop this test with the last lab entry", labKeyID)
	}
}

// TestEmbeddedSetIsNotReleaseReadyYet records the state of the world: no
// production key exists, so ReleaseReady refuses. It is a tripwire, not an
// aspiration — when the ceremony happens and a PurposeProduction key is added,
// this test fails and is DELETED, which is the moment the release guard starts
// answering yes.
func TestEmbeddedSetIsNotReleaseReadyYet(t *testing.T) {
	err := ReleaseReady()
	if err == nil {
		t.Fatal("ReleaseReady() says this build is release-ready. If the production signing " +
			"ceremony has happened (docs/runbooks/licence-signing-ceremony.md), delete this test " +
			"and drop the lab entry from keys.go per the rotation procedure. If it has not, a key " +
			"was mislabelled PurposeProduction and that must be reverted.")
	}
	if !errors.Is(err, ErrNoProductionKey) {
		t.Fatalf("ReleaseReady() returned %v, want an ErrNoProductionKey", err)
	}
	if !strings.Contains(err.Error(), "licence-signing-ceremony") {
		t.Errorf("the refusal does not point at the runbook that resolves it: %v", err)
	}
}

// TestReleaseReadyRequiresAProductionKey exercises the guard itself, in both
// directions, on sets that are not the shipped one.
func TestReleaseReadyRequiresAProductionKey(t *testing.T) {
	cases := []struct {
		name    string
		keys    []PublicKey
		wantErr bool
	}{
		{
			name:    "empty set",
			keys:    nil,
			wantErr: true,
		},
		{
			name:    "lab only — today's state",
			keys:    []PublicKey{testKey(t, 1, RoleCurrent, PurposeLab)},
			wantErr: true,
		},
		{
			name: "lab promoted by role alone is still lab",
			keys: []PublicKey{
				testKey(t, 1, RoleCurrent, PurposeLab),
				testKey(t, 2, RolePrevious, PurposeLab),
			},
			wantErr: true,
		},
		{
			name:    "unlabelled key does not count as production",
			keys:    []PublicKey{testKey(t, 3, RoleCurrent, "")},
			wantErr: true,
		},
		{
			name:    "production current",
			keys:    []PublicKey{testKey(t, 4, RoleCurrent, PurposeProduction)},
			wantErr: false,
		},
		{
			name: "production current, lab retained as previous — the rotation window",
			keys: []PublicKey{
				testKey(t, 4, RoleCurrent, PurposeProduction),
				testKey(t, 1, RolePrevious, PurposeLab),
			},
			wantErr: false,
		},
		{
			name: "production only as PREVIOUS still counts: the build can verify a real licence",
			keys: []PublicKey{
				testKey(t, 1, RoleCurrent, PurposeLab),
				testKey(t, 4, RolePrevious, PurposeProduction),
			},
			wantErr: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := releaseReady(tc.keys)
			if tc.wantErr && err == nil {
				t.Fatalf("releaseReady accepted a key set with no production key")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("releaseReady refused a set containing a production key: %v", err)
			}
			if tc.wantErr && !errors.Is(err, ErrNoProductionKey) {
				t.Fatalf("got %v, want an ErrNoProductionKey", err)
			}
		})
	}
}

// TestUnlabelledKeysStillVerify — labelling governs what may SIGN a release, not
// what may be verified. An operator checking a file with `verify --pubkey` builds
// an unlabelled key, and that must keep working exactly as before.
func TestUnlabelledKeysStillVerify(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 9
	}
	pub, ok := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("no public half")
	}
	k := NewPublicKey(pub, RoleCurrent, "supplied with --pubkey")
	if k.Purpose != "" {
		t.Fatalf("NewPublicKey labelled a key %q; ad-hoc keys must stay unlabelled", k.Purpose)
	}
	if k.ID != KeyID(pub) || k.Base64 == "" {
		t.Fatal("an unlabelled key lost its identity")
	}
	if err := releaseReady([]PublicKey{k}); err == nil {
		t.Fatal("an unlabelled key made a build look release-ready; the guard must fail closed")
	}
}

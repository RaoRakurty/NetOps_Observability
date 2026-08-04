package vault

// dormant.go — the explicit "no custody configured" constructor.

// Dormant returns a Vault with no sealing provider: Encrypt/Decrypt pass values
// through unchanged, which is exactly what the platform does when SEAL_PROVIDER
// is unset (the default). It exists as real API because "dormant" is a genuine
// runtime state, not only a test fixture — and because callers outside this
// package cannot build one from a struct literal now that the fields are
// unexported, which is the point of the boundary.
//
// A dormant vault needs no store: with no provider there are no wrapped DEKs to
// persist. Warnings are dropped, because the caller that chose dormant already
// knows; the boot-time SR-016 warning is emitted by New, not here.
func Dormant() *Vault {
	return &Vault{
		store:   nopStore{},
		warn:    func(string, string, map[string]any) {},
		deks:    map[string][]byte{},
		wrapped: map[string]string{},
	}
}

type nopStore struct{}

func (nopStore) Load(string) ([]byte, error) { return nil, nil }
func (nopStore) Save(string, []byte) error   { return nil }

// Sealed reports whether a real sealing provider is active — i.e. whether
// Encrypt actually encrypts. A dormant Vault (no SEAL_PROVIDER) passes values
// through in plaintext, which is a legitimate lab state but must never be
// silently combined with custody of a long-lived private key.
//
// Exported so callers that hold key material can FAIL CLOSED rather than
// discovering the passthrough at rest (see bootstrapInternalCA: an unsealed
// internal CA would write its 10-year root key to the kv store in cleartext).
func (v *Vault) Sealed() bool { return v != nil && v.provider != nil }

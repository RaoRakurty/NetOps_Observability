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

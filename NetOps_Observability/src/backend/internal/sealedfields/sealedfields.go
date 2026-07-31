package sealedfields

// Package sealedfields is the wiring that makes Sealed Fields real.
//
// Three packages that deliberately do not know about each other meet here:
//
//	internal/vault   owns key CUSTODY (root KEK, per-tenant versioned DEKs)
//	sealing          owns the CIPHER (derivation, token, edge VRL)
//	processors       owns the MODEL (rules, compilation, simulation)
//
// Each is testable and replaceable alone because none imports the others. This
// file is the only place that names all three, which is why it is small: an
// adapter, not a layer.
//
// DORMANT BY DEFAULT. Sealing requires FEATURE_SEALED_FIELDS=true *and* real key
// custody (SEAL_PROVIDER). Without both, no seal engine is installed, and the
// `seal` action refuses validation with a clear reason rather than accepting
// rules that quietly do not encrypt — the failure mode that matters here is an
// operator believing a field is protected when it is not.

import (
	"context"
	"errors"
	"fmt"
	"os"

	"netops/backend/internal/vault"
	"netops/backend/processors"
	"netops/backend/sealing"
)

// vaultKeyProvider adapts the vault to sealing.KeyProvider.
//
// The vault hands over the tenant DEK; sealing HKDF-separates a field-sealing
// key from it. That separation is why this adapter is safe: the material
// crossing this boundary is never used as a cipher key directly, so the
// high-volume log path and the stored-credential path cannot share a weakness.
// KeyProvider adapts the vault to sealing.KeyProvider.
type vaultKeyProvider struct{ v *vault.Vault }

func (p vaultKeyProvider) TenantKey(_ context.Context, tenant string) ([]byte, int, error) {
	return p.v.TenantKeyMaterial(tenant)
}

func (p vaultKeyProvider) TenantKeyVersion(_ context.Context, tenant string, version int) ([]byte, error) {
	return p.v.TenantKeyMaterialVersion(tenant, version)
}

func (p vaultKeyProvider) RotateTenant(_ context.Context, tenant string) (int, error) {
	return p.v.RotateTenantKey(tenant)
}

// sealEngine adapts sealing.CryptoProvider to processors.SealEngine — the seam
// that lets the processor framework compile and preview a seal rule without
// learning anything about the cipher.
type sealEngine struct{ p sealing.CryptoProvider }

func (e sealEngine) EdgeSnippet(tenant, processorID, field, dataType, path string) (string, error) {
	// The key VERSION is resolved at config-generation time and baked into every
	// token the router mints, so a rotation takes effect on the next config
	// render rather than needing the edge to ask anything at runtime.
	m, err := e.p.EdgeKey(context.Background(), tenant)
	if err != nil {
		return "", err
	}
	return sealing.SealVRL(sealing.EdgeSealSpec{
		Context: sealing.Context{
			Tenant: tenant, ProcessorID: processorID, Field: field, DataType: dataType,
		},
		KeyVersion: m.Version,
		Path:       path,
	})
}

func (e sealEngine) SealValue(tenant, processorID, field, dataType, plaintext string) (string, error) {
	return e.p.Seal(context.Background(), sealing.Context{
		Tenant: tenant, ProcessorID: processorID, Field: field, DataType: dataType,
	}, plaintext)
}

func (e sealEngine) DisplayForm(plaintext string, keepLast int) string {
	return sealing.Display(plaintext, keepLast)
}

// sealedFieldsEnabled reports the operator's intent. Custody availability is
// checked separately so the two failures can be reported differently: "you did
// not turn it on" and "you turned it on but there is no key custody" need
// different remedies.
func Enabled() bool { return os.Getenv("FEATURE_SEALED_FIELDS") == "true" }

// initSealedFields installs the seal engine, or explains why it did not.
//
// Returns an error ONLY when the operator asked for sealing and it cannot be
// provided — that combination must abort boot rather than start a deployment
// whose sensitive-data rules silently do nothing.
func Init(v *vault.Vault, warn func(component, msg string, fields map[string]any)) (sealing.CryptoProvider, error) {
	if !Enabled() {
		return nil, nil // dormant, by default and without comment
	}
	if v == nil {
		return nil, errors.New("FEATURE_SEALED_FIELDS=true but no vault is configured")
	}
	// Probe custody before claiming the feature is on. TenantKeyMaterial on the
	// platform tenant is the cheapest honest check: if the vault is dormant it
	// returns ErrCustodyUnavailable here rather than at the first sealed event,
	// hours later, in the ingest path where nobody is watching.
	if _, _, err := v.TenantKeyMaterial(""); err != nil {
		if errors.Is(err, vault.ErrCustodyUnavailable) {
			return nil, fmt.Errorf("FEATURE_SEALED_FIELDS=true requires key custody: %w — set SEAL_PROVIDER=swtpm", err)
		}
		return nil, fmt.Errorf("sealed fields: key custody unusable: %w", err)
	}

	provider := sealing.NewAESCTRProvider(vaultKeyProvider{v: v})
	processors.SetSealEngine(sealEngine{p: provider})
	warn("sealing", "Sealed Fields ENABLED — values matched by a `seal` processor are encrypted at ingest and recoverable only through an audited unmask.", nil)
	return provider, nil
}

// NewProvider builds the CryptoProvider over a vault WITHOUT installing the
// global engine. Exported so callers (and tests) can construct the production
// object graph without the package-level side effect Init performs.
func NewProvider(v *vault.Vault) sealing.CryptoProvider {
	return sealing.NewAESCTRProvider(vaultKeyProvider{v: v})
}

// NewEngine adapts a CryptoProvider to the processor framework's seam.
func NewEngine(p sealing.CryptoProvider) processors.SealEngine { return sealEngine{p: p} }

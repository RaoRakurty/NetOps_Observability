// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package cloudconn is the canonical, provider-neutral contract for connecting a
// customer's cloud account (AWS / Azure / GCP) to Correlix.
//
// It is deliberately a SEPARATE, importable package (not package main) so that
// the connector-framework layer AND the per-provider collector/metadata layer
// agree on ONE definition of a capability pack, an auth method, a scope type and
// a lifecycle state. Nothing here depends on the HTTP server, the database, or
// the secret Vault — those live in package main and consume this contract.
//
// # Two identity planes (non-negotiable separation)
//
// Correlix has two identity planes that MUST NOT share credentials, sessions or
// config objects:
//
//  1. HUMAN AUTH INTO Correlix — SSO/OIDC/SAML/local login. Lives entirely in
//     package main's auth layer. This package never touches it.
//  2. MACHINE AUTH FROM Correlix TO a cloud provider — modeled here. A cloud
//     admin username/password is NEVER a connector credential (AuthMethodProhibited).
//
// # A CloudConnection is five separate concerns, not one credential blob
//
//   - Identity        — who Correlix authenticates AS to the provider (IdentityConfig).
//   - Authorization    — what the identity is permitted to do (CapabilityPack + granted perms).
//   - Collection scope — where in the provider tree we collect (Scope).
//   - Data sources     — which telemetry lanes are enabled (declared by the pack).
//   - Health + audit   — identity health is tracked SEPARATELY from telemetry health.
//
// # Connector identity preference order (design for this, highest first)
//
//  1. Federated short-lived workload identity  (AuthMethodWorkloadFederation)
//  2. Cloud-native role / managed identity     (AuthMethodCloudRole)
//  3. Customer certificate                     (AuthMethodCertificate)
//  4. Rotatable client secret                  (AuthMethodClientSecret)  — legacy
//  5. Static key / SA-key                       (AuthMethodStaticKey)     — legacy
//  6. Cloud admin username/password             (AuthMethodProhibited)    — REJECTED
package cloudconn

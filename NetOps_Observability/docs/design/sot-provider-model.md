# Source of Truth — pluggable provider model

**Status:** proposed (2026-06-19) · **Owner decision:** pluggable, internal Devices = default
**Supersedes the implicit assumption that NetBox *is* the SoT.**

---

## Problem

Today "Source of Truth" is hardwired to NetBox. NetBox supplies the *intent* the
wire can't: site definitions + geographic coordinates, device→site assignment,
the "should-exist" inventory (for drift), and (future) ownership. Two realities
break the hardwiring:

1. **No external SoT.** Most prospects don't run NetBox. Forcing them to stand up
   and populate a CMDB just to get a geo map or drift detection is a non-starter.
   The platform already *has* an inventory (`Infrastructure → Devices`) — it should
   be able to *be* the SoT.
2. **External SoT in the customer environment.** Some customers already run their
   own NetBox / ServiceNow CMDB / Infoblox. We must read **their** authority, not
   make them duplicate inventory into ours.

## Principle

SoT is a **role**, satisfied by a **provider**, not a product. One interface; the
internal provider is the default; external systems are optional connectors that
take over when configured. (CLAUDE.md §1/§4: modular, plug-and-play, plugin
isolation, no hidden coupling.)

```
         ┌──────────────── intent consumers ────────────────┐
         │  geo projection · geomap · drift/compliance ·     │
         │  topology site grouping · ownership · golden-path │
         └───────────────────────┬───────────────────────────┘
                                  │ reads via
                          ┌───────▼────────┐
                          │  SoTProvider   │  (interface)
                          └───────┬────────┘
                ┌─────────────────┼──────────────────┐
        ┌───────▼────────┐ ┌──────▼───────┐  ┌────────▼─────────┐
        │   internal     │ │   netbox     │  │ servicenow/      │
        │  (DEFAULT)     │ │  (external)  │  │ infoblox (future)│
        │ Devices +      │ │  current     │  └──────────────────┘
        │ sites store    │ │  fetch path  │
        └────────────────┘ └──────────────┘
```

## The interface

```go
// SoTProvider supplies operator INTENT that telemetry cannot. Each method is
// tenant-scoped by the caller and must be safe to call when the provider is empty
// (returns zero values, never panics — zero-trust on content).
type SoTProvider interface {
    Name() string                       // "internal" | "netbox" | …
    // Sites returns declared sites with coordinates (decimal WGS-84).
    Sites(ctx context.Context) ([]SoTSite, error)
    // DeviceSites maps a device identity token → site slug (placement intent).
    DeviceSites(ctx context.Context) (map[string]string, error)
    // Configured reports whether this provider has anything to offer.
    Configured() bool
}

type SoTSite struct {
    Slug, Name, Status string
    Lat, Lng           float64
    HasCoords          bool
    Source             string // "internal" | "netbox" — drives evidence.source
}
```

`geomapResolve` (already the single join point — feeds `/api/geomap` *and* the
executive_geo projection) stops calling NetBox directly and instead calls
`s.sot.Active().Sites()/DeviceSites()`. Nothing downstream changes: same
`geoSite` rows, same device→site map, same projection.

## Provider selection

Resolved once, with explicit precedence (mirrors the existing `effective()`
pattern so env-var behavior is preserved):

1. An **external** provider that is enabled + configured (today: NetBox) → authority.
2. Otherwise the **internal** provider (always available).

The internal provider is never "off" — worst case it's empty (no sites yet),
which the UI already handles with the honest onboarding empty-state. So geo/drift
degrade gracefully instead of going dark when NetBox is absent.

> Future refinement (not now): per-domain providers (e.g. NetBox for sites,
> ServiceNow for ownership). The interface is shaped to allow it; selection starts
> single-active to keep it simple.

## Internal provider internals

- **New `sitesStore`** (`sites.go`), modeled on `deviceLocationStore`: a kv-backed
  (`/data/sites.json`, PG-ready) CRUD store of `SoTSite` keyed by slug.
  Operator-editable: name, slug, lat/lng, status.
- **Device→site** comes from the *existing* sources, no new plumbing:
  `Device.Labels["site"]` + the `device_locations` annotation layer. The internal
  provider just reads what's already there.
- **Devices stays the editing surface.** Assigning a device to a site = setting its
  `site` (a label edit on the device) — the inventory the operator already curates.

## API

- `GET/POST /api/sites`, `PUT/DELETE /api/sites/{slug}` — internal sites CRUD
  (platform-owner / infra-write). Same auth posture as `/api/automation/netbox`.
- `/api/geomap`, `/api/devices*`, `/api/topology*` — **unchanged response shapes.**
- `/api/automation/netbox` — unchanged; NetBox becomes *one* provider, not *the* SoT.

## Frontend

- **Provider selector** on `Automation → Source of Truth`: "Internal (this
  platform)" [default] vs "NetBox (external)" vs future. The existing NetBox form
  collapses under the NetBox option; choosing Internal reveals a **Sites manager**.
- **Sites manager** (new): table to add/edit sites + coordinates (decimal WGS-84).
  Reuses the geomap world-map preview.
- **Devices**: site assignment becomes a first-class, editable column/field (it's a
  label edit today; surface it).
- `DeviceGeomap` "Set locations" editor stays — it's the per-device annotation
  fallback, complementary to declared sites.

## Phases (each independently shippable + validated)

**Phase 1 — provider seam + internal sites (backend).**
`SoTProvider` interface + `internalProvider` + `netboxProvider` (wraps current
fetch). New `sitesStore` + `/api/sites` CRUD. Refactor `geomapResolve` to read via
the active provider. Pure unit tests for the store + provider selection. *Outcome:
geo/SoT works fully internally with zero external dependency; NetBox still works
when configured.*

**Phase 2 — operator UI.** Sites manager + provider selector on Source of Truth;
device site assignment on Devices. *Outcome: an operator can run the whole SoT
in-app, no NetBox.*

**Phase 3 — external parity + breadth.** Route drift/compliance and topology site
grouping through the active provider (not NetBox-specific flags); document the
external-customer path; shape ownership intent. (ServiceNow/Infoblox providers are
later, behind the same seam.)

## Non-goals / guardrails

- No change to device identity/dedup tokens (`deviceIdentities`) or the
  `device_locations` annotation layer.
- No response-shape changes to existing endpoints (frontend stays working
  throughout).
- Tenant scoping and secret custody unchanged (NetBox token stays Vault-sealed).
- Coordinates remain operator intent — GeoIP is never introduced.

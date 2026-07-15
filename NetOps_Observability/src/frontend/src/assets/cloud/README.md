# Official cloud-provider marks (vendored)

Vendored so the build stays offline-reproducible. Rendered **as-is** — never
crop, flip, rotate, recolor, or reshape them (every provider's terms forbid
it), and never use them to represent this product; they mark *the provider's*
resources in diagrams only. Compositing them onto a neutral tile/background is
layout, not modification.

| File | Source (official package) | Terms |
|------|---------------------------|-------|
| `aws.svg` | AWS Architecture Icons, `Icon-package_04302026` → `Architecture-Group-Icons/AWS-Cloud-logo_32.svg` | https://aws.amazon.com/architecture/icons/ — provided for customers/partners to build architecture diagrams |
| `azure.svg` | Azure Public Service Icons V24 → `Icons/other/10018-icon-service-Azure-A.svg` | https://learn.microsoft.com/en-us/azure/architecture/icons/ — permitted in architectural diagrams, training materials, documentation |
| `gcp.svg` | Google Cloud logo symbol (the official four-color cloud) — the four paths from Google's official logo-lockup vector, geometry and brand palette (`#EA4335/#4285F4/#34A853/#FBBC05`) untouched; only the viewBox is fitted to the symbol's own bounding box (layout, not modification) | https://about.google/brand-resource-center/ — Google brand features may be used to accurately reference Google's products; the mark must stay unmodified and must not imply endorsement. Product/diagram icon set (agree-to-terms download): https://cloud.google.com/icons |

Same files are embedded in the Go API at `src/backend/cloudicons/` for the RCA
report's path-causality SVG — keep both copies in sync when refreshing the
packages.

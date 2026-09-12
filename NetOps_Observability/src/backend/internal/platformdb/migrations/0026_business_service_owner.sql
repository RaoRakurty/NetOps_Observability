-- 0026_business_service_owner.sql — Service catalog owner field (cloud-platform
-- backlog Wave 3 #8, product-review rev #12). The catalog UI surfaces who is
-- accountable for a business service; owner is free-form operator text (a team
-- or person label), optional, bounded at the handler. No RLS change — the
-- tenant_iso FORCE policy from 0024 already covers the table.

ALTER TABLE business_services
    ADD COLUMN IF NOT EXISTS owner TEXT NOT NULL DEFAULT '';

-- 0028_business_service_runbook.sql — Service catalog runbook URL (cloud-platform
-- backlog Wave 4 #12, resolution actions v1). A per-service link to the team's
-- operational runbook, surfaced as an "Open runbook" action on an open cloud
-- investigation. Optional; https-only + bounded at the handler. No RLS change —
-- the tenant_iso FORCE policy from 0024 already covers the table.

ALTER TABLE business_services
    ADD COLUMN IF NOT EXISTS runbook_url TEXT NOT NULL DEFAULT '';

-- 0022: per-verdict ServiceNow priority mapping on incident policies.
-- Four optional impact/urgency slots (0 = automatic escalation: confirmed+
-- critical → 1/1 = P1, confirmed → urgency 1 = P2, suspected uses the policy
-- defaults). Explicit values win outright — the customer decides the mapping.
-- Additive + idempotent; no data rewrite, existing rows keep automatic (0).
ALTER TABLE incident_policies
    ADD COLUMN IF NOT EXISTS impact_confirmed_critical  smallint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS urgency_confirmed_critical smallint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS impact_confirmed           smallint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS urgency_confirmed          smallint NOT NULL DEFAULT 0;

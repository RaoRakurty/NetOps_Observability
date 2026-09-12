-- 0029_incident_policy_allow_validation_scenarios.sql — F-77.
--
-- `allow_validation_scenarios` has existed on the incidentPolicy struct since
-- the policy engine shipped (ticketing_model.go:29), is accepted by the API,
-- and is echoed back in the response as though it had been saved. It was in NO
-- column list and NO migration. The in-memory store kept it — which is why the
-- unit tests passed — and the production Postgres store dropped it on write and
-- returned the zero value on read.
--
-- Live at audit time: a policy literally named "PDI validation (confirmed-only)"
-- reported allow_validation_scenarios: false. The operator had turned it on.
--
-- The gate it feeds (ticketing_policy.go:43) blocks a validation canary from
-- filing a production ticket, so the always-false value failed in the SAFE
-- direction — no spurious tickets were created. The defect is that the control
-- did not work while the API asserted it had been stored. DEFAULT false keeps
-- that same safe behaviour for every existing row; only an explicit opt-in
-- changes anything.
--
-- No RLS change — the tenant_iso FORCE policy already covers this table.

ALTER TABLE incident_policies
    ADD COLUMN IF NOT EXISTS allow_validation_scenarios BOOLEAN NOT NULL DEFAULT false;

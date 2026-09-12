-- 0004_jobs_generalize.sql — promote the report execution framework to a SHARED
-- background-job substrate (reports, log exports, future archive jobs) by adding
-- an explicit job-type discriminator. This is the "extend, don't fork" step: no
-- second queue, no second executions table. Existing rows default to 'report',
-- so the report pipeline is unaffected.
--
-- The worker still claims by run_after across ALL types (one pool, FIFO-ish), then
-- branches on job_type to the per-type handler. kind on the execution row keeps
-- the immutable history explicitly typed so a tenant's report history and export
-- history are listable apart.

ALTER TABLE report_jobs       ADD COLUMN IF NOT EXISTS job_type TEXT NOT NULL DEFAULT 'report';
ALTER TABLE report_executions ADD COLUMN IF NOT EXISTS kind     TEXT NOT NULL DEFAULT 'report';

-- Type-scoped history listings (e.g. "this tenant's log exports, newest first").
-- The hot claim predicate stays type-agnostic (report_jobs_claim_idx), so adding
-- the discriminator costs the claim path nothing.
CREATE INDEX IF NOT EXISTS report_executions_kind_idx
    ON report_executions (kind, tenant_id, fire_time DESC, id DESC);

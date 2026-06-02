-- 0002_report_pipeline.sql — durable async reporting: queue + immutable
-- execution history + per-phase event timeline. Tenant isolation follows the
-- exact audit_events pattern: a tenant_id column + the tenant_iso RLS policy
-- bound to the app.current_tenant GUC ('*' = platform owner sees all). FORCE RLS
-- keeps even the table owner subject to policy.

-- ---- report_jobs: the durable work queue (FOR UPDATE SKIP LOCKED consumer) ----
CREATE TABLE IF NOT EXISTS report_jobs (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL DEFAULT '',
    schedule_id  TEXT NOT NULL,                  -- SavedObject report id
    execution_id TEXT NOT NULL,                  -- 1:1 immutable execution row
    fire_time    TIMESTAMPTZ NOT NULL,           -- logical scheduled instant
    status       TEXT NOT NULL DEFAULT 'queued', -- queued | running | failed | done
    attempts     INT  NOT NULL DEFAULT 0,
    max_attempts INT  NOT NULL DEFAULT 5,
    run_after    TIMESTAMPTZ NOT NULL DEFAULT now(), -- visibility / backoff gate
    locked_by    TEXT,
    locked_at    TIMESTAMPTZ,
    lease_until  TIMESTAMPTZ,                     -- crash-recovery visibility timeout
    last_error   TEXT,
    payload      JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Idempotency: at most one job per (schedule, logical fire instant). The
    -- scheduler enqueues ON CONFLICT DO NOTHING, so restarts / multiple replicas
    -- converge to exactly one job per fire.
    UNIQUE (schedule_id, fire_time)
);
-- Claim path: runnable jobs ordered for fair pickup.
CREATE INDEX IF NOT EXISTS report_jobs_claim_idx
    ON report_jobs (run_after) WHERE status IN ('queued', 'running');
ALTER TABLE report_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE report_jobs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON report_jobs;
CREATE POLICY tenant_iso ON report_jobs
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));

-- ---- report_executions: immutable history (denormalized summary) ----
CREATE TABLE IF NOT EXISTS report_executions (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL DEFAULT '',
    schedule_id     TEXT NOT NULL,
    job_id          TEXT,
    fire_time       TIMESTAMPTZ NOT NULL,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    status          TEXT NOT NULL DEFAULT 'queued', -- queued|running|completed|failed|cancelled
    artifact_ref    JSONB,                          -- {format,content_type,size,sha256,summary,key}
    delivery_status JSONB,                          -- [{channel,recipient,ok,attempt,error,at}]
    error           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS report_executions_tenant_idx
    ON report_executions (tenant_id, fire_time DESC, id DESC);
CREATE INDEX IF NOT EXISTS report_executions_sched_idx
    ON report_executions (schedule_id, fire_time DESC);
ALTER TABLE report_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE report_executions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON report_executions;
CREATE POLICY tenant_iso ON report_executions
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));

-- ---- report_execution_events: append-only per-phase timeline ----
CREATE TABLE IF NOT EXISTS report_execution_events (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL DEFAULT '',
    execution_id TEXT NOT NULL,
    phase        TEXT NOT NULL, -- queued|running|rendering|delivering|completed|failed
    at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    note         TEXT
);
CREATE INDEX IF NOT EXISTS report_execution_events_exec_idx
    ON report_execution_events (execution_id, at);
ALTER TABLE report_execution_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE report_execution_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso ON report_execution_events;
CREATE POLICY tenant_iso ON report_execution_events
    USING (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (current_setting('app.current_tenant', true) = '*'
        OR tenant_id = current_setting('app.current_tenant', true));

-- netops-app-role.sql — least-privilege role for the Postgres app-state backend.
--
-- The app (STORE_BACKEND=postgres) MUST connect as a NON-superuser role: a
-- superuser (or a BYPASSRLS role) ignores Row-Level Security even under FORCE,
-- silently disabling tenant isolation. Startup refuses such a role. This role is
-- created NOSUPERUSER and owns the app-state tables; FORCE RLS keeps even the
-- owner subject to the per-tenant policy.
--
-- Run ONCE against the app-state database (idempotent). Example:
--   docker compose exec -e PGPASSWORD="$DB_PASSWORD" postgres \
--     psql -U "$DB_USER" -d "${DB_NAME:-netops}" \
--          -v app_pw="'CHANGE-ME-strong-password'" \
--          -f /docker-entrypoint-initdb.d/netops-app-role.sql
-- Then set in deployment/docker/.env:
--   STORE_BACKEND=postgres
--   APP_DATABASE_URL=postgres://netops_app:CHANGE-ME-strong-password@postgres:5432/netops?sslmode=disable
-- and restart the api service. The app runs its own schema migrations on boot.

\set ON_ERROR_STOP on

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'netops_app') THEN
        CREATE ROLE netops_app LOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
END
$$;

-- Set or rotate the password (caller supplies :app_pw, already single-quoted).
ALTER ROLE netops_app WITH PASSWORD :app_pw;

-- Let the role create and own its app-state objects in the schema.
GRANT ALL ON SCHEMA public TO netops_app;

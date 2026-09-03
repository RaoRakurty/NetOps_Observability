-- Rollback for 0040_iris_investigations.sql.
--
-- NOTE for the operator: this drops the assistant's INVESTIGATION MEMORY — the
-- record of which prior conclusions an operator confirmed or rejected. Nothing
-- else depends on it (Iris degrades to answering with no prior context, which is
-- its pre-Phase-B behaviour), but the operator judgements themselves are not
-- recoverable from any other table: ai_feedback keeps the rating without the
-- investigation, and rca_feedback judges the engine's verdict, not the
-- assistant's. Export first if that history matters.
DROP TABLE IF EXISTS iris_investigations;

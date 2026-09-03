-- Rollback for 0041_bgp_alert_policy.sql.
--
-- NOTE for the operator: dropping this table removes every tenant's DECLARED
-- alert intent (expected origins, upstream sets, thresholds). The watchlist
-- evaluator then falls back to a LEARNED origin baseline and runs no route-leak
-- heuristic at all — it keeps working, but it alerts on less, and it will not
-- say that it used to know more. Export the rows first if the intent is a
-- version rollback rather than a feature removal.
DROP TABLE IF EXISTS bgp_alert_policy;

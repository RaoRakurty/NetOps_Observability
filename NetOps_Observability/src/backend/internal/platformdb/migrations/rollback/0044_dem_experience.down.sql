-- Rollback for 0044_dem_experience.sql. Drops the declared journeys and the
-- normalized change feed. Nothing derived is lost, because nothing derived was
-- stored: the evidence, hypotheses and incidents are computed from the
-- measurements, the path observations and the producers' own records, all of
-- which live elsewhere and are untouched.
DROP TABLE IF EXISTS dem_change_events;
DROP TABLE IF EXISTS dem_journeys;

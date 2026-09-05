-- Rollback for 0043_dem_targets.sql. Drops the DEM target catalogue; the
-- experience time series in VictoriaMetrics are unaffected and simply stop
-- being produced once no target is projected.
DROP TABLE IF EXISTS dem_targets;

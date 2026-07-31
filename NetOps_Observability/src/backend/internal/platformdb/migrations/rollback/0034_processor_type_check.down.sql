-- Rollback for 0034_processor_type_check.sql. Restores the 0032 enum, which
-- only accepts the four original types — any mask/drop_event processors must be
-- removed first or the constraint will not validate.
ALTER TABLE pipeline_processors
    ADD CONSTRAINT pipeline_processors_rule_type_check
    CHECK (rule_type IN ('redact_field','redact_pattern','drop_field','set_field'));

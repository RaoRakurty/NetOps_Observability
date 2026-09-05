-- Rollback for 0045_tac_templates.sql. Drops the per-tenant TAC command
-- templates. Correlix's own default templates are generated from the authored
-- plans and are unaffected — after this rollback the review step still shows
-- every command before collect and still lets an operator edit the list; only
-- SAVING a set survives it.
DROP TABLE IF EXISTS tac_templates;

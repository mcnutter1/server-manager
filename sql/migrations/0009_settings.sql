-- =====================================================================
-- Migration 0009 — settings registry marker.
-- No new schema: operator-editable settings are stored in the existing
-- `settings` table under the `cfg:<dot.key>` namespace (see App\Settings)
-- and overlaid onto the file config at bootstrap. This migration only bumps
-- the recorded schema version so deployments can gate the Settings feature.
-- Idempotent.
-- =====================================================================

INSERT INTO settings (skey, svalue) VALUES
    ('schema_version', '"1.8.0"')
ON DUPLICATE KEY UPDATE svalue = VALUES(svalue);

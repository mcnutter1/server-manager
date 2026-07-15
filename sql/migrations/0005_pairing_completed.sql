-- =====================================================================
-- Migration 0005 — pairing_codes.completed_at (single-use redemption).
-- A pairing/unlock token is redeemed exactly once: when the manager claims
-- an app's secret it stamps completed_at, so the same token can never enroll
-- a second app. Idempotent.
-- =====================================================================

SET @col := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'pairing_codes'
      AND COLUMN_NAME = 'completed_at'
);
SET @ddl := IF(@col = 0,
    'ALTER TABLE pairing_codes ADD COLUMN completed_at DATETIME NULL AFTER last_used_at',
    'DO 0');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

INSERT INTO settings (skey, svalue) VALUES
    ('schema_version', '"1.4.0"')
ON DUPLICATE KEY UPDATE svalue = VALUES(svalue);

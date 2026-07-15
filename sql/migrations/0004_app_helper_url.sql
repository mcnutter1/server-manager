-- =====================================================================
-- Migration 0004 — managed_apps.helper_url (full helper endpoint URL).
-- Replaces the split domain + helper_path addressing with a single full
-- URL to the app's helper (e.g. https://app.example.com/srvmgr/helper.php).
-- domain is retained for display / traffic attribution. Idempotent.
-- =====================================================================

SET @col := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'managed_apps'
      AND COLUMN_NAME = 'helper_url'
);
SET @ddl := IF(@col = 0,
    'ALTER TABLE managed_apps ADD COLUMN helper_url VARCHAR(255) NULL AFTER health_url',
    'DO 0');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Backfill helper_url from the legacy domain + helper_path for existing rows.
UPDATE managed_apps
   SET helper_url = CONCAT('https://', domain, '/',
                           TRIM(LEADING '/' FROM COALESCE(NULLIF(helper_path, ''), 'srvmgr/helper.php')))
 WHERE (helper_url IS NULL OR helper_url = '')
   AND domain IS NOT NULL AND domain <> '';

INSERT INTO settings (skey, svalue) VALUES
    ('schema_version', '"1.3.0"')
ON DUPLICATE KEY UPDATE svalue = VALUES(svalue);

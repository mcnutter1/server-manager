-- =====================================================================
-- Migration 0006 — geo_cache network classification flags.
-- Adds hosting (data center), proxy/VPN and mobile-carrier hints returned by
-- the geolocation provider (ip-api fields: hosting, proxy, mobile). Powers the
-- entity drill-downs on the Traffic Map (is this IP a data center? a proxy?).
-- NULL = unknown / not yet resolved. Idempotent.
-- =====================================================================

SET @col := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'geo_cache'
      AND COLUMN_NAME = 'hosting'
);
SET @ddl := IF(@col = 0,
    'ALTER TABLE geo_cache ADD COLUMN hosting TINYINT(1) NULL AFTER asn',
    'DO 0');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'geo_cache'
      AND COLUMN_NAME = 'proxy'
);
SET @ddl := IF(@col = 0,
    'ALTER TABLE geo_cache ADD COLUMN proxy TINYINT(1) NULL AFTER hosting',
    'DO 0');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'geo_cache'
      AND COLUMN_NAME = 'mobile'
);
SET @ddl := IF(@col = 0,
    'ALTER TABLE geo_cache ADD COLUMN mobile TINYINT(1) NULL AFTER proxy',
    'DO 0');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

INSERT INTO settings (skey, svalue) VALUES
    ('schema_version', '"1.5.0"')
ON DUPLICATE KEY UPDATE svalue = VALUES(svalue);

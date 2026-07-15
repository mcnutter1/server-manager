-- =====================================================================
-- Migration 0002 — traffic map (geo cache + stitched traffic events +
-- per-app log lines). Powers the Traffic Map view. Idempotent.
-- =====================================================================

-- ---------------------------------------------------------------------
-- GeoIP cache. Distinct source IPs are resolved to a country / ISP /
-- lat-lng once and re-used, so we never hammer the upstream provider.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS geo_cache (
    ip_address    VARCHAR(45)     NOT NULL,
    country       VARCHAR(80)     NULL,
    country_code  CHAR(2)         NULL,
    region        VARCHAR(120)    NULL,
    city          VARCHAR(120)    NULL,
    lat           DECIMAL(9,6)    NULL,
    lng           DECIMAL(9,6)    NULL,
    isp           VARCHAR(190)    NULL,
    org           VARCHAR(190)    NULL,
    asn           VARCHAR(80)     NULL,
    status        VARCHAR(20)     NOT NULL DEFAULT 'ok',
    updated_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (ip_address),
    KEY idx_country (country_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Aggregated traffic events. Each ingest run rolls raw log lines up into
-- one row per (window, source IP, app, kind) so the map stays fast.
--   kind = allow : accepted inbound request seen in the apache access log
--   kind = block : traffic dropped by the firewall (iptables byte counters)
--   kind = app   : per-app request line pulled from that app's health helper
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS traffic_events (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    window_start  DATETIME        NOT NULL,
    src_ip        VARCHAR(45)     NOT NULL,
    app_id        BIGINT UNSIGNED NULL,
    app_slug      VARCHAR(120)    NULL,
    host          VARCHAR(190)    NULL,
    kind          ENUM('allow','block','app') NOT NULL DEFAULT 'allow',
    method        VARCHAR(10)     NULL,
    top_path      VARCHAR(255)    NULL,
    status_sample INT             NULL,
    requests      INT UNSIGNED    NOT NULL DEFAULT 0,
    errors        INT UNSIGNED    NOT NULL DEFAULT 0,
    bytes         BIGINT UNSIGNED NOT NULL DEFAULT 0,
    created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_window (window_start),
    KEY idx_src (src_ip),
    KEY idx_app (app_id),
    KEY idx_kind (kind)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Raw-ish per-app log lines pulled from each app's health helper "logs"
-- action. Kept short-lived for the drill-down panels on the traffic map.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_log_events (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    app_id        BIGINT UNSIGNED NOT NULL,
    app_slug      VARCHAR(120)    NULL,
    level         VARCHAR(20)     NULL,
    src_ip        VARCHAR(45)     NULL,
    method        VARCHAR(10)     NULL,
    path          VARCHAR(255)    NULL,
    status_code   INT             NULL,
    bytes         BIGINT UNSIGNED NULL,
    message       TEXT            NULL,
    logged_at     DATETIME        NULL,
    created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_app (app_id),
    KEY idx_src (src_ip),
    KEY idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO settings (skey, svalue) VALUES
    ('schema_version', '"1.1.0"')
ON DUPLICATE KEY UPDATE svalue = VALUES(svalue);

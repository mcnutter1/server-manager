-- =====================================================================
-- Migration 0007 — app_health_checks history.
-- Stores the result of every application health check (HTTP probe + helper
-- reply) so the UI can render a health report modal with what came back and
-- when it last ran. Powers automatic (worker) + manual checks. Idempotent.
-- =====================================================================

CREATE TABLE IF NOT EXISTS app_health_checks (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    app_id        BIGINT UNSIGNED NOT NULL,
    app_slug      VARCHAR(120)    NULL,
    status        VARCHAR(40)     NOT NULL DEFAULT 'unknown', -- healthy | degraded | unhealthy | unknown
    trigger_type  VARCHAR(20)     NOT NULL DEFAULT 'manual',  -- manual | auto
    http_ok       TINYINT(1)      NULL,
    http_status   INT             NULL,
    http_time_ms  INT             NULL,
    helper_ok     TINYINT(1)      NULL,
    helper_status VARCHAR(40)     NULL,
    detail        JSON            NULL,                        -- full checks payload
    checked_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_app (app_id),
    KEY idx_checked (checked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO settings (skey, svalue) VALUES
    ('schema_version', '"1.6.0"')
ON DUPLICATE KEY UPDATE svalue = VALUES(svalue);

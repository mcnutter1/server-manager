-- =====================================================================
-- Migration 0008 — ip_reputation threat-intelligence cache.
-- Stores the malicious-IP verdict for each address we look up against known
-- threat databases (DNSBLs, AbuseIPDB, ...). Populated reactively when an IP
-- is drilled into and proactively by the threat-intel cron worker. Idempotent.
-- =====================================================================

CREATE TABLE IF NOT EXISTS ip_reputation (
    ip_address     VARCHAR(45)     NOT NULL,
    is_malicious   TINYINT(1)      NOT NULL DEFAULT 0,
    score          INT             NOT NULL DEFAULT 0,   -- 0..100 confidence
    total_reports  INT             NOT NULL DEFAULT 0,
    categories     VARCHAR(255)    NULL,                 -- comma-joined threat categories
    sources        JSON            NULL,                 -- per-provider detail array
    usage_type     VARCHAR(120)    NULL,                 -- e.g. Data Center / ISP (AbuseIPDB)
    status         VARCHAR(20)     NOT NULL DEFAULT 'ok',-- ok | private | error | disabled
    last_listed_at DATETIME        NULL,
    checked_at     DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ip_address),
    KEY idx_malicious (is_malicious),
    KEY idx_checked (checked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO settings (skey, svalue) VALUES
    ('schema_version', '"1.7.0"')
ON DUPLICATE KEY UPDATE svalue = VALUES(svalue);

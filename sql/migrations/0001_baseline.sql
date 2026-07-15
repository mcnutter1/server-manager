-- =====================================================================
-- Migration 0001 — baseline schema (all core tables, pre-traffic-map)
-- Applied by bin/migrate.php. Idempotent (CREATE TABLE IF NOT EXISTS),
-- so it is a no-op on databases that were bootstrapped from schema.sql.
-- The database + user themselves are created by the installer, not here.
-- =====================================================================

-- ---------------------------------------------------------------------
-- Local API tokens (machine-to-machine access to THIS platform).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_tokens (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name          VARCHAR(120)    NOT NULL,
    token_hash    CHAR(64)        NOT NULL,
    scopes        JSON            NULL,
    created_by    VARCHAR(190)    NULL,
    last_used_at  DATETIME        NULL,
    expires_at    DATETIME        NULL,
    revoked       TINYINT(1)      NOT NULL DEFAULT 0,
    created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_token_hash (token_hash),
    KEY idx_revoked (revoked)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Audit log — every privileged / mutating action lands here.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    actor         VARCHAR(190)    NOT NULL,
    actor_type    ENUM('user','token','system') NOT NULL DEFAULT 'user',
    action        VARCHAR(120)    NOT NULL,
    target        VARCHAR(190)    NULL,
    params        JSON            NULL,
    result        ENUM('success','failure','denied') NOT NULL DEFAULT 'success',
    message       TEXT            NULL,
    ip_address    VARCHAR(45)     NULL,
    created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_actor (actor),
    KEY idx_action (action),
    KEY idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Time-series system metrics (collected by bin/collect-metrics.php).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS metrics (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    cpu_pct       DECIMAL(5,2)    NULL,
    mem_pct       DECIMAL(5,2)    NULL,
    swap_pct      DECIMAL(5,2)    NULL,
    disk_pct      DECIMAL(5,2)    NULL,
    load1         DECIMAL(6,2)    NULL,
    load5         DECIMAL(6,2)    NULL,
    load15        DECIMAL(6,2)    NULL,
    net_rx_bytes  BIGINT UNSIGNED NULL,
    net_tx_bytes  BIGINT UNSIGNED NULL,
    procs         INT UNSIGNED    NULL,
    created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Service state history (transitions captured by the monitor).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS service_events (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    service       VARCHAR(120)    NOT NULL,
    state         VARCHAR(40)     NOT NULL,
    sub_state     VARCHAR(60)     NULL,
    detail        TEXT            NULL,
    created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_service (service),
    KEY idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Managed applications registry.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS managed_apps (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    slug          VARCHAR(120)    NOT NULL,
    name          VARCHAR(190)    NOT NULL,
    description   TEXT            NULL,
    path          VARCHAR(255)    NOT NULL,
    domain        VARCHAR(190)    NULL,
    repo_url      VARCHAR(255)    NULL,
    db_name       VARCHAR(120)    NULL,
    db_user       VARCHAR(120)    NULL,
    service_name  VARCHAR(120)    NULL,
    health_url    VARCHAR(255)    NULL,
    helper_path   VARCHAR(255)    NULL DEFAULT 'srvmgr/helper.php',
    helper_token  VARCHAR(190)    NULL,
    status        ENUM('active','disabled','maintenance','unmanaged') NOT NULL DEFAULT 'active',
    managed       TINYINT(1)      NOT NULL DEFAULT 1,
    meta          JSON            NULL,
    last_health   VARCHAR(40)     NULL,
    last_checked  DATETIME        NULL,
    created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_slug (slug),
    UNIQUE KEY uq_path (path),
    KEY idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- NIDS events (parsed indicators of compromise / suspicious activity).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS nids_events (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    source        VARCHAR(60)     NOT NULL,
    category      VARCHAR(80)     NOT NULL,
    severity      ENUM('info','low','medium','high','critical') NOT NULL DEFAULT 'low',
    src_ip        VARCHAR(45)     NOT NULL,
    dst_port      INT UNSIGNED    NULL,
    signature     VARCHAR(190)    NULL,
    raw           TEXT            NULL,
    count         INT UNSIGNED    NOT NULL DEFAULT 1,
    created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_src_ip (src_ip),
    KEY idx_category (category),
    KEY idx_severity (severity),
    KEY idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Blocked hosts (firewall drops managed by this platform, with timers).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blocked_hosts (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    ip_address    VARCHAR(45)     NOT NULL,
    reason        VARCHAR(255)    NULL,
    source        VARCHAR(60)     NOT NULL DEFAULT 'manual',
    created_by    VARCHAR(190)    NULL,
    active        TINYINT(1)      NOT NULL DEFAULT 1,
    permanent     TINYINT(1)      NOT NULL DEFAULT 0,
    blocked_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at    DATETIME        NULL,
    unblocked_at  DATETIME        NULL,
    hits          INT UNSIGNED    NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    KEY idx_ip (ip_address),
    KEY idx_active (active),
    KEY idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Firewall rule snapshots (for the UI + change tracking).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS firewall_snapshots (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    table_name    VARCHAR(40)     NOT NULL DEFAULT 'filter',
    rules_json    JSON            NOT NULL,
    rule_count    INT UNSIGNED    NOT NULL DEFAULT 0,
    created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- CLI command execution log (Python runner bridge).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS command_log (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    actor         VARCHAR(190)    NOT NULL,
    command_key   VARCHAR(120)    NOT NULL,
    arguments     JSON            NULL,
    exit_code     INT             NULL,
    duration_ms   INT UNSIGNED    NULL,
    stdout        MEDIUMTEXT      NULL,
    stderr        MEDIUMTEXT      NULL,
    ip_address    VARCHAR(45)     NULL,
    created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_actor (actor),
    KEY idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Alerts raised by the platform + notification dispatch status.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    severity      ENUM('info','warning','critical') NOT NULL DEFAULT 'warning',
    category      VARCHAR(80)     NOT NULL,
    title         VARCHAR(190)    NOT NULL,
    body          TEXT            NULL,
    fingerprint   CHAR(40)        NULL,
    notified      TINYINT(1)      NOT NULL DEFAULT 0,
    acknowledged  TINYINT(1)      NOT NULL DEFAULT 0,
    ack_by        VARCHAR(190)    NULL,
    created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_severity (severity),
    KEY idx_ack (acknowledged),
    KEY idx_fingerprint (fingerprint),
    KEY idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Generic key/value settings store.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS settings (
    skey          VARCHAR(120)    NOT NULL,
    svalue        JSON            NULL,
    updated_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (skey)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO settings (skey, svalue) VALUES
    ('schema_version', '"1.0.0"')
ON DUPLICATE KEY UPDATE svalue = VALUES(svalue);

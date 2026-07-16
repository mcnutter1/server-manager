-- =====================================================================
-- Server Manager — MySQL schema
-- Target: MySQL 8.x / MariaDB 10.5+ on Ubuntu
--
-- NOTE: This file is a full-snapshot convenience reference and an
-- installer fallback. The AUTHORITATIVE, incremental schema lives in
-- sql/migrations/ and is applied by bin/migrate.php (wired into both
-- deploy/install.sh and deploy/update.sh). When you change the schema,
-- add a new numbered migration under sql/migrations/ AND mirror it here.
-- =====================================================================
SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE DATABASE IF NOT EXISTS server_manager
    CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE server_manager;

-- ---------------------------------------------------------------------
-- Local API tokens (for machine-to-machine access to THIS platform).
-- User auth is delegated to McNutt Cloud Auth; these are for automation.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_tokens (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name          VARCHAR(120)    NOT NULL,
    token_hash    CHAR(64)        NOT NULL,           -- sha256 of the raw token
    scopes        JSON            NULL,               -- ["read","services","firewall","nids","apps","runner"]
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
    actor         VARCHAR(190)    NOT NULL,           -- identity email or "token:<name>"
    actor_type    ENUM('user','token','system') NOT NULL DEFAULT 'user',
    action        VARCHAR(120)    NOT NULL,           -- e.g. service.restart
    target        VARCHAR(190)    NULL,               -- e.g. apache2, 10.0.0.5
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
    state         VARCHAR(40)     NOT NULL,           -- active, inactive, failed, ...
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
    path          VARCHAR(255)    NOT NULL,           -- /var/www/<app>
    domain        VARCHAR(190)    NULL,
    repo_url      VARCHAR(255)    NULL,
    db_name       VARCHAR(120)    NULL,
    db_user       VARCHAR(120)    NULL,
    service_name  VARCHAR(120)    NULL,               -- optional systemd unit
    health_url    VARCHAR(255)    NULL,               -- optional HTTP health check
    -- Full URL to the "helper" the app exposes so this platform can interface
    -- with it in a common way (e.g. https://app.example.com/srvmgr/helper.php).
    -- See docs/APP_HELPER.md. helper_path is the legacy split form.
    helper_url    VARCHAR(255)    NULL,
    helper_path   VARCHAR(255)    NULL DEFAULT 'srvmgr/helper.php',
    helper_token  VARCHAR(190)    NULL,
    status        ENUM('active','disabled','maintenance','unmanaged') NOT NULL DEFAULT 'active',
    managed       TINYINT(1)      NOT NULL DEFAULT 1, -- 0 = discovered but not adopted
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
    source        VARCHAR(60)     NOT NULL,           -- auth, apache, manual, ...
    category      VARCHAR(80)     NOT NULL,           -- ssh_bruteforce, sqli, xss, scan...
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
    source        VARCHAR(60)     NOT NULL DEFAULT 'manual', -- manual, nids, api
    created_by    VARCHAR(190)    NULL,
    active        TINYINT(1)      NOT NULL DEFAULT 1,
    permanent     TINYINT(1)      NOT NULL DEFAULT 0,
    blocked_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at    DATETIME        NULL,               -- NULL + permanent=1 => never
    unblocked_at  DATETIME        NULL,
    hits          INT UNSIGNED    NOT NULL DEFAULT 0, -- iptables packet counter snapshot
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
    command_key   VARCHAR(120)    NOT NULL,           -- whitelisted key, not raw shell
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
    category      VARCHAR(80)     NOT NULL,           -- service, resource, nids, app
    title         VARCHAR(190)    NOT NULL,
    body          TEXT            NULL,
    fingerprint   CHAR(40)        NULL,               -- de-dupe repeated alerts
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

-- ---------------------------------------------------------------------
-- GeoIP cache. Distinct source IPs are resolved to a country / ISP / lat-lng
-- once and re-used, so we never hammer the upstream geolocation provider.
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
    hosting       TINYINT(1)      NULL,                     -- 1 = data center / hosting
    proxy         TINYINT(1)      NULL,                     -- 1 = proxy / VPN / Tor exit
    mobile        TINYINT(1)      NULL,                     -- 1 = mobile carrier network
    status        VARCHAR(20)     NOT NULL DEFAULT 'ok',   -- ok | private | fail
    updated_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (ip_address),
    KEY idx_country (country_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Aggregated traffic events. Each ingest run rolls raw log lines up into one
-- row per (window, source IP, app, kind) so the map and tables stay fast.
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
    host          VARCHAR(190)    NULL,               -- vhost / domain hit
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

-- ---------------------------------------------------------------------
-- Application health check history. One row per health check (HTTP probe +
-- helper reply) so the UI can show a health report and when it last ran.
-- ---------------------------------------------------------------------
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
    detail        JSON            NULL,
    checked_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_app (app_id),
    KEY idx_checked (checked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Pairing unlock codes. Short-lived codes the manager issues so an operator
-- can unlock a downstream app's helper page and reveal its enrollment key.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS pairing_codes (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    code_hash     CHAR(64)        NOT NULL,          -- sha256 of the token jti; plaintext never stored
    label         VARCHAR(190)    NULL,
    created_by    VARCHAR(190)    NULL,
    used          INT UNSIGNED    NOT NULL DEFAULT 0,
    last_used_at  DATETIME        NULL,
    completed_at  DATETIME        NULL,              -- set once when the token is redeemed (single use)
    expires_at    DATETIME        NOT NULL,
    created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_code_hash (code_hash),
    KEY idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- IP reputation / threat-intelligence cache. The malicious-IP verdict for
-- each address checked against known threat databases (DNSBLs, AbuseIPDB).
-- Populated reactively on drill-down and proactively by the threat-intel cron.
-- ---------------------------------------------------------------------
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

-- Seed a couple of defaults.
INSERT INTO settings (skey, svalue) VALUES
    ('schema_version', '"1.8.0"')
ON DUPLICATE KEY UPDATE svalue = VALUES(svalue);
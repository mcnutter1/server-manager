<?php
/**
 * Server Manager — main configuration.
 * Copy this file to config.php and fill in the real values.
 * config.php is git-ignored and should never be committed.
 */

return [
    // ---------------------------------------------------------------
    // Application
    // ---------------------------------------------------------------
    'app' => [
        'name'        => 'McNutt Cloud — Server Manager',
        'env'         => 'production',           // production | development
        'debug'       => false,
        'base_url'    => 'https://manage.mcnutt.cloud',
        'timezone'    => 'America/New_York',
        // Absolute path on disk that holds the individually managed apps.
        'apps_root'   => '/var/www',
        // Automatic application health checks. The monitor worker
        // (bin/collect-metrics.php) re-checks each managed app whose last
        // check is older than this many minutes. 0 disables automatic
        // checks (manual "Check" button only).
        'health_interval_min' => 5,
    ],

    // ---------------------------------------------------------------
    // Database (MySQL)
    // ---------------------------------------------------------------
    'db' => [
        'host'     => '127.0.0.1',
        'port'     => 3306,
        'name'     => 'server_manager',
        'user'     => 'server_manager',
        'pass'     => 'CHANGE_ME',
        'charset'  => 'utf8mb4',
    ],

    // ---------------------------------------------------------------
    // McNutt Cloud Auth (SSO)
    // These mirror client_helper/config.php and are used for role checks.
    // ---------------------------------------------------------------
    'auth' => [
        'enabled'       => true,
        // Roles that are allowed to reach the platform at all.
        'allowed_roles' => ['admin', 'ops', 'support'],
        // Roles required to perform privileged/mutating actions.
        'admin_roles'   => ['admin', 'ops'],
    ],

    // ---------------------------------------------------------------
    // Notifications service
    // ---------------------------------------------------------------
    'notifications' => [
        'enabled'    => true,
        'endpoint'   => 'https://notify.mcnutt.cloud/api/send.php',
        'api_token'  => 'CHANGE_ME',
        'default_from' => 'Server Manager <alerts@mcnutt.cloud>',
        // Where operational alerts go.
        'alert_email' => 'ops@mcnutt.cloud',
        'alert_sms'   => '+17325550123',
    ],

    // ---------------------------------------------------------------
    // Privileged Python runner
    // ---------------------------------------------------------------
    'runner' => [
        // Full path to the python interpreter.
        'python'      => '/usr/bin/python3',
        // Path to runner.py on disk.
        'script'      => '/var/www/server-manager/runner/runner.py',
        // Shared secret the PHP layer passes to the runner. Must match
        // the token baked into the runner environment / sudoers wrapper.
        'token'       => 'CHANGE_ME_LONG_RANDOM_TOKEN',
        // If true, the runner is invoked through sudo (recommended so the
        // web user has no direct privileges).
        'use_sudo'    => true,
        'sudo_binary' => '/usr/bin/sudo',
        // Hard timeout (seconds) for any runner invocation.
        'timeout'     => 30,
    ],

    // ---------------------------------------------------------------
    // Monitoring thresholds (used for health scoring + alerts)
    // ---------------------------------------------------------------
    'monitoring' => [
        'cpu_warn'   => 75,   // percent
        'cpu_crit'   => 90,
        'mem_warn'   => 80,
        'mem_crit'   => 92,
        'disk_warn'  => 80,
        'disk_crit'  => 90,
        'load_warn'  => 4.0,  // per-core normalized would be nicer; simple for now
        // Services that must always be running. Alerts fire if they stop.
        'critical_services' => ['apache2', 'mysql', 'ssh'],
    ],

    // ---------------------------------------------------------------
    // NIDS / host blocking
    // ---------------------------------------------------------------
    'nids' => [
        // Log sources that the analyzer tails for suspicious activity.
        'auth_log'      => '/var/log/auth.log',
        'apache_access' => '/var/log/apache2/access.log',
        'apache_error'  => '/var/log/apache2/error.log',
        // Default block duration (minutes). 0 = permanent until manually removed.
        'default_block_minutes' => 60,
        // Auto-block after this many failed events from one host within window.
        'auto_block_threshold'  => 8,
        'auto_block_window_min' => 10,
        // Never block these (control plane, monitoring, your office IPs).
        // Baseline allowlist from config; additional "Never block" entries
        // (IPv4/IPv6 addresses or CIDR ranges) can be managed live from the
        // Security view and are stored in the settings table.
        'whitelist' => ['127.0.0.1', '::1'],
        // iptables chain used exclusively by this system.
        'chain'     => 'SRVMGR_BLOCK',
    ],

    // -----------------------------------------------------------------
    // GeoIP resolution for the traffic map. Distinct source IPs are resolved
    // once and cached in the geo_cache table.
    // -----------------------------------------------------------------
    'geo' => [
        'enabled'    => true,
        'provider'   => 'ip-api',                 // 'ip-api' (free, no key) | 'none'
        'endpoint'   => 'http://ip-api.com/batch',// free tier is HTTP only, batched, ~15 req/min
        'cache_days' => 14,                       // how long a cached lookup stays fresh
        // Where this server sits on the map (destination of every flow arc).
        // Defaults below are us-east-1; set to your region for accurate arcs.
        'server_lat'   => 39.0438,
        'server_lng'   => -77.4874,
        'server_label' => 'This server',
    ],

    // -----------------------------------------------------------------
    // Traffic map ingest: apache access log + firewall counters + per-app
    // logs pulled from each managed app's health helper.
    // -----------------------------------------------------------------
    'traffic' => [
        'enabled'           => true,
        // Access log(s) to parse for accepted ("allow") traffic. May be a single
        // path, a glob, or an array of either. The default glob captures the
        // manager's own vhost log + every app's vhost log. The worker user
        // (RUN_AS, default www-data) must be able to read these — the installer
        // adds it to the 'adm' group for that.
        'apache_access'     => '/var/log/apache2/*access*.log',
        'max_lines_per_run' => 20000,   // cap per ingest cycle
        'app_log_lines'     => 200,     // lines requested from each app helper
        'collect_app_logs'  => true,    // pull per-app logs via the health helper
        'retention_days'    => 30,      // prune traffic_events / app_log_events after this
    ],
];

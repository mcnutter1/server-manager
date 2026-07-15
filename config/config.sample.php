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
        'whitelist' => ['127.0.0.1', '::1'],
        // iptables chain used exclusively by this system.
        'chain'     => 'SRVMGR_BLOCK',
    ],
];

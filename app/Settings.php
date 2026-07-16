<?php

declare(strict_types=1);

namespace App;

/**
 * Settings — a small registry + store for operator-editable configuration.
 *
 * The canonical configuration still lives in config/config.php (file-based,
 * git-ignored, owned by root). Anything the operator can safely tune from the
 * web UI is described here as a *definition* and stored as a JSON override in
 * the `settings` table under the `cfg:<dot.key>` namespace. At bootstrap the
 * overrides are overlaid onto App\Config so edited values take effect app-wide
 * without ever touching the on-disk file.
 *
 * Secrets that must never round-trip through the browser (DB password, runner
 * token, notification API token) are intentionally NOT in the registry. Keys
 * flagged `sensitive` (e.g. the AbuseIPDB key) are editable but write-only:
 * their current value is masked on read and only overwritten when a new value
 * is submitted.
 */
final class Settings
{
    /** Prefix for override rows in the `settings` table. */
    private const PREFIX = 'cfg:';

    /** Placeholder returned instead of a real sensitive value. */
    public const MASK = '__unchanged__';

    /**
     * The definition registry. Add new tunables here — the API and UI are
     * fully data-driven, so a new entry automatically appears in its group.
     *
     * type: bool | int | float | string | text | password | select | csv
     */
    private static function registry(): array
    {
        return [
            // ---- General ---------------------------------------------
            [
                'key' => 'app.name', 'group' => 'General', 'label' => 'Application name',
                'type' => 'string', 'help' => 'Shown in the browser title and page header.',
            ],
            [
                'key' => 'app.timezone', 'group' => 'General', 'label' => 'Timezone',
                'type' => 'string', 'help' => 'PHP timezone identifier, e.g. America/New_York.',
            ],
            [
                'key' => 'app.health_interval_min', 'group' => 'General',
                'label' => 'Health-check interval (minutes)', 'type' => 'int',
                'min' => 0, 'max' => 1440,
                'help' => 'How often the monitor re-checks each managed app. 0 disables automatic checks.',
            ],
            [
                'key' => 'app.debug', 'group' => 'General', 'label' => 'Debug mode',
                'type' => 'bool', 'advanced' => true,
                'help' => 'Expose PHP/API error detail. Leave OFF in production.',
            ],

            // ---- Monitoring ------------------------------------------
            [
                'key' => 'monitoring.cpu_warn', 'group' => 'Monitoring', 'label' => 'CPU warn (%)',
                'type' => 'int', 'min' => 1, 'max' => 100,
            ],
            [
                'key' => 'monitoring.cpu_crit', 'group' => 'Monitoring', 'label' => 'CPU critical (%)',
                'type' => 'int', 'min' => 1, 'max' => 100,
            ],
            [
                'key' => 'monitoring.mem_warn', 'group' => 'Monitoring', 'label' => 'Memory warn (%)',
                'type' => 'int', 'min' => 1, 'max' => 100,
            ],
            [
                'key' => 'monitoring.mem_crit', 'group' => 'Monitoring', 'label' => 'Memory critical (%)',
                'type' => 'int', 'min' => 1, 'max' => 100,
            ],
            [
                'key' => 'monitoring.disk_warn', 'group' => 'Monitoring', 'label' => 'Disk warn (%)',
                'type' => 'int', 'min' => 1, 'max' => 100,
            ],
            [
                'key' => 'monitoring.disk_crit', 'group' => 'Monitoring', 'label' => 'Disk critical (%)',
                'type' => 'int', 'min' => 1, 'max' => 100,
            ],
            [
                'key' => 'monitoring.load_warn', 'group' => 'Monitoring', 'label' => 'Load average warn',
                'type' => 'float', 'min' => 0, 'max' => 256,
            ],
            [
                'key' => 'monitoring.critical_services', 'group' => 'Monitoring',
                'label' => 'Critical services', 'type' => 'csv',
                'help' => 'Comma-separated systemd units that must always run (alerts fire if they stop).',
            ],

            // ---- Security / NIDS -------------------------------------
            [
                'key' => 'nids.default_block_minutes', 'group' => 'Security', 'label' => 'Default block duration (minutes)',
                'type' => 'int', 'min' => 1, 'max' => 525600,
                'help' => 'Duration applied when a block is created without an explicit time.',
            ],
            [
                'key' => 'nids.auto_block_threshold', 'group' => 'Security', 'label' => 'Auto-block threshold',
                'type' => 'int', 'min' => 1, 'max' => 1000,
                'help' => 'Number of scored events within the window before an IP is auto-blocked.',
            ],
            [
                'key' => 'nids.auto_block_window_min', 'group' => 'Security', 'label' => 'Auto-block window (minutes)',
                'type' => 'int', 'min' => 1, 'max' => 1440,
                'help' => 'Sliding window over which events are counted toward the threshold.',
            ],

            // ---- Threat intelligence ---------------------------------
            [
                'key' => 'threat_intel.enabled', 'group' => 'Threat Intelligence', 'label' => 'Enable threat intelligence',
                'type' => 'bool', 'help' => 'Master switch for DNSBL / AbuseIPDB reputation lookups.',
            ],
            [
                'key' => 'threat_intel.dnsbl_enabled', 'group' => 'Threat Intelligence', 'label' => 'Query DNSBLs',
                'type' => 'bool', 'help' => 'Check public DNS blocklists (Spamhaus, Barracuda, SpamCop, UCEPROTECT, s5h).',
            ],
            [
                'key' => 'threat_intel.abuseipdb_key', 'group' => 'Threat Intelligence', 'label' => 'AbuseIPDB API key',
                'type' => 'password', 'sensitive' => true,
                'help' => 'Optional. When set, IPs are cross-checked against AbuseIPDB.',
            ],
            [
                'key' => 'threat_intel.malicious_score', 'group' => 'Threat Intelligence', 'label' => 'Malicious score threshold',
                'type' => 'int', 'min' => 1, 'max' => 100,
                'help' => 'Combined confidence score at or above which an IP is treated as malicious.',
            ],
            [
                'key' => 'threat_intel.cache_hours', 'group' => 'Threat Intelligence', 'label' => 'Reputation cache (hours)',
                'type' => 'int', 'min' => 1, 'max' => 720, 'advanced' => true,
                'help' => 'How long a reputation verdict is trusted before it is considered stale.',
            ],
            [
                'key' => 'threat_intel.abuseipdb_max_age', 'group' => 'Threat Intelligence', 'label' => 'AbuseIPDB max report age (days)',
                'type' => 'int', 'min' => 1, 'max' => 365, 'advanced' => true,
            ],
            [
                'key' => 'threat_intel.auto_block', 'group' => 'Threat Intelligence', 'label' => 'Auto-block malicious IPs',
                'type' => 'bool', 'help' => 'Automatically block IPs the feed worker flags as malicious.',
            ],
            [
                'key' => 'threat_intel.auto_block_minutes', 'group' => 'Threat Intelligence', 'label' => 'Auto-block duration (minutes)',
                'type' => 'int', 'min' => 1, 'max' => 525600, 'advanced' => true,
            ],

            // ---- Notifications ---------------------------------------
            [
                'key' => 'notifications.enabled', 'group' => 'Notifications', 'label' => 'Enable notifications',
                'type' => 'bool', 'help' => 'Send operational alerts (email / SMS) via the notifications service.',
            ],
            [
                'key' => 'notifications.alert_email', 'group' => 'Notifications', 'label' => 'Alert email',
                'type' => 'string', 'help' => 'Where operational alerts are emailed.',
            ],
            [
                'key' => 'notifications.alert_sms', 'group' => 'Notifications', 'label' => 'Alert SMS',
                'type' => 'string', 'help' => 'Optional phone number for SMS alerts (E.164, e.g. +17325550123).',
            ],

            // ---- Traffic ---------------------------------------------
            [
                'key' => 'traffic.enabled', 'group' => 'Traffic', 'label' => 'Enable traffic collection',
                'type' => 'bool', 'help' => 'Parse Apache access logs into the traffic map and geo data.',
            ],
            [
                'key' => 'traffic.retention_days', 'group' => 'Traffic', 'label' => 'Retention (days)',
                'type' => 'int', 'min' => 1, 'max' => 3650,
                'help' => 'How long parsed traffic events are kept before pruning.',
            ],
            [
                'key' => 'traffic.collect_app_logs', 'group' => 'Traffic', 'label' => 'Collect app logs',
                'type' => 'bool', 'help' => 'Also capture recent per-app log lines during collection.',
            ],
            [
                'key' => 'traffic.app_log_lines', 'group' => 'Traffic', 'label' => 'App log lines',
                'type' => 'int', 'min' => 10, 'max' => 5000, 'advanced' => true,
            ],
            [
                'key' => 'traffic.max_lines_per_run', 'group' => 'Traffic', 'label' => 'Max access-log lines / run',
                'type' => 'int', 'min' => 100, 'max' => 500000, 'advanced' => true,
            ],
        ];
    }

    /** Ordered list of group names as they should appear in the UI. */
    private const GROUP_ORDER = [
        'General', 'Security', 'Threat Intelligence', 'Monitoring', 'Traffic', 'Notifications',
    ];

    /** Return the definition for a single key, or null. */
    private static function definition(string $key): ?array
    {
        foreach (self::registry() as $def) {
            if ($def['key'] === $key) {
                return $def;
            }
        }
        return null;
    }

    // -----------------------------------------------------------------
    // Reading
    // -----------------------------------------------------------------

    /**
     * All stored overrides as a flat map (dot.key => decoded value), limited
     * to keys that still exist in the registry. Best-effort: returns [] if the
     * settings table is not reachable yet (e.g. very early boot).
     */
    public static function overrides(): array
    {
        $out = [];
        try {
            $rows = Database::instance()->all(
                "SELECT skey, svalue FROM settings WHERE skey LIKE '" . self::PREFIX . "%'"
            );
        } catch (\Throwable $e) {
            return $out;
        }
        foreach ($rows as $row) {
            $key = substr((string) $row['skey'], strlen(self::PREFIX));
            if (self::definition($key) === null) {
                continue; // ignore stale keys no longer in the registry
            }
            $decoded = json_decode((string) $row['svalue'], true);
            $out[$key] = $decoded;
        }
        return $out;
    }

    /**
     * Apply every stored override onto the live App\Config. Called from
     * bootstrap after Config::init(). Safe to call when DB is unavailable.
     */
    public static function applyOverrides(): void
    {
        foreach (self::overrides() as $key => $value) {
            Config::overlay($key, $value);
        }
    }

    /** Effective value for a key (DB override if present, else file value). */
    public static function get(string $key, mixed $default = null): mixed
    {
        return Config::get($key, $default);
    }

    /**
     * Definitions grouped for the UI, each carrying the current effective
     * value, the underlying file default, and whether an override is active.
     * Sensitive values are masked.
     */
    public static function groups(): array
    {
        $overrides = self::overrides();
        $groups = [];
        foreach (self::registry() as $def) {
            $key = $def['key'];
            $sensitive = !empty($def['sensitive']);
            $effective = Config::get($key, self::typeDefault($def['type']));
            $fileVal = Config::fileDefault($key, self::typeDefault($def['type']));

            $item = [
                'key'        => $key,
                'label'      => $def['label'],
                'type'       => $def['type'],
                'help'       => $def['help'] ?? '',
                'advanced'   => !empty($def['advanced']),
                'overridden' => array_key_exists($key, $overrides),
            ];
            if (isset($def['min'])) { $item['min'] = $def['min']; }
            if (isset($def['max'])) { $item['max'] = $def['max']; }
            if (isset($def['options'])) { $item['options'] = $def['options']; }

            if ($sensitive) {
                $item['sensitive'] = true;
                $item['has_value'] = $effective !== null && $effective !== '';
                $item['value'] = '';       // never expose the real secret
                $item['default'] = '';
            } else {
                $item['value'] = self::presentValue($def['type'], $effective);
                $item['default'] = self::presentValue($def['type'], $fileVal);
            }

            $groups[$def['group']][] = $item;
        }

        // Emit in the preferred order, then any unlisted groups alphabetically.
        $ordered = [];
        foreach (self::GROUP_ORDER as $name) {
            if (isset($groups[$name])) {
                $ordered[] = ['name' => $name, 'settings' => $groups[$name]];
                unset($groups[$name]);
            }
        }
        ksort($groups);
        foreach ($groups as $name => $settings) {
            $ordered[] = ['name' => $name, 'settings' => $settings];
        }
        return $ordered;
    }

    // -----------------------------------------------------------------
    // Writing
    // -----------------------------------------------------------------

    /**
     * Persist a batch of key => value edits. Unknown keys are ignored;
     * per-key validation errors are collected and returned. Returns
     * ['ok' => bool, 'saved' => int, 'errors' => [key => msg]].
     */
    public static function saveMany(array $values, string $actor = 'system'): array
    {
        $saved = 0;
        $errors = [];
        foreach ($values as $key => $raw) {
            $def = self::definition((string) $key);
            if ($def === null) {
                continue; // silently skip anything not in the registry
            }
            // Sensitive: skip when the client sends the mask or an empty
            // string that means "leave unchanged".
            if (!empty($def['sensitive']) && ($raw === self::MASK || $raw === null)) {
                continue;
            }
            try {
                $clean = self::coerce($def, $raw);
            } catch (\InvalidArgumentException $e) {
                $errors[$key] = $e->getMessage();
                continue;
            }
            self::store((string) $key, $clean);
            Config::overlay((string) $key, $clean);
            $saved++;
        }

        if ($saved > 0) {
            AuditLogger::log('settings.update', 'settings', ['changed' => $saved], 'success', $saved . ' setting(s) changed');
        }
        return ['ok' => empty($errors), 'saved' => $saved, 'errors' => $errors];
    }

    /** Remove an override, reverting the key to its file default. */
    public static function reset(string $key, string $actor = 'system'): array
    {
        if (self::definition($key) === null) {
            return ['ok' => false, 'error' => 'Unknown setting.'];
        }
        Database::instance()->exec(
            'DELETE FROM settings WHERE skey = ?',
            [self::PREFIX . $key]
        );
        // Restore the file value into the live config for this request.
        Config::overlay($key, Config::fileDefault($key));
        AuditLogger::log('settings.reset', 'settings', ['key' => $key]);
        return ['ok' => true];
    }

    // -----------------------------------------------------------------
    // Statistics
    // -----------------------------------------------------------------

    /** Aggregate statistics surfaced on the Settings page. */
    public static function stats(): array
    {
        $db = Database::instance();

        return [
            'system'       => self::systemStats($db),
            'security'     => self::securityStats($db),
            'threat_intel' => self::threatIntelStats($db),
            'traffic'      => self::trafficStats($db),
            'apps'         => self::appStats($db),
        ];
    }

    private static function systemStats(Database $db): array
    {
        $out = [
            'schema_version' => null,
            'db_size_bytes'  => null,
            'hostname'       => php_uname('n'),
            'os'             => php_uname('s') . ' ' . php_uname('r'),
            'php_version'    => PHP_VERSION,
        ];
        try {
            $row = $db->one("SELECT svalue FROM settings WHERE skey = 'schema_version'");
            if ($row) {
                $out['schema_version'] = trim((string) json_decode((string) $row['svalue'], true), '"');
                if ($out['schema_version'] === '') {
                    $out['schema_version'] = trim((string) $row['svalue'], '"');
                }
            }
        } catch (\Throwable $e) { /* best-effort */ }
        try {
            $out['db_size_bytes'] = (int) $db->scalar(
                'SELECT COALESCE(SUM(data_length + index_length), 0)
                   FROM information_schema.tables WHERE table_schema = DATABASE()'
            );
        } catch (\Throwable $e) { /* best-effort */ }
        return $out;
    }

    private static function securityStats(Database $db): array
    {
        try {
            return [
                'active_blocks'  => (int) $db->scalar('SELECT COUNT(*) FROM blocked_hosts WHERE active = 1'),
                'permanent'      => (int) $db->scalar('SELECT COUNT(*) FROM blocked_hosts WHERE active = 1 AND permanent = 1'),
                'events_24h'     => (int) $db->scalar('SELECT COUNT(*) FROM nids_events WHERE created_at >= (NOW() - INTERVAL 24 HOUR)'),
                'critical_24h'   => (int) $db->scalar("SELECT COUNT(*) FROM nids_events WHERE severity IN ('high','critical') AND created_at >= (NOW() - INTERVAL 24 HOUR)"),
            ];
        } catch (\Throwable $e) {
            return [];
        }
    }

    private static function threatIntelStats(Database $db): array
    {
        $out = [
            'enabled'         => (bool) config('threat_intel.enabled', true),
            'dnsbl_enabled'   => (bool) config('threat_intel.dnsbl_enabled', true),
            'abuseipdb'       => trim((string) config('threat_intel.abuseipdb_key', '')) !== '',
            'auto_block'      => (bool) config('threat_intel.auto_block', false),
            'malicious_known' => 0,
            'checked_total'   => 0,
            'last_checked'    => null,
        ];
        $zones = config('threat_intel.dnsbl', []);
        $out['dnsbl_count'] = is_array($zones) && $zones ? count($zones) : 5;
        try {
            $out['malicious_known'] = (int) $db->scalar('SELECT COUNT(*) FROM ip_reputation WHERE is_malicious = 1');
            $out['checked_total']   = (int) $db->scalar('SELECT COUNT(*) FROM ip_reputation');
            $out['last_checked']    = $db->scalar('SELECT MAX(checked_at) FROM ip_reputation');
        } catch (\Throwable $e) { /* table may not exist yet */ }
        return $out;
    }

    private static function trafficStats(Database $db): array
    {
        try {
            return [
                'enabled'        => (bool) config('traffic.enabled', true),
                'events'         => (int) $db->scalar('SELECT COUNT(*) FROM traffic_events'),
                'distinct_src'   => (int) $db->scalar('SELECT COUNT(DISTINCT src_ip) FROM traffic_events'),
                'events_24h'     => (int) $db->scalar('SELECT COUNT(*) FROM traffic_events WHERE created_at >= (NOW() - INTERVAL 24 HOUR)'),
                'geo_cache'      => (int) $db->scalar('SELECT COUNT(*) FROM geo_cache'),
            ];
        } catch (\Throwable $e) {
            return [];
        }
    }

    private static function appStats(Database $db): array
    {
        try {
            $total = (int) $db->scalar('SELECT COUNT(*) FROM managed_apps');
            $rows = $db->all(
                "SELECT COALESCE(NULLIF(last_health, ''), 'unknown') AS health, COUNT(*) AS n
                   FROM managed_apps GROUP BY health"
            );
            $health = [];
            foreach ($rows as $r) {
                $health[(string) $r['health']] = (int) $r['n'];
            }
            return ['total' => $total, 'health' => $health];
        } catch (\Throwable $e) {
            return [];
        }
    }

    // -----------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------

    /** Persist one override as JSON. */
    private static function store(string $key, mixed $value): void
    {
        Database::instance()->exec(
            'INSERT INTO settings (skey, svalue) VALUES (?, ?)
             ON DUPLICATE KEY UPDATE svalue = VALUES(svalue)',
            [self::PREFIX . $key, json_encode($value, JSON_UNESCAPED_SLASHES)]
        );
    }

    /** Validate + cast a raw submitted value according to its definition. */
    private static function coerce(array $def, mixed $raw): mixed
    {
        switch ($def['type']) {
            case 'bool':
                return filter_var($raw, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) ?? (bool) $raw;

            case 'int':
                if (!is_numeric($raw)) {
                    throw new \InvalidArgumentException('Must be a number.');
                }
                $n = (int) $raw;
                if (isset($def['min']) && $n < $def['min']) { $n = (int) $def['min']; }
                if (isset($def['max']) && $n > $def['max']) { $n = (int) $def['max']; }
                return $n;

            case 'float':
                if (!is_numeric($raw)) {
                    throw new \InvalidArgumentException('Must be a number.');
                }
                $f = (float) $raw;
                if (isset($def['min']) && $f < $def['min']) { $f = (float) $def['min']; }
                if (isset($def['max']) && $f > $def['max']) { $f = (float) $def['max']; }
                return $f;

            case 'select':
                $val = (string) $raw;
                $options = $def['options'] ?? [];
                if (!in_array($val, $options, true)) {
                    throw new \InvalidArgumentException('Invalid option.');
                }
                return $val;

            case 'csv':
                $items = is_array($raw)
                    ? $raw
                    : array_map('trim', explode(',', (string) $raw));
                return array_values(array_filter(array_map('strval', $items), static fn ($v) => $v !== ''));

            case 'password':
            case 'string':
            case 'text':
            default:
                return trim((string) $raw);
        }
    }

    /** Normalise a stored/effective value for display in the UI. */
    private static function presentValue(string $type, mixed $value): mixed
    {
        return match ($type) {
            'bool'  => (bool) $value,
            'int'   => $value === null ? null : (int) $value,
            'float' => $value === null ? null : (float) $value,
            'csv'   => is_array($value)
                        ? implode(', ', $value)
                        : (string) ($value ?? ''),
            default => $value === null ? '' : (string) $value,
        };
    }

    private static function typeDefault(string $type): mixed
    {
        return match ($type) {
            'bool'  => false,
            'int'   => 0,
            'float' => 0.0,
            'csv'   => [],
            default => '',
        };
    }

}

<?php

declare(strict_types=1);

namespace App;

/**
 * Read-only diagnostics engine for the AI/LLM helper interface.
 *
 * Every method here is READ-ONLY. It exists so an operator (or an AI agent the
 * operator has handed a `diag`-scoped API token to) can introspect the platform
 * — logs, database, audit trail and live helper/API interactions — in order to
 * work out why a downstream app's services are misbehaving, WITHOUT being able
 * to mutate anything.
 *
 * Auth is handled by the API front controller (`Auth::requirePrivileged('diag')`)
 * so the only thing that can reach these methods is a caller holding a token
 * with the `diag` scope (or a `*` scope / admin user). The token is created
 * out-of-band with `php bin/token.php create ai-diag diag` and handed to the AI.
 *
 * See docs/DIAGNOSTICS.md.
 */
final class Diagnostics
{
    /** Helper actions probed by default when introspecting an app. */
    private const DEFAULT_PROBE_ACTIONS = ['health', 'version', 'stats', 'components', 'commands'];

    /** Tables the guarded SQL runner / schema browser is allowed to touch. */
    private const MAX_QUERY_ROWS = 1000;

    // -----------------------------------------------------------------
    // Self-documentation
    // -----------------------------------------------------------------

    /** Machine-readable catalogue of every diagnostics endpoint. */
    public static function catalog(): array
    {
        return [
            'ok'          => true,
            'interface'   => 'server-manager diagnostics',
            'read_only'   => true,
            'auth'        => 'Bearer token with the "diag" scope (Authorization: Bearer smgr_...)',
            'guide'       => 'docs/DIAGNOSTICS.md',
            'endpoints'   => [
                ['method' => 'GET',  'path' => '/api/diag',                        'desc' => 'This catalogue.'],
                ['method' => 'GET',  'path' => '/api/diag/overview',               'desc' => 'Platform health: versions, DB connectivity, 24h counts.'],
                ['method' => 'GET',  'path' => '/api/diag/apps',                   'desc' => 'Registered apps with pairing + last health state.'],
                ['method' => 'GET',  'path' => '/api/diag/apps/{id}/probe',        'desc' => 'Live-probe an app helper. RAW responses per action. ?actions=health,components'],
                ['method' => 'GET',  'path' => '/api/diag/apps/{id}/health-checks','desc' => 'Recent stored health-check history (decoded). ?limit=20'],
                ['method' => 'GET',  'path' => '/api/diag/logs',                   'desc' => 'Recent app log events. ?app_id&level&status_min&q&hours&limit'],
                ['method' => 'GET',  'path' => '/api/diag/audit',                  'desc' => 'Recent audit-log entries. ?action&target&result&actor&hours&limit'],
                ['method' => 'GET',  'path' => '/api/diag/schema',                 'desc' => 'List tables (approx row counts). ?table=<name> for columns.'],
                ['method' => 'POST', 'path' => '/api/diag/query',                  'desc' => 'Guarded read-only SELECT. Body: {"sql":"SELECT ...","limit":200}'],
                ['method' => 'GET',  'path' => '/api/diag/guide',                  'desc' => 'The full skill guide (plain text). Also public at /integrate/diagnostics.txt'],
            ],
        ];
    }

    // -----------------------------------------------------------------
    // Overview
    // -----------------------------------------------------------------

    public static function overview(): array
    {
        $db     = Database::instance();
        $dbOk   = true;
        $dbErr  = null;
        try {
            $db->scalar('SELECT 1');
        } catch (\Throwable $e) {
            $dbOk  = false;
            $dbErr = $e->getMessage();
        }

        return [
            'ok'   => true,
            'time' => date('c'),
            'app'  => [
                'name'     => (string) config('app.name', 'Server Manager'),
                'env'      => (string) config('app.env', 'production'),
                'debug'    => (bool) config('app.debug', false),
                'base_url' => (string) config('app.base_url', ''),
                'timezone' => (string) config('app.timezone', date_default_timezone_get()),
            ],
            'runtime' => [
                'php'         => PHP_VERSION,
                'sapi'        => PHP_SAPI,
                'server_time' => date('Y-m-d H:i:s'),
                'curl'        => \function_exists('curl_init'),
            ],
            'database' => [
                'ok'      => $dbOk,
                'name'    => (string) config('db.name', ''),
                'host'    => (string) config('db.host', ''),
                'error'   => $dbErr,
            ],
            'counts' => $dbOk ? [
                'apps_total'        => self::count('SELECT COUNT(*) FROM managed_apps'),
                'apps_paired'       => self::count("SELECT COUNT(*) FROM managed_apps WHERE helper_url IS NOT NULL AND helper_url <> '' AND helper_token IS NOT NULL"),
                'apps_unhealthy'    => self::count("SELECT COUNT(*) FROM managed_apps WHERE last_health IN ('unhealthy','degraded')"),
                'log_events_24h'    => self::count('SELECT COUNT(*) FROM app_log_events WHERE created_at >= (NOW() - INTERVAL 24 HOUR)'),
                'health_checks_24h' => self::count('SELECT COUNT(*) FROM app_health_checks WHERE checked_at >= (NOW() - INTERVAL 24 HOUR)'),
                'audit_24h'         => self::count('SELECT COUNT(*) FROM audit_log WHERE created_at >= (NOW() - INTERVAL 24 HOUR)'),
                'audit_failures_24h'=> self::count("SELECT COUNT(*) FROM audit_log WHERE result <> 'success' AND created_at >= (NOW() - INTERVAL 24 HOUR)"),
            ] : [],
        ];
    }

    // -----------------------------------------------------------------
    // Apps
    // -----------------------------------------------------------------

    public static function apps(): array
    {
        $rows = Database::instance()->all(
            'SELECT id, slug, name, domain, status, managed, helper_url, helper_token,
                    last_health, last_checked, updated_at
             FROM managed_apps ORDER BY name'
        );
        $apps = [];
        foreach ($rows as $r) {
            $apps[] = [
                'id'           => (int) $r['id'],
                'slug'         => $r['slug'],
                'name'         => $r['name'],
                'domain'       => $r['domain'],
                'status'       => $r['status'],
                'managed'      => (bool) $r['managed'],
                'helper_url'   => $r['helper_url'],
                'paired'       => !empty($r['helper_url']) && !empty($r['helper_token']),
                'last_health'  => $r['last_health'],
                'last_checked' => $r['last_checked'],
                'updated_at'   => $r['updated_at'],
            ];
        }
        return ['ok' => true, 'count' => count($apps), 'apps' => $apps];
    }

    /**
     * Live-probe an app's helper endpoint and return the RAW response for each
     * requested action. This is the primary tool for debugging "the app's
     * services aren't working" — it shows the exact HTTP status, whether the
     * body parsed as JSON, any app-reported error and a raw body snippet.
     */
    public static function probeApp(int $id, ?array $actions = null): array
    {
        $app = AppManager::find($id);
        if (!$app) {
            return ['ok' => false, 'error' => 'app not found'];
        }

        $actions = $actions ?: self::DEFAULT_PROBE_ACTIONS;
        // Whitelist to a safe, read-only set of helper actions.
        $allowed = ['health', 'version', 'stats', 'components', 'commands', 'logs', 'ping'];
        $actions = array_values(array_intersect(array_map('strval', $actions), $allowed));
        if (!$actions) {
            $actions = self::DEFAULT_PROBE_ACTIONS;
        }

        $probes = [];
        foreach ($actions as $action) {
            $probes[$action] = AppManager::rawHelperCall($id, $action);
        }

        return [
            'ok'  => true,
            'app' => [
                'id'         => (int) $app['id'],
                'slug'       => $app['slug'],
                'name'       => $app['name'],
                'domain'     => $app['domain'] ?? null,
                'helper_url' => $app['helper_url'] ?? null,
                'paired'     => !empty($app['helper_url']) && !empty($app['helper_token']),
            ],
            'probes' => $probes,
        ];
    }

    public static function healthChecks(int $appId, int $limit = 20): array
    {
        $limit = max(1, min($limit, 100));
        $rows  = Database::instance()->all(
            'SELECT id, status, trigger_type, http_ok, http_status, http_time_ms,
                    helper_ok, helper_status, detail, checked_at
             FROM app_health_checks WHERE app_id = ? ORDER BY checked_at DESC LIMIT ' . $limit,
            [$appId]
        );
        foreach ($rows as &$r) {
            $r['detail'] = isset($r['detail']) && $r['detail'] !== null
                ? json_decode((string) $r['detail'], true)
                : null;
        }
        unset($r);
        return ['ok' => true, 'count' => count($rows), 'checks' => $rows];
    }

    // -----------------------------------------------------------------
    // Logs & audit
    // -----------------------------------------------------------------

    public static function logs(array $q): array
    {
        $limit = max(1, min((int) ($q['limit'] ?? 100), self::MAX_QUERY_ROWS));
        $hours = max(1, min((int) ($q['hours'] ?? 24), 24 * 30));

        $where  = ['created_at >= (NOW() - INTERVAL ' . $hours . ' HOUR)'];
        $params = [];
        if (!empty($q['app_id'])) {
            $where[]  = 'app_id = ?';
            $params[] = (int) $q['app_id'];
        }
        if (!empty($q['level'])) {
            $where[]  = 'level = ?';
            $params[] = (string) $q['level'];
        }
        if (isset($q['status_min']) && $q['status_min'] !== '') {
            $where[]  = 'status_code >= ?';
            $params[] = (int) $q['status_min'];
        }
        if (!empty($q['q'])) {
            $where[]  = '(path LIKE ? OR message LIKE ?)';
            $params[] = '%' . $q['q'] . '%';
            $params[] = '%' . $q['q'] . '%';
        }

        $rows = Database::instance()->all(
            'SELECT id, app_id, app_slug, level, src_ip, method, path, status_code,
                    bytes, message, logged_at, created_at
             FROM app_log_events WHERE ' . implode(' AND ', $where) . '
             ORDER BY id DESC LIMIT ' . $limit,
            $params
        );
        return ['ok' => true, 'count' => count($rows), 'events' => $rows];
    }

    public static function audit(array $q): array
    {
        $limit = max(1, min((int) ($q['limit'] ?? 100), self::MAX_QUERY_ROWS));
        $hours = max(1, min((int) ($q['hours'] ?? 24), 24 * 30));

        $where  = ['created_at >= (NOW() - INTERVAL ' . $hours . ' HOUR)'];
        $params = [];
        if (!empty($q['action'])) {
            $where[]  = 'action LIKE ?';
            $params[] = '%' . $q['action'] . '%';
        }
        if (!empty($q['target'])) {
            $where[]  = 'target LIKE ?';
            $params[] = '%' . $q['target'] . '%';
        }
        if (!empty($q['actor'])) {
            $where[]  = 'actor LIKE ?';
            $params[] = '%' . $q['actor'] . '%';
        }
        if (!empty($q['result'])) {
            $where[]  = 'result = ?';
            $params[] = (string) $q['result'];
        }

        $rows = Database::instance()->all(
            'SELECT id, actor, actor_type, action, target, params, result, message, ip_address, created_at
             FROM audit_log WHERE ' . implode(' AND ', $where) . '
             ORDER BY id DESC LIMIT ' . $limit,
            $params
        );
        foreach ($rows as &$r) {
            if (isset($r['params']) && $r['params'] !== null) {
                $decoded = json_decode((string) $r['params'], true);
                $r['params'] = $decoded ?? $r['params'];
            }
        }
        unset($r);
        return ['ok' => true, 'count' => count($rows), 'entries' => $rows];
    }

    // -----------------------------------------------------------------
    // Schema & guarded SQL
    // -----------------------------------------------------------------

    public static function schema(?string $table = null): array
    {
        $db = Database::instance();

        if ($table !== null && $table !== '') {
            if (!preg_match('/^[A-Za-z0-9_]+$/', $table)) {
                return ['ok' => false, 'error' => 'invalid table name'];
            }
            $cols = $db->all(
                'SELECT COLUMN_NAME AS name, COLUMN_TYPE AS type, IS_NULLABLE AS nullable,
                        COLUMN_KEY AS `key`, COLUMN_DEFAULT AS `default`, EXTRA AS extra
                 FROM information_schema.COLUMNS
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
                 ORDER BY ORDINAL_POSITION',
                [$table]
            );
            if (!$cols) {
                return ['ok' => false, 'error' => 'unknown table'];
            }
            return ['ok' => true, 'table' => $table, 'columns' => $cols];
        }

        $tables = $db->all(
            'SELECT TABLE_NAME AS name, TABLE_ROWS AS approx_rows, DATA_LENGTH AS data_bytes
             FROM information_schema.TABLES
             WHERE TABLE_SCHEMA = DATABASE()
             ORDER BY TABLE_NAME'
        );
        return ['ok' => true, 'count' => count($tables), 'tables' => $tables];
    }

    /**
     * Guarded read-only SQL runner. Accepts a SINGLE SELECT/WITH statement only.
     *
     * Defences:
     *   - must begin with SELECT or WITH
     *   - no ";" (single statement only — blocks stacked queries)
     *   - blocks file access / timing gadgets (INTO OUTFILE/DUMPFILE, LOAD_FILE,
     *     SLEEP(), BENCHMARK(), GET_LOCK())
     *   - a LIMIT is appended when absent and every result set is capped
     *
     * This is deliberately powerful (arbitrary reads across the schema) and is
     * only reachable with the `diag` scope, which the operator controls and can
     * revoke at any time via bin/token.php.
     */
    public static function query(string $sql, int $limit = 200): array
    {
        $sql = trim($sql);
        if ($sql === '') {
            return ['ok' => false, 'error' => 'empty query'];
        }
        if (strpos($sql, ';') !== false) {
            return ['ok' => false, 'error' => 'only a single statement is allowed (remove ";")'];
        }
        if (!preg_match('/^(select|with)\b/i', $sql)) {
            return ['ok' => false, 'error' => 'only read-only SELECT / WITH queries are allowed'];
        }
        if (preg_match('/(into\s+(outfile|dumpfile)|\bload_file\s*\(|\bsleep\s*\(|\bbenchmark\s*\(|\bget_lock\s*\(|\brelease_lock\s*\()/i', $sql)) {
            return ['ok' => false, 'error' => 'query contains a disallowed construct (file access / timing gadget)'];
        }

        $limit = max(1, min($limit, self::MAX_QUERY_ROWS));
        if (!preg_match('/\blimit\s+\d+/i', $sql)) {
            $sql .= ' LIMIT ' . $limit;
        }

        try {
            $rows = Database::instance()->all($sql);
        } catch (\Throwable $e) {
            return ['ok' => false, 'error' => 'query failed: ' . $e->getMessage()];
        }

        $rows = array_slice($rows, 0, $limit);
        return [
            'ok'        => true,
            'row_count' => count($rows),
            'columns'   => $rows ? array_keys($rows[0]) : [],
            'rows'      => $rows,
        ];
    }

    // -----------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------

    private static function count(string $sql): int
    {
        try {
            return (int) Database::instance()->scalar($sql);
        } catch (\Throwable $e) {
            return -1;
        }
    }
}

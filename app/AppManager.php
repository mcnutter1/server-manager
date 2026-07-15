<?php

declare(strict_types=1);

namespace App;

/**
 * Managed applications registry + discovery.
 *
 * The platform provides a common interface to individually-deployed apps that
 * each own their code + database under apps_root (e.g. /var/www/<app>). Apps
 * opt into deeper integration by shipping a small "helper" endpoint (see
 * docs/APP_HELPER.md) that this class can call for health, stats and actions.
 */
final class AppManager
{
    // -----------------------------------------------------------------
    // Registry CRUD
    // -----------------------------------------------------------------
    public static function all(bool $includeUnmanaged = true): array
    {
        $sql = 'SELECT * FROM managed_apps';
        if (!$includeUnmanaged) {
            $sql .= ' WHERE managed = 1';
        }
        $sql .= ' ORDER BY managed DESC, name ASC';
        return Database::instance()->all($sql);
    }

    public static function find(int $id): ?array
    {
        return Database::instance()->one('SELECT * FROM managed_apps WHERE id = ?', [$id]);
    }

    public static function findBySlug(string $slug): ?array
    {
        return Database::instance()->one('SELECT * FROM managed_apps WHERE slug = ?', [$slug]);
    }

    public static function register(array $input): array
    {
        $slug = self::slugify($input['slug'] ?? $input['name'] ?? '');
        if ($slug === '') {
            return ['ok' => false, 'error' => 'name/slug required'];
        }
        $path = rtrim((string) ($input['path'] ?? ''), '/');
        if ($path === '' || !self::pathAllowed($path)) {
            return ['ok' => false, 'error' => 'path must be inside ' . config('app.apps_root')];
        }

        $db = Database::instance();
        $existing = $db->one('SELECT id FROM managed_apps WHERE slug = ? OR path = ?', [$slug, $path]);

        $data = [
            'slug'         => $slug,
            'name'         => $input['name'] ?? $slug,
            'description'  => $input['description'] ?? null,
            'path'         => $path,
            'domain'       => $input['domain'] ?? null,
            'repo_url'     => $input['repo_url'] ?? null,
            'db_name'      => $input['db_name'] ?? null,
            'db_user'      => $input['db_user'] ?? null,
            'service_name' => $input['service_name'] ?? null,
            'health_url'   => $input['health_url'] ?? null,
            'helper_path'  => $input['helper_path'] ?? 'srvmgr/helper.php',
            'helper_token' => $input['helper_token'] ?? null,
            'status'       => $input['status'] ?? 'active',
            'managed'      => 1,
            'meta'         => isset($input['meta']) ? json_encode($input['meta']) : null,
        ];

        if ($existing) {
            unset($data['slug']); // don't change identity on update
            $set = implode(', ', array_map(static fn ($k) => "{$k} = :{$k}", array_keys($data)));
            $data['id'] = $existing['id'];
            $db->exec("UPDATE managed_apps SET {$set} WHERE id = :id", $data);
            $id = (int) $existing['id'];
            AuditLogger::log('app.update', $slug, ['id' => $id]);
        } else {
            $id = $db->insert('managed_apps', $data);
            AuditLogger::log('app.register', $slug, ['id' => $id, 'path' => $path]);
        }

        return ['ok' => true, 'id' => $id, 'app' => self::find($id)];
    }

    public static function setStatus(int $id, string $status): array
    {
        $allowed = ['active', 'disabled', 'maintenance'];
        if (!in_array($status, $allowed, true)) {
            return ['ok' => false, 'error' => 'invalid status'];
        }
        $app = self::find($id);
        if (!$app) {
            return ['ok' => false, 'error' => 'not found'];
        }
        Database::instance()->exec('UPDATE managed_apps SET status = ? WHERE id = ?', [$status, $id]);
        AuditLogger::log('app.status', $app['slug'], ['status' => $status]);
        return ['ok' => true, 'id' => $id, 'status' => $status];
    }

    public static function remove(int $id): array
    {
        $app = self::find($id);
        if (!$app) {
            return ['ok' => false, 'error' => 'not found'];
        }
        Database::instance()->exec('DELETE FROM managed_apps WHERE id = ?', [$id]);
        AuditLogger::log('app.remove', $app['slug'], ['id' => $id]);
        return ['ok' => true];
    }

    // -----------------------------------------------------------------
    // Discovery — scan apps_root for unmanaged apps.
    // -----------------------------------------------------------------
    public static function discover(): array
    {
        $root = rtrim((string) config('app.apps_root', '/var/www'), '/');
        if (!is_dir($root)) {
            return ['ok' => false, 'error' => "apps_root {$root} not found", 'discovered' => []];
        }

        $known = [];
        foreach (self::all() as $app) {
            $known[$app['path']] = true;
        }

        $selfPath = SM_ROOT;
        $found = [];

        foreach (glob($root . '/*', GLOB_ONLYDIR) ?: [] as $dir) {
            // Skip our own install and already-registered paths.
            if ($dir === $selfPath || isset($known[$dir])) {
                continue;
            }
            $name = basename($dir);
            if (in_array($name, ['html'], true) && !self::looksLikeApp($dir)) {
                // default docroot; only include if it looks like an app
            }
            $found[] = [
                'name'        => $name,
                'path'        => $dir,
                'detected'    => self::detectStack($dir),
                'has_git'     => is_dir($dir . '/.git'),
                'has_helper'  => is_file($dir . '/srvmgr/helper.php'),
                'size_bytes'  => self::dirSizeApprox($dir),
                'modified'    => date('c', @filemtime($dir) ?: time()),
            ];
        }

        return ['ok' => true, 'root' => $root, 'discovered' => $found];
    }

    private static function looksLikeApp(string $dir): bool
    {
        return is_file($dir . '/index.php')
            || is_file($dir . '/composer.json')
            || is_file($dir . '/package.json')
            || is_dir($dir . '/public');
    }

    private static function detectStack(string $dir): array
    {
        $stack = [];
        if (glob($dir . '/*.php') || is_file($dir . '/index.php')) $stack[] = 'php';
        if (is_file($dir . '/composer.json')) $stack[] = 'composer';
        if (is_file($dir . '/package.json'))  $stack[] = 'node';
        if (is_file($dir . '/requirements.txt') || is_file($dir . '/manage.py')) $stack[] = 'python';
        if (is_file($dir . '/artisan')) $stack[] = 'laravel';
        if (is_file($dir . '/wp-config.php')) $stack[] = 'wordpress';
        return $stack ?: ['unknown'];
    }

    private static function dirSizeApprox(string $dir): int
    {
        // Cheap approximation — top-level files only to avoid heavy recursion.
        $size = 0;
        foreach (glob($dir . '/*') ?: [] as $f) {
            if (is_file($f)) {
                $size += (int) @filesize($f);
            }
        }
        return $size;
    }

    // -----------------------------------------------------------------
    // Health checks
    // -----------------------------------------------------------------
    /** Check one app: HTTP health_url and/or its helper endpoint. */
    public static function checkHealth(int $id): array
    {
        $app = self::find($id);
        if (!$app) {
            return ['ok' => false, 'error' => 'not found'];
        }

        $result = ['app_id' => $id, 'slug' => $app['slug'], 'checks' => []];
        $overall = 'unknown';

        if (!empty($app['health_url'])) {
            $http = self::httpProbe($app['health_url']);
            $result['checks']['http'] = $http;
            $overall = $http['ok'] ? 'healthy' : 'unhealthy';
        }

        $helper = self::callHelper($app, 'health');
        if ($helper['ok']) {
            $result['checks']['helper'] = $helper['data'];
            $status = $helper['data']['status'] ?? 'healthy';
            $overall = $status === 'ok' || $status === 'healthy' ? 'healthy' : 'degraded';
        }

        Database::instance()->exec(
            'UPDATE managed_apps SET last_health = ?, last_checked = NOW() WHERE id = ?',
            [$overall, $id]
        );

        $result['status'] = $overall;
        return ['ok' => true] + $result;
    }

    private static function httpProbe(string $url): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 6,
            CURLOPT_NOBODY         => false,
            CURLOPT_FOLLOWLOCATION => true,
        ]);
        $start = microtime(true);
        curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return [
            'ok'      => $code >= 200 && $code < 400,
            'status'  => $code,
            'time_ms' => (int) round((microtime(true) - $start) * 1000),
        ];
    }

    /**
     * Call the app's common helper endpoint. Contract (docs/APP_HELPER.md):
     *   POST {app}/{helper_path}
     *   Header: X-Srvmgr-Token: <helper_token>
     *   Body:   { "action": "health|stats|migrate|clear_cache|...", ... }
     *   Reply:  { "ok": true, "data": {...} }
     */
    public static function callHelper(array $app, string $action, array $params = []): array
    {
        if (empty($app['domain']) && empty($app['helper_url'])) {
            // Without a domain we cannot reach the helper over HTTP.
            return ['ok' => false, 'error' => 'no domain configured for helper'];
        }
        $base = !empty($app['helper_url'])
            ? $app['helper_url']
            : rtrim('https://' . $app['domain'], '/') . '/' . ltrim((string) $app['helper_path'], '/');

        $ch = curl_init($base);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 12,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/json',
                'X-Srvmgr-Token: ' . (string) ($app['helper_token'] ?? ''),
            ],
            CURLOPT_POSTFIELDS     => json_encode(['action' => $action] + $params, JSON_UNESCAPED_SLASHES),
        ]);
        $body = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $json = json_decode((string) $body, true);
        if ($code >= 200 && $code < 300 && is_array($json)) {
            AuditLogger::log('app.helper', $app['slug'], ['action' => $action]);
            return ['ok' => (bool) ($json['ok'] ?? true), 'data' => $json['data'] ?? $json];
        }
        return ['ok' => false, 'error' => "helper HTTP {$code}", 'raw' => $body];
    }

    // -----------------------------------------------------------------
    // Utils
    // -----------------------------------------------------------------
    private static function slugify(string $value): string
    {
        $value = strtolower(trim($value));
        $value = preg_replace('/[^a-z0-9]+/', '-', $value) ?? '';
        return trim($value, '-');
    }

    private static function pathAllowed(string $path): bool
    {
        $root = rtrim((string) config('app.apps_root', '/var/www'), '/');
        $real = realpath($path) ?: $path;
        return str_starts_with($real, $root . '/') || $real === $root;
    }
}

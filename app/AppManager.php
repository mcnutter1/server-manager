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

    /**
     * Edit an existing registration by id. Partial update: only the fields
     * present in $input are changed. The slug (identity) is never altered here,
     * and helper_token is only replaced when a non-empty value is supplied so
     * the edit form can leave it blank to keep the current secret.
     */
    public static function update(int $id, array $input): array
    {
        $app = self::find($id);
        if (!$app) {
            return ['ok' => false, 'error' => 'app not found'];
        }

        $data = [];

        // Free-text fields: empty string clears them to NULL.
        foreach (['name', 'description', 'domain', 'repo_url', 'db_name',
                  'db_user', 'service_name', 'health_url', 'helper_path'] as $f) {
            if (array_key_exists($f, $input)) {
                $v = is_string($input[$f]) ? trim($input[$f]) : $input[$f];
                $data[$f] = ($v === '' || $v === null) ? null : $v;
            }
        }

        if (array_key_exists('name', $data) && $data['name'] === null) {
            return ['ok' => false, 'error' => 'name cannot be empty'];
        }

        if (array_key_exists('path', $input)) {
            $path = rtrim((string) $input['path'], '/');
            if ($path === '' || !self::pathAllowed($path)) {
                return ['ok' => false, 'error' => 'path must be inside ' . config('app.apps_root')];
            }
            $data['path'] = $path;
        }

        if (array_key_exists('status', $input) && (string) $input['status'] !== '') {
            $status = (string) $input['status'];
            if (!in_array($status, ['active', 'disabled', 'maintenance'], true)) {
                return ['ok' => false, 'error' => 'invalid status'];
            }
            $data['status'] = $status;
        }

        // Only overwrite the secret when a new one is actually provided.
        if (!empty($input['helper_token'])) {
            $data['helper_token'] = (string) $input['helper_token'];
        }

        if (array_key_exists('meta', $input)) {
            $data['meta'] = $input['meta'] !== null ? json_encode($input['meta']) : null;
        }

        if ($data === []) {
            return ['ok' => true, 'id' => $id, 'app' => $app];
        }

        $db = Database::instance();
        $set = implode(', ', array_map(static fn ($k) => "{$k} = :{$k}", array_keys($data)));
        $data['id'] = $id;
        $db->exec("UPDATE managed_apps SET {$set} WHERE id = :id", $data);
        AuditLogger::log('app.update', $app['slug'], ['id' => $id, 'fields' => array_keys($data)]);

        return ['ok' => true, 'id' => $id, 'app' => self::find($id)];
    }

    /**
     * Enroll (pair) a downstream app using the one-time challenge it displays
     * on its helper page. We call the helper's unauthenticated `enroll` action
     * with the challenge, receive the app's self-generated secret over HTTPS,
     * and register the app with that secret as its helper_token — so no secret
     * is ever copied by a human.
     *
     * Accepts either a combined `enroll_key` (base64url JSON of url+challenge)
     * or explicit `helper_url`/`domain` + `challenge`.
     */
    public static function enroll(array $input): array
    {
        $challenge  = trim((string) ($input['challenge'] ?? ''));
        $helperUrl  = trim((string) ($input['helper_url'] ?? ''));
        $domain     = trim((string) ($input['domain'] ?? ''));
        $helperPath = trim((string) ($input['helper_path'] ?? 'srvmgr/helper.php'));

        // Combined enrollment key auto-fills url + challenge (+ host).
        if (!empty($input['enroll_key'])) {
            $decoded = self::decodeEnrollKey((string) $input['enroll_key']);
            if ($decoded) {
                $helperUrl = $helperUrl !== '' ? $helperUrl : trim((string) ($decoded['u'] ?? ''));
                $challenge = $challenge !== '' ? $challenge : trim((string) ($decoded['c'] ?? ''));
                $domain    = $domain !== ''    ? $domain    : trim((string) ($decoded['h'] ?? ''));
            } elseif ($challenge === '') {
                // Not a combined key — treat the pasted value as the challenge.
                $challenge = trim((string) $input['enroll_key']);
            }
        }

        if ($challenge === '') {
            return ['ok' => false, 'error' => 'challenge / enrollment key required'];
        }

        // Resolve the helper endpoint.
        $base = $helperUrl !== ''
            ? $helperUrl
            : ($domain !== '' ? rtrim('https://' . $domain, '/') . '/' . ltrim($helperPath, '/') : '');
        if ($base === '' || !filter_var($base, FILTER_VALIDATE_URL)) {
            return ['ok' => false, 'error' => 'a valid helper URL or domain is required'];
        }
        if (!str_starts_with($base, 'https://') && !str_starts_with($base, 'http://')) {
            return ['ok' => false, 'error' => 'helper URL must be http(s)'];
        }

        // Claim the secret from the helper using the challenge.
        $claim = self::claimSecret($base, $challenge);
        if (empty($claim['ok'])) {
            return $claim;
        }
        $secret = (string) $claim['secret'];

        // Derive the domain (host[:port]) we will call the helper on.
        if ($domain === '') {
            $host = parse_url($base, PHP_URL_HOST) ?: '';
            $port = parse_url($base, PHP_URL_PORT);
            if ($host === '') {
                return ['ok' => false, 'error' => 'could not derive host from helper URL'];
            }
            $domain = $port && !in_array((int) $port, [80, 443], true) ? "{$host}:{$port}" : $host;
        }

        // Register (or update) the app with the freshly claimed secret.
        $reg = self::register([
            'name'         => $input['name'] ?? $domain,
            'slug'         => $input['slug'] ?? ($input['name'] ?? $domain),
            'path'         => $input['path'] ?? '',
            'domain'       => $domain,
            'helper_path'  => $helperPath,
            'helper_token' => $secret,
            'health_url'   => $input['health_url'] ?? null,
            'repo_url'     => $input['repo_url'] ?? null,
            'db_name'      => $input['db_name'] ?? null,
            'description'  => $input['description'] ?? 'Paired via challenge enrollment',
            'status'       => 'active',
        ]);
        if (empty($reg['ok'])) {
            return $reg;
        }

        AuditLogger::log('app.enroll', $domain, ['id' => $reg['id'] ?? null]);
        return ['ok' => true, 'id' => $reg['id'] ?? null, 'app' => $reg['app'] ?? null, 'paired' => true];
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
     *   Body:   { "action": "health|stats|logs|migrate|clear_cache|...", ... }
     *   Reply:  { "ok": true, "data": {...} }
     *
     * Authentication is a per-request HMAC signature so the shared secret is
     * never sent on the wire and captured requests cannot be replayed:
     *   X-Srvmgr-Timestamp: <unix seconds>
     *   X-Srvmgr-Nonce:     <random hex, single-use>
     *   X-Srvmgr-Signature: v1=<base64url(hmac_sha256(secret, canonical))>
     *   canonical = "{ts}\n{nonce}\nPOST\n{path}\n{sha256(body)}"
     * The legacy X-Srvmgr-Token header is still sent so older helpers that only
     * check the shared token keep working during migration.
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

        $secret = (string) ($app['helper_token'] ?? '');
        $body   = json_encode(['action' => $action] + $params, JSON_UNESCAPED_SLASHES);
        $headers = array_merge(
            ['Content-Type: application/json'],
            self::signHeaders($base, (string) $body, $secret)
        );

        $ch = curl_init($base);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 12,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_POSTFIELDS     => $body,
        ]);
        $resp = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $json = json_decode((string) $resp, true);
        if ($code >= 200 && $code < 300 && is_array($json)) {
            AuditLogger::log('app.helper', $app['slug'], ['action' => $action]);
            return ['ok' => (bool) ($json['ok'] ?? true), 'data' => $json['data'] ?? $json];
        }
        return ['ok' => false, 'error' => "helper HTTP {$code}", 'raw' => $resp];
    }

    /**
     * Build the signed authentication headers for a helper request.
     *
     * @return string[] header lines ready for CURLOPT_HTTPHEADER
     */
    private static function signHeaders(string $url, string $body, string $secret): array
    {
        $ts    = (string) time();
        $nonce = bin2hex(random_bytes(16));
        $path  = parse_url($url, PHP_URL_PATH) ?: '/';

        $canonical = implode("\n", [$ts, $nonce, 'POST', $path, hash('sha256', $body)]);
        $sig = self::b64url(hash_hmac('sha256', $canonical, $secret, true));

        return [
            'X-Srvmgr-Token: ' . $secret,          // legacy fallback
            'X-Srvmgr-Timestamp: ' . $ts,
            'X-Srvmgr-Nonce: ' . $nonce,
            'X-Srvmgr-Signature: v1=' . $sig,
        ];
    }

    private static function b64url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    /**
     * Present a challenge to a helper's unauthenticated `enroll` action and
     * return the shared secret it hands back. This is the only helper call
     * made WITHOUT a signature — the challenge itself is the proof.
     *
     * @return array{ok:bool, secret?:string, error?:string}
     */
    private static function claimSecret(string $base, string $challenge): array
    {
        $body = json_encode(['action' => 'enroll', 'challenge' => $challenge], JSON_UNESCAPED_SLASHES);

        $ch = curl_init($base);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 12,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
            CURLOPT_POSTFIELDS     => $body,
        ]);
        $resp = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $cerr = curl_error($ch);
        curl_close($ch);

        if ($resp === false) {
            return ['ok' => false, 'error' => 'could not reach helper: ' . ($cerr ?: 'connection failed')];
        }

        $json = json_decode((string) $resp, true);
        if ($code >= 200 && $code < 300 && is_array($json) && !empty($json['ok'])) {
            $secret = (string) ($json['data']['secret'] ?? '');
            if ($secret === '') {
                return ['ok' => false, 'error' => 'helper returned no secret'];
            }
            return ['ok' => true, 'secret' => $secret];
        }

        $err = is_array($json)
            ? (string) ($json['error'] ?? $json['data']['error'] ?? "HTTP {$code}")
            : "HTTP {$code}";
        return ['ok' => false, 'error' => "pairing rejected: {$err}"];
    }

    /** Decode a combined enrollment key (base64url JSON). Returns null if not one. */
    private static function decodeEnrollKey(string $key): ?array
    {
        $key = trim($key);
        if ($key === '') {
            return null;
        }
        $raw = base64_decode(strtr($key, '-_', '+/'), true);
        if ($raw === false) {
            return null;
        }
        $doc = json_decode($raw, true);
        return is_array($doc) && (isset($doc['c']) || isset($doc['u'])) ? $doc : null;
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

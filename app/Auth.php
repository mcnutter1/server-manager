<?php

declare(strict_types=1);

namespace App;

/**
 * Authentication + authorization facade.
 *
 * Bridges the McNutt Cloud client_helper (SSO + API keys) into the platform
 * and adds local machine tokens (api_tokens table) for automation.
 */
final class Auth
{
    private static ?array $current = null;   // resolved actor for this request
    private static bool $helperLoaded = false;

    // -----------------------------------------------------------------
    // Helper loading
    // -----------------------------------------------------------------
    private static function loadHelper(): void
    {
        if (self::$helperLoaded) {
            return;
        }
        $helper = SM_ROOT . '/client_helper/auth.php';
        if (is_file($helper)) {
            require_once $helper;
        }
        self::$helperLoaded = true;
    }

    // -----------------------------------------------------------------
    // Browser (SSO) protection — used by index.php / page routes.
    // -----------------------------------------------------------------
    public static function requireWeb(): array
    {
        if (!config('auth.enabled', true)) {
            self::$current = self::devActor();
            return self::$current;
        }

        self::loadHelper();

        // Process an SSO return: the login service redirects back to our
        // return_url with ?payload=&sig=. Consume it here (sets the session
        // cookie + redirects to a clean URL) so we don't loop back to login.
        if (function_exists('handle_sso_callback')
            && isset($_GET['payload'], $_GET['sig'])) {
            handle_sso_callback();
        }

        $allowed = config('auth.allowed_roles', []);
        $auth = ensure_role($allowed, 'any');  // redirects on failure

        self::$current = [
            'name'  => $auth['identity']['email'] ?? ($auth['identity']['name'] ?? 'unknown'),
            'type'  => 'user',
            'roles' => $auth['roles'] ?? [],
            'identity' => $auth['identity'] ?? [],
        ];
        return self::$current;
    }

    // -----------------------------------------------------------------
    // API protection — used by the REST router.
    // Order: local machine token -> McNutt API key -> SSO cookie.
    // -----------------------------------------------------------------
    public static function authenticateApi(): array
    {
        if (!config('auth.enabled', true)) {
            return self::$current = self::devActor();
        }

        self::loadHelper();
        $rawKey = function_exists('extract_api_key_c') ? extract_api_key_c() : null;

        // 1) Local machine token (this platform's own tokens).
        if ($rawKey !== null) {
            $local = self::resolveLocalToken($rawKey);
            if ($local !== null) {
                return self::$current = $local;
            }

            // 2) McNutt Cloud personal/system API key.
            $validated = validate_api_key_c($rawKey);
            if ($validated !== null) {
                $roles = $validated['roles'] ?? [];
                if (!self::rolesIntersect($roles, config('auth.allowed_roles', []))) {
                    Response::denied('Your account lacks access to Server Manager.');
                }
                return self::$current = [
                    'name'  => $validated['identity']['email'] ?? 'api-user',
                    'type'  => 'user',
                    'roles' => $roles,
                    'scopes' => ['*'],
                    'identity' => $validated['identity'] ?? [],
                ];
            }
            Response::unauthorized('Invalid API token.');
        }

        // 3) Same-origin browser session (SPA XHR carries the SSO cookie).
        $identity = function_exists('read_identity_cookie_c') ? read_identity_cookie_c() : null;
        if ($identity && !empty($identity['session_token'])) {
            $fresh = revalidate($identity['session_token']);
            if ($fresh !== false) {
                $roles = $fresh['roles'] ?? ($identity['roles'] ?? []);
                if (!self::rolesIntersect($roles, config('auth.allowed_roles', []))) {
                    Response::denied('Your account lacks access to Server Manager.');
                }
                return self::$current = [
                    'name'  => $fresh['identity']['email'] ?? ($identity['identity']['email'] ?? 'user'),
                    'type'  => 'user',
                    'roles' => $roles,
                    'scopes' => ['*'],
                    'identity' => $fresh['identity'] ?? ($identity['identity'] ?? []),
                ];
            }
        }

        Response::unauthorized('Authentication required.');
    }

    /** Require the actor to hold an admin/ops role (or a scope) before mutating. */
    public static function requirePrivileged(string $scope = 'admin'): void
    {
        $actor = self::$current ?? self::authenticateApi();

        // Token actors are checked by scope.
        if ($actor['type'] === 'token') {
            $scopes = $actor['scopes'] ?? [];
            if (in_array('*', $scopes, true) || in_array($scope, $scopes, true)) {
                return;
            }
            Response::denied("Token missing scope: {$scope}");
        }

        // User actors are checked by role.
        if (self::rolesIntersect($actor['roles'] ?? [], config('auth.admin_roles', []))) {
            return;
        }
        Response::denied('This action requires an administrative role.');
    }

    // -----------------------------------------------------------------
    // Local token resolution
    // -----------------------------------------------------------------
    private static function resolveLocalToken(string $rawKey): ?array
    {
        // Local tokens use a recognizable prefix to avoid a network round-trip.
        if (!str_starts_with($rawKey, 'smgr_')) {
            return null;
        }
        $hash = hash('sha256', $rawKey);
        $row = Database::instance()->one(
            'SELECT * FROM api_tokens WHERE token_hash = ? AND revoked = 0 LIMIT 1',
            [$hash]
        );
        if (!$row) {
            return null;
        }
        if (!empty($row['expires_at']) && strtotime($row['expires_at']) < time()) {
            return null;
        }
        Database::instance()->exec(
            'UPDATE api_tokens SET last_used_at = NOW() WHERE id = ?',
            [$row['id']]
        );
        return [
            'name'   => 'token:' . $row['name'],
            'type'   => 'token',
            'roles'  => [],
            'scopes' => json_decode((string) ($row['scopes'] ?? '[]'), true) ?: [],
        ];
    }

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------
    public static function currentActor(): array
    {
        return self::$current ?? [
            'name'  => 'system',
            'type'  => 'system',
            'roles' => [],
        ];
    }

    public static function setSystemActor(string $name = 'system'): void
    {
        self::$current = ['name' => $name, 'type' => 'system', 'roles' => [], 'scopes' => ['*']];
    }

    private static function rolesIntersect(array $have, array $need): bool
    {
        if (empty($need)) {
            return true;
        }
        return count(array_intersect($have, $need)) > 0;
    }

    private static function devActor(): array
    {
        return ['name' => 'dev@local', 'type' => 'user', 'roles' => ['admin'], 'scopes' => ['*']];
    }
}

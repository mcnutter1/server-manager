<?php
/**
 * McNutt Cloud Auth — PHP client helper.
 *
 * Self-contained implementation of the integration surface documented at
 * https://login.mcnutt.cloud/docs/. Drop this folder into a downstream app,
 * copy config.sample.php -> config.php, then use the functions below.
 *
 * Public surface:
 *   handle_sso_callback()           Process payload/sig redirect from login.
 *   ensure_authenticated()          Require a session; returns identity payload.
 *   ensure_role($required, $mode)   Require one/all roles.
 *   validate_api_key_c($key)        Server-side personal API key check.
 *   extract_api_key_c()             Read raw API key from headers/query.
 *   handle_logout_request()         Convenience logout entry point.
 *   client_ip_c()                   Best client IP for logging.
 *
 * Signature helpers: b64url_encode_c, hmac_sign_c, verify_hmac_c.
 */

declare(strict_types=1);

$__mc_config_file = __DIR__ . '/config.php';
if (!is_file($__mc_config_file)) {
    $__mc_config_file = __DIR__ . '/config.sample.php';
}
/** @var array $config */
$config = require $__mc_config_file;

// ---------------------------------------------------------------------
// Signature utilities
// ---------------------------------------------------------------------
function b64url_encode_c(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function hmac_sign_c(string $payloadJson, string $secret): string
{
    return b64url_encode_c(hash_hmac('sha256', $payloadJson, $secret, true));
}

function verify_hmac_c(string $payloadJson, string $secret, string $sig): bool
{
    $expected = hmac_sign_c($payloadJson, $secret);
    return hash_equals($expected, $sig);
}

// ---------------------------------------------------------------------
// IP + cookie helpers
// ---------------------------------------------------------------------
function client_ip_c(): string
{
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']));
        foreach ($parts as $p) {
            if (filter_var($p, FILTER_VALIDATE_IP)) {
                return $p;
            }
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function set_cookie_c(string $value, int $ttl): void
{
    global $config;
    setcookie($config['cookie_name'], $value, [
        'expires'  => time() + $ttl,
        'path'     => '/',
        'domain'   => $config['cookie_domain'] ?? '',
        'secure'   => true,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

function clear_cookie_c(): void
{
    global $config;
    setcookie($config['cookie_name'], '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'domain'   => $config['cookie_domain'] ?? '',
        'secure'   => true,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

// ---------------------------------------------------------------------
// Low-level HTTP to the login service
// ---------------------------------------------------------------------
function mc_http_get_c(string $url, array $headers = []): array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 8,
        CURLOPT_HTTPHEADER     => $headers,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    $body = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    $json = is_string($body) ? json_decode($body, true) : null;
    return ['code' => $code, 'json' => is_array($json) ? $json : null, 'raw' => $body];
}

/**
 * Read the encoded identity cookie into an array (unverified structure).
 */
function read_identity_cookie_c(): ?array
{
    global $config;
    $raw = $_COOKIE[$config['cookie_name']] ?? '';
    if ($raw === '') {
        return null;
    }
    $decoded = base64_decode(strtr($raw, '-_', '+/'), true);
    if ($decoded === false) {
        return null;
    }
    $data = json_decode($decoded, true);
    return is_array($data) ? $data : null;
}

function store_identity_cookie_c(array $identity): void
{
    global $config;
    $json = json_encode($identity, JSON_UNESCAPED_SLASHES);
    set_cookie_c(b64url_encode_c($json), (int) ($config['ttl_sec'] ?? 7200));
}

// ---------------------------------------------------------------------
// SSO callback
// ---------------------------------------------------------------------
function handle_sso_callback(): void
{
    global $config;
    $payloadRaw = $_GET['payload'] ?? '';
    $sig        = $_GET['sig'] ?? '';
    $appId      = $_GET['app_id'] ?? '';

    if ($payloadRaw === '' || $sig === '') {
        return; // not a callback request
    }

    if ($appId !== '' && $appId !== $config['app_id']) {
        header('Location: ' . $config['access_denied_url']);
        exit;
    }

    if (!verify_hmac_c($payloadRaw, $config['app_secret'], $sig)) {
        header('Location: ' . $config['access_denied_url']);
        exit;
    }

    $payload = json_decode($payloadRaw, true);
    if (!is_array($payload)) {
        header('Location: ' . $config['access_denied_url']);
        exit;
    }

    store_identity_cookie_c($payload);

    // Strip query params for a clean URL.
    $clean = strtok($_SERVER['REQUEST_URI'] ?? '/', '?');
    header('Location: ' . ($clean ?: '/'));
    exit;
}

// ---------------------------------------------------------------------
// Session validation
// ---------------------------------------------------------------------
function revalidate(string $sessionToken): array|false
{
    global $config;
    $url = $config['validate_endpoint']
        . '?token=' . urlencode($sessionToken)
        . '&app_id=' . urlencode($config['app_id']);
    $res = mc_http_get_c($url);
    if ($res['code'] !== 200 || !$res['json']) {
        return false;
    }
    $json = $res['json'];
    // Verify signature over the payload.
    if (isset($json['payload'], $json['sig'])) {
        $payloadJson = json_encode($json['payload'], JSON_UNESCAPED_SLASHES);
        if (!verify_hmac_c($payloadJson, $config['app_secret'], $json['sig'])) {
            return false;
        }
        return $json['payload'];
    }
    return $json['valid'] ?? false ? $json : false;
}

/**
 * Require an authenticated browser session. On failure, redirects to the
 * central login UI. Returns identity array with keys:
 *   identity, roles, session_token, exp
 */
function ensure_authenticated(): array
{
    global $config;
    $identity = read_identity_cookie_c();

    if ($identity && !empty($identity['session_token'])) {
        $needsRefresh = !isset($identity['_checked'])
            || (time() - (int) $identity['_checked']) > (int) ($config['refresh_sec'] ?? 1200);

        if ($needsRefresh) {
            $fresh = revalidate($identity['session_token']);
            if ($fresh === false) {
                clear_cookie_c();
                mc_redirect_to_login_c();
            }
            $identity = array_merge($identity, $fresh, ['_checked' => time()]);
            store_identity_cookie_c($identity);
        }
        return $identity;
    }

    mc_redirect_to_login_c();
}

function mc_redirect_to_login_c(): never
{
    global $config;
    $return = (isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://'
        . ($_SERVER['HTTP_HOST'] ?? 'localhost')
        . ($_SERVER['REQUEST_URI'] ?? '/');
    $url = rtrim($config['login_base'], '/') . '/login'
        . '?app_id=' . urlencode($config['app_id'])
        . '&return_url=' . urlencode($return);
    header('Location: ' . $url);
    exit;
}

/**
 * Require one or more roles. $mode = 'any' | 'all'.
 */
function ensure_role(array|string $required, string $mode = 'any'): array
{
    global $config;
    $auth = ensure_authenticated();
    $roles = $auth['roles'] ?? [];
    $required = (array) $required;

    $has = array_intersect($required, $roles);
    $ok = $mode === 'all'
        ? count($has) === count($required)
        : count($has) > 0;

    if (!$ok) {
        header('Location: ' . $config['access_denied_url']);
        exit;
    }
    return $auth;
}

// ---------------------------------------------------------------------
// API key auth (machine-to-machine, no browser)
// ---------------------------------------------------------------------
function extract_api_key_c(): ?string
{
    $headers = function_exists('getallheaders') ? getallheaders() : [];
    $auth = $headers['Authorization'] ?? $headers['authorization']
        ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (stripos($auth, 'Bearer ') === 0) {
        return trim(substr($auth, 7));
    }
    $xkey = $headers['X-Api-Key'] ?? $_SERVER['HTTP_X_API_KEY'] ?? '';
    if ($xkey !== '') {
        return trim($xkey);
    }
    if (!empty($_GET['api_key'])) {
        return trim((string) $_GET['api_key']);
    }
    return null;
}

/**
 * Validate a personal / system API key against the login service.
 * Returns payload array (identity, roles, session_token) or null.
 */
function validate_api_key_c(string $apiKey): ?array
{
    global $config;
    $res = mc_http_get_c(
        rtrim($config['login_base'], '/') . '/api/whoami',
        ['Authorization: Bearer ' . $apiKey]
    );
    if ($res['code'] !== 200 || !$res['json']) {
        return null;
    }
    $json = $res['json'];
    if (isset($json['payload'], $json['sig'])) {
        $payloadJson = json_encode($json['payload'], JSON_UNESCAPED_SLASHES);
        if (!verify_hmac_c($payloadJson, $config['app_secret'], $json['sig'])) {
            return null;
        }
        return $json['payload'];
    }
    // Fallback: some deployments return identity directly.
    if (!empty($json['identity'])) {
        return $json;
    }
    return null;
}

// ---------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------
function logout_everywhere(): void
{
    global $config;
    $identity = read_identity_cookie_c();
    if ($identity && !empty($identity['session_token'])) {
        mc_http_get_c(
            $config['logout_endpoint'] . '?token=' . urlencode($identity['session_token'])
        );
    }
    clear_cookie_c();
}

function initiate_logout(?string $returnUrl = null): never
{
    global $config;
    logout_everywhere();
    $return = $returnUrl ?: (
        (isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://'
        . ($_SERVER['HTTP_HOST'] ?? 'localhost') . '/'
    );
    $url = rtrim($config['login_base'], '/') . '/logout?return_url=' . urlencode($return);
    header('Location: ' . $url);
    exit;
}

function handle_logout_request(): never
{
    $return = $_GET['return_url'] ?? null;
    initiate_logout($return);
}

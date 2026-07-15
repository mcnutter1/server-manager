<?php
/**
 * Serves the drop-in app helper (helper.sample.php.txt) pre-filled with THIS
 * manager's public base URL, so an operator who downloads it gets a working
 * pairing gate with zero configuration — no env var to set. The env var
 * SRVMGR_MANAGER_URL still overrides the baked-in default at runtime.
 *
 * The only value injected is the manager's own (public) base URL, so this
 * endpoint is safe to serve without authentication, exactly like the raw
 * helper.sample.php.txt template it is based on.
 */
declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/app/bootstrap.php';

$template = __DIR__ . '/helper.sample.php.txt';
$src = @file_get_contents($template);
if ($src === false) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "helper template unavailable\n";
    exit;
}

$base = rtrim((string) config('app.base_url', ''), '/');
if ($base !== '' && filter_var($base, FILTER_VALIDATE_URL)) {
    // Bake the manager URL into the gate default so the helper can verify
    // one-time unlock codes out of the box.
    $src = preg_replace(
        "/const SRVMGR_MANAGER_URL_DEFAULT = '';/",
        "const SRVMGR_MANAGER_URL_DEFAULT = '" . addslashes($base) . "';",
        $src,
        1
    );
}

header('Content-Type: text/plain; charset=utf-8');
header('Content-Disposition: attachment; filename="helper.php"');
echo $src;

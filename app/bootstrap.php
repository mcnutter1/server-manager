<?php
/**
 * Bootstrap — shared initialisation for every entry point.
 * Loads config, sets up autoloading, timezone, error handling and DB.
 */

declare(strict_types=1);

define('SM_ROOT', dirname(__DIR__));

// ---------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------
$configFile = SM_ROOT . '/config/config.php';
if (!is_file($configFile)) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode([
        'ok'    => false,
        'error' => 'Missing config/config.php. Copy config/config.sample.php and edit it.',
    ]);
    exit;
}

/** @var array $CONFIG */
$CONFIG = require $configFile;

date_default_timezone_set($CONFIG['app']['timezone'] ?? 'UTC');

if (!empty($CONFIG['app']['debug'])) {
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
} else {
    error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE);
    ini_set('display_errors', '0');
}

// ---------------------------------------------------------------------
// Tiny PSR-4-ish autoloader for the App namespace.
// ---------------------------------------------------------------------
spl_autoload_register(static function (string $class): void {
    $prefix = 'App\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $file = SM_ROOT . '/app/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($file)) {
        require $file;
    }
});

require_once SM_ROOT . '/app/helpers.php';

// Make config globally reachable through a container-lite accessor.
App\Config::init($CONFIG);

// Overlay operator-editable settings stored in the database on top of the
// file config, so UI-driven changes take effect app-wide. Best-effort:
// never fatal if the database is unreachable during early boot.
try {
    App\Settings::applyOverrides();
} catch (\Throwable $e) {
    error_log('[bootstrap] settings overlay skipped: ' . $e->getMessage());
}

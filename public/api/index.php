<?php
/**
 * Server Manager — REST API front controller.
 *
 * All API traffic enters here. Routing is expressed as METHOD + path pattern.
 * Every route authenticates; mutating routes additionally require a privileged
 * role/scope via Auth::requirePrivileged().
 *
 * Path is taken from ?r= (set by .htaccess rewrite) or PATH_INFO.
 */

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/app/bootstrap.php';

use App\Auth;
use App\Response;
use App\SystemMonitor;
use App\ServiceManager;
use App\FirewallManager;
use App\NidsManager;
use App\AppManager;
use App\LogAnalyzer;
use App\TrafficAnalyzer;
use App\Notifier;
use App\Runner;
use App\Database;

// ---------------------------------------------------------------------
// CORS / preflight (same-origin SPA + token clients).
// ---------------------------------------------------------------------
header('Vary: Origin');
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Authorization, Content-Type, X-Api-Key');
    http_response_code(204);
    exit;
}

// ---------------------------------------------------------------------
// Resolve method + path + JSON body.
// ---------------------------------------------------------------------
$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
$path = $_GET['r'] ?? ($_SERVER['PATH_INFO'] ?? '');
$path = '/' . trim((string) $path, '/');

$body = [];
$rawBody = file_get_contents('php://input') ?: '';
if ($rawBody !== '') {
    $decoded = json_decode($rawBody, true);
    if (is_array($decoded)) {
        $body = $decoded;
    }
}
$input = array_merge($_GET, $body);

// ---------------------------------------------------------------------
// Authenticate (all API routes require it, except the public health ping).
// ---------------------------------------------------------------------
if ($path !== '/ping') {
    Auth::authenticateApi();
}

// Simple router: [method, regex, handler]. First match wins.
$routes = [];
$get  = static function (string $p, callable $h) use (&$routes) { $routes[] = ['GET', $p, $h]; };
$post = static function (string $p, callable $h) use (&$routes) { $routes[] = ['POST', $p, $h]; };
$del  = static function (string $p, callable $h) use (&$routes) { $routes[] = ['DELETE', $p, $h]; };

// =====================================================================
// Meta
// =====================================================================
$get('/ping', static fn () => Response::ok(['pong' => true, 'time' => date('c')]));

$get('/me', static function () {
    Response::ok(Auth::currentActor());
});

// =====================================================================
// System / health
// =====================================================================
$get('/system/overview', static function () {
    Response::ok([
        'system'   => SystemMonitor::snapshot(),
        'services' => ServiceManager::criticalHealth(),
        'nids'     => NidsManager::stats(),
        'firewall' => FirewallManager::summary(),
    ]);
});

$get('/system/metrics', static function () {
    Response::ok(SystemMonitor::snapshot());
});

$get('/system/processes', static function () {
    Response::ok(SystemMonitor::topProcesses((int) ($_GET['limit'] ?? 10)));
});

$get('/system/mounts', static function () {
    Response::ok(SystemMonitor::mounts());
});

$get('/system/metrics/history', static function () {
    $hours = max(1, min((int) ($_GET['hours'] ?? 6), 168));
    $rows = Database::instance()->all(
        'SELECT cpu_pct, mem_pct, disk_pct, load1, created_at
         FROM metrics WHERE created_at >= (NOW() - INTERVAL ? HOUR) ORDER BY created_at ASC',
        [$hours]
    );
    Response::ok($rows);
});

// =====================================================================
// Services
// =====================================================================
$get('/services', static fn () => Response::ok(ServiceManager::list()));

$get('/services/(?<name>[A-Za-z0-9._@-]+)', static function ($p) {
    Response::ok(ServiceManager::status($p['name']));
});

$post('/services/(?<name>[A-Za-z0-9._@-]+)/(?<verb>start|stop|restart|reload)', static function ($p) {
    Auth::requirePrivileged('services');
    $result = ServiceManager::action($p['name'], $p['verb']);
    Response::json(['ok' => $result['ok'], 'data' => $result], $result['ok'] ? 200 : 500);
});

// =====================================================================
// Firewall
// =====================================================================
$get('/firewall/rules', static function () {
    Response::ok(FirewallManager::rules($_GET['table'] ?? 'filter'));
});

$get('/firewall/summary', static fn () => Response::ok(FirewallManager::summary()));

$get('/firewall/ports', static fn () => Response::ok(FirewallManager::listeningPorts()));

$post('/firewall/snapshot', static function () {
    Auth::requirePrivileged('firewall');
    Response::ok(['snapshot_id' => FirewallManager::snapshot()]);
});

// =====================================================================
// NIDS + blocking
// =====================================================================
$get('/nids/stats', static fn () => Response::ok(NidsManager::stats()));

$get('/nids/events', static function () {
    Response::ok(NidsManager::recentEvents((int) ($_GET['limit'] ?? 100)));
});

$get('/nids/offenders', static function () {
    Response::ok(NidsManager::topOffenders((int) ($_GET['limit'] ?? 10)));
});

$get('/nids/blocks', static fn () => Response::ok(NidsManager::activeBlocks()));

$post('/nids/block', static function () use ($input) {
    Auth::requirePrivileged('nids');
    $ip = trim((string) ($input['ip'] ?? ''));
    $result = NidsManager::block(
        $ip,
        $input['reason'] ?? null,
        isset($input['minutes']) ? (int) $input['minutes'] : null,
        $input['source'] ?? 'api',
        !empty($input['permanent'])
    );
    Response::json(['ok' => $result['ok'], 'data' => $result], $result['ok'] ? 200 : 400);
});

$post('/nids/unblock', static function () use ($input) {
    Auth::requirePrivileged('nids');
    $result = NidsManager::unblock(trim((string) ($input['ip'] ?? '')));
    Response::json(['ok' => $result['ok'], 'data' => $result], $result['ok'] ? 200 : 400);
});

$post('/nids/events', static function () use ($input) {
    Auth::requirePrivileged('nids');
    $id = NidsManager::recordEvent(
        $input['source'] ?? 'api',
        $input['category'] ?? 'manual',
        trim((string) ($input['src_ip'] ?? '')),
        $input['severity'] ?? 'low',
        isset($input['dst_port']) ? (int) $input['dst_port'] : null,
        $input['signature'] ?? null,
        $input['raw'] ?? null
    );
    Response::ok(['event_id' => $id]);
});

// =====================================================================
// Applications
// =====================================================================
$get('/apps', static function () {
    Response::ok(AppManager::all());
});

$get('/apps/discover', static function () {
    Auth::requirePrivileged('apps');
    Response::ok(AppManager::discover());
});

$get('/apps/(?<id>\d+)', static function ($p) {
    $app = AppManager::find((int) $p['id']);
    $app ? Response::ok($app) : Response::notFound('app not found');
});

$post('/apps', static function () use ($input) {
    Auth::requirePrivileged('apps');
    $result = AppManager::register($input);
    Response::json(['ok' => $result['ok'], 'data' => $result], $result['ok'] ? 200 : 400);
});

$post('/apps/(?<id>\d+)/status', static function ($p) use ($input) {
    Auth::requirePrivileged('apps');
    Response::ok(AppManager::setStatus((int) $p['id'], $input['status'] ?? ''));
});

$post('/apps/(?<id>\d+)/health', static function ($p) {
    Response::ok(AppManager::checkHealth((int) $p['id']));
});

$post('/apps/(?<id>\d+)/helper', static function ($p) use ($input) {
    Auth::requirePrivileged('apps');
    $app = AppManager::find((int) $p['id']);
    if (!$app) {
        Response::notFound('app not found');
    }
    Response::ok(AppManager::callHelper($app, $input['action'] ?? 'health', $input['params'] ?? []));
});

$del('/apps/(?<id>\d+)', static function ($p) {
    Auth::requirePrivileged('apps');
    Response::ok(AppManager::remove((int) $p['id']));
});

$get('/apps/(?<id>\d+)/logs', static function ($p) {
    Auth::requirePrivileged('apps');
    Response::ok(TrafficAnalyzer::appLogs((int) $p['id'], (int) ($_GET['lines'] ?? 100)));
});

// =====================================================================
// Traffic map (geo + flows, stitched from apache + firewall + app logs)
// =====================================================================
$get('/traffic/map', static function () {
    Response::ok(TrafficAnalyzer::mapData((int) ($_GET['hours'] ?? 24)));
});

$get('/traffic/summary', static function () {
    Response::ok(TrafficAnalyzer::summary((int) ($_GET['hours'] ?? 24)));
});

$get('/traffic/sources', static function () {
    Response::ok(TrafficAnalyzer::topSources((int) ($_GET['hours'] ?? 24), (int) ($_GET['limit'] ?? 25)));
});

$get('/traffic/countries', static function () {
    Response::ok(TrafficAnalyzer::byCountry((int) ($_GET['hours'] ?? 24), (int) ($_GET['limit'] ?? 25)));
});

$get('/traffic/isps', static function () {
    Response::ok(TrafficAnalyzer::byIsp((int) ($_GET['hours'] ?? 24), (int) ($_GET['limit'] ?? 25)));
});

$get('/traffic/apps', static function () {
    Response::ok(TrafficAnalyzer::byApp((int) ($_GET['hours'] ?? 24)));
});

$post('/traffic/ingest', static function () {
    Auth::requirePrivileged('nids');
    Response::ok(TrafficAnalyzer::ingest());
});

// =====================================================================
// Logs
// =====================================================================
$get('/logs/sources', static fn () => Response::ok(LogAnalyzer::sources()));

$get('/logs/tail', static function () {
    Response::ok(LogAnalyzer::tail($_GET['source'] ?? 'syslog', (int) ($_GET['lines'] ?? 200)));
});

$get('/logs/access-summary', static function () {
    Response::ok(LogAnalyzer::accessSummary((int) ($_GET['lines'] ?? 5000)));
});

$post('/logs/scan', static function () {
    Auth::requirePrivileged('nids');
    Response::ok(LogAnalyzer::scanForThreats((int) ($_POST['lines'] ?? 1000)));
});

// =====================================================================
// CLI runner (emulate whitelisted CLI commands through the API)
// =====================================================================
$get('/runner/actions', static fn () => Response::ok(Runner::actions()));

$post('/runner/exec', static function () use ($input) {
    Auth::requirePrivileged('runner');
    $action = (string) ($input['action'] ?? '');
    if (!in_array($action, Runner::actions(), true)) {
        Response::error('unknown or forbidden action', 400);
    }
    $result = Runner::run($action, (array) ($input['args'] ?? []));
    Response::ok($result);
});

$get('/runner/history', static function () {
    $rows = Database::instance()->all(
        'SELECT id, actor, command_key, exit_code, duration_ms, ip_address, created_at
         FROM command_log ORDER BY created_at DESC LIMIT 100'
    );
    Response::ok($rows);
});

// =====================================================================
// Alerts + audit
// =====================================================================
$get('/alerts', static function () {
    $rows = Database::instance()->all(
        'SELECT * FROM alerts ORDER BY created_at DESC LIMIT 100'
    );
    Response::ok($rows);
});

$post('/alerts/(?<id>\d+)/ack', static function ($p) {
    Auth::requirePrivileged('admin');
    Database::instance()->exec(
        'UPDATE alerts SET acknowledged = 1, ack_by = ? WHERE id = ?',
        [Auth::currentActor()['name'], (int) $p['id']]
    );
    Response::ok(['acknowledged' => true]);
});

$post('/notify/test', static function () use ($input) {
    Auth::requirePrivileged('admin');
    Response::ok(Notifier::alert('info', 'test', 'Test alert from Server Manager', $input['message'] ?? 'It works.'));
});

$get('/audit', static function () {
    $rows = Database::instance()->all(
        'SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200'
    );
    Response::ok($rows);
});

// ---------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------
foreach ($routes as [$routeMethod, $pattern, $handler]) {
    if ($routeMethod !== $method) {
        continue;
    }
    $regex = '#^' . $pattern . '$#';
    if (preg_match($regex, $path, $matches)) {
        $params = array_filter($matches, 'is_string', ARRAY_FILTER_USE_KEY);
        try {
            $handler($params);
        } catch (\Throwable $e) {
            error_log('[api] ' . $e->getMessage());
            Response::error(
                \App\config('app.debug') ? $e->getMessage() : 'Internal server error',
                500
            );
        }
        exit;
    }
}

Response::notFound("No route for {$method} {$path}");

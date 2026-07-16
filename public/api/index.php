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
use App\ThreatIntel;
use App\Settings;
use App\AppManager;
use App\PairManager;
use App\LogAnalyzer;
use App\TrafficAnalyzer;
use App\Notifier;
use App\Runner;
use App\Diagnostics;
use App\AuditLogger;
use App\Database;
use function App\is_valid_ip;

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
// Authenticate. All API routes require it, except the public health ping and
// the pairing-code verification endpoint (called server-to-server by a
// downstream app's helper, which has no manager credentials yet).
// ---------------------------------------------------------------------
$publicPaths = ['/ping', '/pair/verify', '/pair/pubkey'];
if (!in_array($path, $publicPaths, true)) {
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
$get('/nids/stats', static fn () => Response::ok(
    NidsManager::stats() + ['threat_intel' => ThreatIntel::stats()]
));

$get('/nids/events', static function () {
    Response::ok(NidsManager::recentEvents((int) ($_GET['limit'] ?? 100)));
});

$get('/nids/offenders', static function () {
    Response::ok(NidsManager::topOffenders((int) ($_GET['limit'] ?? 10)));
});

$get('/nids/blocks', static fn () => Response::ok(NidsManager::activeBlocks()));

// Full drill-down dossier for a single IP (behaviour, block history, NIDS
// timeline, services/apps touched, and malicious-IP threat intelligence).
$get('/nids/ip', static function () {
    $ip = trim((string) ($_GET['ip'] ?? ''));
    if (!is_valid_ip($ip)) {
        Response::error('Invalid or missing IP address.', 400);
        return;
    }
    $hours = (int) ($_GET['hours'] ?? 24);
    Response::ok(NidsManager::ipDossier($ip, $hours));
});

// Force a fresh threat-intel lookup for an IP (privileged; hits upstream feeds).
$post('/nids/ip/recheck', static function () use ($input) {
    Auth::requirePrivileged('nids');
    $ip = trim((string) ($input['ip'] ?? ''));
    if (!is_valid_ip($ip)) {
        Response::error('Invalid or missing IP address.', 400);
        return;
    }
    Response::ok(ThreatIntel::check($ip));
});

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

// Never-block allowlist (editable; IPv4 / IPv6 / CIDR).
$get('/nids/never-block', static fn () => Response::ok([
    'entries' => NidsManager::neverBlockList(),
    'config'  => NidsManager::configWhitelist(),
]));

$post('/nids/never-block', static function () use ($input) {
    Auth::requirePrivileged('nids');
    $result = NidsManager::addNeverBlock(
        trim((string) ($input['ip'] ?? '')),
        isset($input['note']) ? trim((string) $input['note']) : null
    );
    Response::json(['ok' => $result['ok'], 'data' => $result], $result['ok'] ? 200 : 400);
});

$post('/nids/never-block/remove', static function () use ($input) {
    Auth::requirePrivileged('nids');
    $result = NidsManager::removeNeverBlock(trim((string) ($input['ip'] ?? '')));
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

$post('/apps/(?<id>\d+)', static function ($p) use ($input) {
    Auth::requirePrivileged('apps');
    $result = AppManager::update((int) $p['id'], $input);
    Response::json(['ok' => $result['ok'], 'data' => $result], $result['ok'] ? 200 : 400);
});

$post('/apps/enroll', static function () use ($input) {
    Auth::requirePrivileged('apps');
    $result = AppManager::enroll($input);
    Response::json(['ok' => $result['ok'], 'data' => $result], $result['ok'] ? 200 : 400);
});

// Issue a short-lived, signed unlock token to present to a downstream app's
// helper page. The helper verifies the manager signature offline.
$post('/apps/pair/code', static function () use ($input) {
    Auth::requirePrivileged('apps');
    Response::ok(PairManager::issueToken($input['label'] ?? null, (int) ($input['ttl'] ?? 900)));
});

// PUBLIC: the manager's Ed25519 public signing key, so a helper can verify
// unlock/claim tokens offline. Public keys are safe to expose.
$get('/pair/pubkey', static function () {
    Response::ok(['pubkey' => PairManager::pubKeyB64(), 'alg' => 'ed25519']);
});

// PUBLIC: a downstream helper verifies the operator-presented unlock token.
// Returns only valid/invalid; tokens are Ed25519-signed + short-lived.
$post('/pair/verify', static function () use ($input) {
    usleep(150000); // uniform small delay to blunt brute force
    $ok = PairManager::verifyCode((string) ($input['code'] ?? $input['token'] ?? ''));
    Response::json(['ok' => $ok, 'data' => ['valid' => $ok]], $ok ? 200 : 403);
});

$post('/apps/(?<id>\d+)/status', static function ($p) use ($input) {
    Auth::requirePrivileged('apps');
    Response::ok(AppManager::setStatus((int) $p['id'], $input['status'] ?? ''));
});

$post('/apps/(?<id>\d+)/health', static function ($p) {
    AppManager::checkHealth((int) $p['id'], 'manual');
    Response::ok(AppManager::healthReport((int) $p['id']));
});

$get('/apps/(?<id>\d+)/health', static function ($p) {
    Response::ok(AppManager::healthReport((int) $p['id']));
});

// App-declared components (extensible common-information-model health surface).
$get('/apps/(?<id>\d+)/components', static function ($p) {
    Auth::requirePrivileged('apps');
    Response::ok(AppManager::components((int) $p['id']));
});

// App-declared CLI commands + invocation.
$get('/apps/(?<id>\d+)/commands', static function ($p) {
    Auth::requirePrivileged('apps');
    Response::ok(AppManager::commands((int) $p['id']));
});

$post('/apps/(?<id>\d+)/command', static function ($p) use ($input) {
    Auth::requirePrivileged('runner');
    $res = AppManager::runCommand(
        (int) $p['id'],
        (string) ($input['command'] ?? ''),
        is_array($input['args'] ?? null) ? $input['args'] : []
    );
    Response::json(['ok' => (bool) ($res['ok'] ?? false), 'data' => $res], ($res['ok'] ?? false) ? 200 : 400);
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
// Parse the UI filter-bar tags (`tags` = JSON array of {t,v}) and boolean
// `logic` (and|or) into the shape TrafficAnalyzer expects.
$trafficFilter = static function (): array {
    $tags = [];
    $raw  = $_GET['tags'] ?? '';
    if (is_string($raw) && $raw !== '') {
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) {
            $tags = $decoded;
        }
    }
    $logic = strtolower((string) ($_GET['logic'] ?? 'and')) === 'or' ? 'or' : 'and';
    return ['tags' => $tags, 'logic' => $logic];
};

$get('/traffic/map', static function () use ($trafficFilter) {
    Response::ok(TrafficAnalyzer::mapData((int) ($_GET['hours'] ?? 24), $trafficFilter()));
});

$get('/traffic/summary', static function () use ($trafficFilter) {
    Response::ok(TrafficAnalyzer::summary((int) ($_GET['hours'] ?? 24), $trafficFilter()));
});

$get('/traffic/sources', static function () use ($trafficFilter) {
    Response::ok(TrafficAnalyzer::topSources((int) ($_GET['hours'] ?? 24), (int) ($_GET['limit'] ?? 25), $trafficFilter()));
});

$get('/traffic/countries', static function () use ($trafficFilter) {
    Response::ok(TrafficAnalyzer::byCountry((int) ($_GET['hours'] ?? 24), (int) ($_GET['limit'] ?? 25), $trafficFilter()));
});

$get('/traffic/isps', static function () use ($trafficFilter) {
    Response::ok(TrafficAnalyzer::byIsp((int) ($_GET['hours'] ?? 24), (int) ($_GET['limit'] ?? 25), $trafficFilter()));
});

$get('/traffic/apps', static function () use ($trafficFilter) {
    Response::ok(TrafficAnalyzer::byApp((int) ($_GET['hours'] ?? 24), $trafficFilter()));
});

// Entity drill-downs: IP -> services/ports/apps, ISP -> IPs, country -> ISPs.
$get('/traffic/ip', static function () {
    $ip = trim((string) ($_GET['ip'] ?? ''));
    if (!is_valid_ip($ip)) {
        Response::error('a valid ip parameter is required', 400);
    }
    Response::ok(TrafficAnalyzer::ipDetail($ip, (int) ($_GET['hours'] ?? 24)));
});

$get('/traffic/app', static function () {
    $app = trim((string) ($_GET['app'] ?? ''));
    if ($app === '') {
        Response::error('an app parameter is required', 400);
    }
    Response::ok(TrafficAnalyzer::appDetail($app, (int) ($_GET['hours'] ?? 24)));
});


$get('/traffic/isp', static function () {
    $isp = trim((string) ($_GET['isp'] ?? ''));
    if ($isp === '') {
        Response::error('an isp parameter is required', 400);
    }
    Response::ok(TrafficAnalyzer::ispSources($isp, (int) ($_GET['hours'] ?? 24), (int) ($_GET['limit'] ?? 250)));
});

$get('/traffic/country', static function () {
    $code = trim((string) ($_GET['code'] ?? ''));
    Response::ok(TrafficAnalyzer::countryIsps($code, (int) ($_GET['hours'] ?? 24), (int) ($_GET['limit'] ?? 200)));
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

$get('/logs/app-usage', static function () {
    Response::ok(LogAnalyzer::appUsageSummary((int) ($_GET['hours'] ?? 24)));
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

// =====================================================================
// Settings (admin only) — grouped registry + statistics
// =====================================================================
$get('/settings', static function () {
    Auth::requirePrivileged('admin');
    Response::ok([
        'groups' => Settings::groups(),
    ]);
});

$get('/settings/stats', static function () {
    Auth::requirePrivileged('admin');
    Response::ok(Settings::stats());
});

$post('/settings', static function () use ($input) {
    Auth::requirePrivileged('admin');
    $values = $input['values'] ?? null;
    if (!is_array($values)) {
        Response::error('Expected a "values" object of key => value pairs.', 400);
        return;
    }
    $result = Settings::saveMany($values, Auth::currentActor()['name']);
    // Always 200: the JSON body's "ok" flag carries success/failure so the SPA
    // can surface per-field validation messages instead of a generic error.
    Response::json(['ok' => $result['ok'], 'data' => $result], 200);
});

$post('/settings/reset', static function () use ($input) {
    Auth::requirePrivileged('admin');
    $key = trim((string) ($input['key'] ?? ''));
    if ($key === '') {
        Response::error('Missing setting key.', 400);
        return;
    }
    $result = Settings::reset($key, Auth::currentActor()['name']);
    Response::json(['ok' => $result['ok'], 'data' => $result], $result['ok'] ? 200 : 400);
});

// =====================================================================
// AI / LLM diagnostics interface (read-only, "diag" scope).
//
// A key-protected, READ-ONLY window into logs, the database, the audit trail
// and live app/API interactions so an operator (or an AI agent handed a
// `diag`-scoped token) can work out why a downstream app is misbehaving.
// Create the key with:  php bin/token.php create ai-diag diag
// See docs/DIAGNOSTICS.md.
// =====================================================================
$get('/diag', static function () {
    Auth::requirePrivileged('diag');
    Response::ok(Diagnostics::catalog());
});

$get('/diag/overview', static function () {
    Auth::requirePrivileged('diag');
    Response::ok(Diagnostics::overview());
});

$get('/diag/apps', static function () {
    Auth::requirePrivileged('diag');
    Response::ok(Diagnostics::apps());
});

$get('/diag/apps/(?<id>\d+)/probe', static function ($p) use ($input) {
    Auth::requirePrivileged('diag');
    $actions = null;
    if (!empty($input['actions'])) {
        $actions = array_filter(array_map('trim', explode(',', (string) $input['actions'])));
    }
    $res = Diagnostics::probeApp((int) $p['id'], $actions);
    Response::json(['ok' => $res['ok'], 'data' => $res], $res['ok'] ? 200 : 404);
});

$get('/diag/apps/(?<id>\d+)/health-checks', static function ($p) use ($input) {
    Auth::requirePrivileged('diag');
    Response::ok(Diagnostics::healthChecks((int) $p['id'], (int) ($input['limit'] ?? 20)));
});

$get('/diag/logs', static function () use ($input) {
    Auth::requirePrivileged('diag');
    Response::ok(Diagnostics::logs($input));
});

$get('/diag/audit', static function () use ($input) {
    Auth::requirePrivileged('diag');
    Response::ok(Diagnostics::audit($input));
});

$get('/diag/schema', static function () use ($input) {
    Auth::requirePrivileged('diag');
    Response::ok(Diagnostics::schema(isset($input['table']) ? (string) $input['table'] : null));
});

$post('/diag/query', static function () use ($input) {
    Auth::requirePrivileged('diag');
    $sql = (string) ($input['sql'] ?? '');
    if (trim($sql) === '') {
        Response::error('Missing "sql".', 400);
        return;
    }
    $res = Diagnostics::query($sql, (int) ($input['limit'] ?? 200));
    Response::json(['ok' => $res['ok'], 'data' => $res], $res['ok'] ? 200 : 400);
});

// The human/AI-readable skill page. Served publicly at /integrate/diagnostics.txt
// too; this in-band copy lets a token holder fetch it without a second host.
$get('/diag/guide', static function () {
    Auth::requirePrivileged('diag');
    $file = SM_ROOT . '/public/integrate/diagnostics.txt';
    $text = is_readable($file) ? (string) file_get_contents($file) : 'Guide unavailable.';
    header('Content-Type: text/plain; charset=utf-8');
    echo $text;
    exit;
});

// -- Diagnostics key management (admin only) --------------------------
// Minting/revoking diag tokens is a privileged write, so it requires the
// 'admin' role — a diag token itself must NOT be able to create more tokens.
$get('/diag/keys', static function () {
    Auth::requirePrivileged('admin');
    $rows = Database::instance()->all(
        "SELECT id, name, created_by, last_used_at, expires_at, revoked, created_at
         FROM api_tokens
         WHERE JSON_CONTAINS(scopes, '\"diag\"') OR JSON_CONTAINS(scopes, '\"*\"')
         ORDER BY id DESC"
    );
    $now = time();
    $keys = array_map(static function ($r) use ($now) {
        $expired = !empty($r['expires_at']) && strtotime((string) $r['expires_at']) < $now;
        return [
            'id'           => (int) $r['id'],
            'name'         => $r['name'],
            'created_by'   => $r['created_by'],
            'last_used_at' => $r['last_used_at'],
            'expires_at'   => $r['expires_at'],
            'revoked'      => (bool) $r['revoked'],
            'expired'      => $expired,
            'active'       => !$r['revoked'] && !$expired,
            'created_at'   => $r['created_at'],
        ];
    }, $rows);
    Response::ok(['keys' => $keys]);
});

$post('/diag/keys', static function () use ($input) {
    Auth::requirePrivileged('admin');
    $name = trim((string) ($input['name'] ?? 'ai-diag'));
    if ($name === '') {
        $name = 'ai-diag';
    }
    if (!preg_match('/^[\w .\-]{1,120}$/', $name)) {
        Response::error('Invalid name (letters, numbers, space, dot, dash only).', 400);
        return;
    }
    $days = (int) ($input['expires_days'] ?? 7);
    $days = max(0, min($days, 365));

    $raw = 'smgr_' . bin2hex(random_bytes(24));
    $id  = Database::instance()->insert('api_tokens', [
        'name'       => $name,
        'token_hash' => hash('sha256', $raw),
        'scopes'     => json_encode(['diag']),
        'created_by' => Auth::currentActor()['name'],
        'expires_at' => $days > 0 ? date('Y-m-d H:i:s', time() + $days * 86400) : null,
    ]);
    AuditLogger::log('diag.key.create', $name, ['id' => $id, 'expires_days' => $days]);

    Response::ok(
        [
            'id'           => $id,
            'name'         => $name,
            'token'        => $raw,           // shown once
            'scope'        => 'diag',
            'expires_days' => $days ?: null,
        ],
        ['message' => 'Copy this token now — it is shown only once.']
    );
});

$post('/diag/keys/(?<id>\d+)/revoke', static function ($p) {
    Auth::requirePrivileged('admin');
    Database::instance()->exec('UPDATE api_tokens SET revoked = 1 WHERE id = ?', [(int) $p['id']]);
    AuditLogger::log('diag.key.revoke', (string) $p['id']);
    Response::ok(['revoked' => true]);
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

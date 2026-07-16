<?php
/**
 * Server Manager — managed app helper (drop-in reference).
 *
 * Copy this file into your application at: srvmgr/helper.php
 * Then set $HELPER_TOKEN (or load it from your app config) and fill in the
 * health/stats/version bodies with your app's real internals.
 *
 * Server Manager calls this endpoint to interface with your app in a common
 * way. See docs/APP_HELPER.md for the contract.
 */

declare(strict_types=1);

header('Content-Type: application/json');

// ---------------------------------------------------------------------
// 1) Shared secret — MUST match managed_apps.helper_token in Server Manager.
//    Prefer loading from your app's config rather than hard-coding.
// ---------------------------------------------------------------------
$HELPER_TOKEN = getenv('SRVMGR_HELPER_TOKEN') ?: 'replace_with_shared_secret';

$provided = $_SERVER['HTTP_X_SRVMGR_TOKEN'] ?? '';
if (!$provided || !hash_equals($HELPER_TOKEN, $provided)) {
    http_response_code(401);
    echo json_encode(['ok' => false, 'error' => 'unauthorized']);
    exit;
}

$req = json_decode(file_get_contents('php://input') ?: '[]', true) ?: [];
$action = $req['action'] ?? '';

/**
 * Example: reuse your app's PDO. Replace with your own bootstrap.
 * $pdo = require __DIR__ . '/../config/pdo.php';
 */
function app_db(): ?PDO
{
    // TODO: return your application's PDO connection.
    return null;
}

function reply(array $data, bool $ok = true, int $code = 200): void
{
    http_response_code($code);
    echo json_encode(['ok' => $ok, 'data' => $data], JSON_UNESCAPED_SLASHES);
    exit;
}

switch ($action) {
    case 'health':
        $dbOk = false;
        try {
            $pdo = app_db();
            $dbOk = $pdo ? (bool) $pdo->query('SELECT 1')->fetchColumn() : true;
        } catch (Throwable $e) {
            $dbOk = false;
        }
        reply([
            'status' => $dbOk ? 'ok' : 'degraded',
            'db'     => $dbOk,
            'time'   => date('c'),
        ]);

    case 'version':
        $sha = @trim((string) @shell_exec('git -C ' . escapeshellarg(dirname(__DIR__)) . ' rev-parse --short HEAD 2>/dev/null'));
        reply(['version' => $sha ?: 'unknown']);

    case 'stats':
        // TODO: return real counters from your app.
        reply(['users' => 0, 'sessions' => 0]);

    case 'components':
        // Declare YOUR app's sub-processes / components. Each follows the
        // common information model; only id/name/status are required. Server
        // Manager renders whatever you return and lets any degraded/down
        // component pull the app's overall health down.
        reply([
            'components' => [
                [
                    'id'       => 'queue-worker',
                    'name'     => 'Queue worker',
                    'kind'     => 'process',            // process|service|worker|queue|datastore|integration|job|custom
                    'status'   => 'ok',                 // ok|healthy|degraded|down|unknown
                    'summary'  => '3 running · 12 jobs/min',
                    'metrics'  => ['workers' => 3, 'queue_depth' => 12],
                    'commands' => ['worker.restart', 'worker.stats'],
                ],
            ],
        ]);

    case 'commands':
        // Declare the commands Server Manager may invoke. The app owns this
        // allow-list — only keys returned here can be run via `command`.
        reply([
            'commands' => [
                [
                    'key'         => 'worker.restart',
                    'name'        => 'Restart worker',
                    'description' => 'Gracefully restart the queue worker',
                    'component'   => 'queue-worker',
                    'dangerous'   => false,
                    'params'      => [
                        ['name' => 'graceful', 'type' => 'bool', 'label' => 'Graceful', 'default' => true],
                    ],
                ],
                [
                    'key'         => 'worker.stats',
                    'name'        => 'Worker stats',
                    'description' => 'Dump current worker statistics',
                ],
            ],
        ]);

    case 'command':
        // Execute one declared command. ALWAYS re-check the command name here;
        // never run anything you did not advertise in `commands`.
        $command = (string) ($req['command'] ?? '');
        $args    = is_array($req['args'] ?? null) ? $req['args'] : [];
        switch ($command) {
            case 'worker.restart':
                $graceful = !empty($args['graceful']);
                // TODO: restart your worker.
                reply(['output' => 'worker restart requested (graceful=' . ($graceful ? 'yes' : 'no') . ')']);
            case 'worker.stats':
                // TODO: return real worker stats.
                reply(['output' => "workers: 3\nqueue_depth: 12"]);
            default:
                reply(['error' => 'command not declared'], false, 400);
        }
        // no break — every case above exits via reply()

    case 'clear_cache':
        // TODO: flush your app cache.
        reply(['cleared' => true]);

    case 'maintenance':
        $on = !empty($req['on']);
        // TODO: toggle a maintenance flag your app checks.
        reply(['maintenance' => $on]);

    default:
        reply(['error' => 'unknown action'], false, 400);
}

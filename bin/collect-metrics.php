<?php
/**
 * Metrics + service monitor — run from cron every minute.
 *   * snapshot system metrics into the metrics table
 *   * check critical services; alert + record transitions on failure
 *   * raise resource alerts when thresholds are crossed
 *
 * Usage:  php bin/collect-metrics.php
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/app/bootstrap.php';

use App\Auth;
use App\Database;
use App\SystemMonitor;
use App\ServiceManager;
use App\Notifier;

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

Auth::setSystemActor('metrics-worker');
$db = Database::instance();

// --- Metrics snapshot -------------------------------------------------
$s = SystemMonitor::snapshot();
$db->insert('metrics', [
    'cpu_pct'      => $s['cpu']['usage_pct'],
    'mem_pct'      => $s['memory']['used_pct'],
    'swap_pct'     => $s['memory']['swap_pct'],
    'disk_pct'     => $s['disk']['used_pct'],
    'load1'        => $s['load']['1'],
    'load5'        => $s['load']['5'],
    'load15'       => $s['load']['15'],
    'net_rx_bytes' => $s['network']['rx_bytes'],
    'net_tx_bytes' => $s['network']['tx_bytes'],
    'procs'        => $s['processes'],
]);

// --- Resource alerts --------------------------------------------------
if ($s['health']['status'] === 'critical') {
    Notifier::alert('critical', 'resource', 'System health critical on ' . $s['hostname'],
        implode("\n", $s['health']['reasons']));
} elseif ($s['health']['status'] === 'warning') {
    Notifier::alert('warning', 'resource', 'System health degraded on ' . $s['hostname'],
        implode("\n", $s['health']['reasons']));
}

// --- Critical service monitoring -------------------------------------
foreach (ServiceManager::criticalHealth() as $svc) {
    if (!$svc['healthy']) {
        Notifier::alert('critical', 'service', "Service down: {$svc['name']}",
            "Critical service {$svc['name']} is {$svc['state']} on {$s['hostname']}.");
        $db->insert('service_events', [
            'service'   => $svc['name'],
            'state'     => $svc['state'],
            'sub_state' => '',
            'detail'    => 'detected down by monitor',
        ]);
    }
}

// --- Retention: keep metrics for 30 days ------------------------------
$db->exec('DELETE FROM metrics WHERE created_at < (NOW() - INTERVAL 30 DAY)');

fwrite(STDOUT, sprintf("[%s] metrics stored; health=%s\n", date('c'), $s['health']['status']));

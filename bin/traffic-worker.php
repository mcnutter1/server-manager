<?php
/**
 * Traffic worker — run from cron/systemd on a short interval (e.g. every 2 min).
 *
 * Stitches together the traffic picture and geolocates new source IPs:
 *   * parse new apache access-log lines           (accepted inbound traffic)
 *   * read firewall drop counters via the runner  (blocked traffic)
 *   * pull per-app logs from each app's helper     (per-app attribution)
 *   * resolve any new IP to country / city / ISP / lat-lng (cached)
 *
 * Usage:  php bin/traffic-worker.php
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/app/bootstrap.php';

use App\Auth;
use App\TrafficAnalyzer;

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

Auth::setSystemActor('traffic-worker');

$r = TrafficAnalyzer::ingest();

fwrite(STDOUT, sprintf(
    "[%s] window=%s allow=%d block=%d app=%d ips_geo=%d\n",
    date('c'),
    $r['window'] ?? '-',
    $r['allow'] ?? 0,
    $r['block'] ?? 0,
    $r['app'] ?? 0,
    $r['ips'] ?? 0
));

foreach (($r['warnings'] ?? []) as $w) {
    fwrite(STDERR, "[warn] {$w}\n");
}

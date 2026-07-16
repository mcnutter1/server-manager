<?php
/**
 * Threat-intelligence worker — run from cron (e.g. every 15 minutes).
 *
 *   * Score the most active NIDS offenders and recently blocked/active hosts
 *     against known malicious-IP databases (DNSBLs, AbuseIPDB, ...).
 *   * Cache each verdict in ip_reputation so the UI can show it instantly.
 *   * Optionally auto-block anything confirmed malicious
 *     (config('threat_intel.auto_block')).
 *
 * Usage:  php bin/threat-intel.php [limit]
 *
 * Suggested crontab entry (every 15 minutes):
 *   [slash]15 * * * * www-data /usr/bin/php /path/to/bin/threat-intel.php >> /var/log/srvmgr-threatintel.log 2>&1
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/app/bootstrap.php';

use App\Auth;
use App\ThreatIntel;

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

Auth::setSystemActor('threat-intel-worker');

$limit = isset($argv[1]) ? max(1, (int) $argv[1]) : 200;
$result = ThreatIntel::refreshActive($limit);

fwrite(STDOUT, sprintf(
    "[%s] checked=%d malicious=%d auto_blocked=%s\n",
    date('c'),
    $result['checked'],
    $result['malicious'],
    implode(',', $result['blocked']) ?: '-'
));

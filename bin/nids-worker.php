<?php
/**
 * NIDS worker — run from cron every minute.
 *   * expire timed blocks whose timer elapsed
 *   * scan logs for threats + auto-block
 *
 * Usage:  php bin/nids-worker.php
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/app/bootstrap.php';

use App\Auth;
use App\NidsManager;
use App\LogAnalyzer;

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

Auth::setSystemActor('nids-worker');

$expired = NidsManager::expireDue();
$scan    = LogAnalyzer::scanForThreats(1000);

fwrite(STDOUT, sprintf(
    "[%s] expired=%d scanned_events=%d suspects=%d auto_blocked=%s\n",
    date('c'),
    $expired['expired'],
    $scan['events'],
    $scan['suspects'],
    implode(',', $scan['auto_blocked']) ?: '-'
));

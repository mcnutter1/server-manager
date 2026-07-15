<?php

declare(strict_types=1);

namespace App;

/**
 * NIDS + host blocking with timers.
 *
 * Responsibilities:
 *   * Record suspicious events (nids_events) from log analysis or the API.
 *   * Block / unblock IPs at the firewall via the runner, with optional TTLs.
 *   * Expire timed blocks (called by bin/nids-worker.php).
 *   * Auto-block hosts that cross a threshold within a window.
 */
final class NidsManager
{
    // -----------------------------------------------------------------
    // Blocking
    // -----------------------------------------------------------------
    /**
     * Block a host at the firewall.
     *
     * @param int|null $minutes  TTL in minutes; null/0 with $permanent=false
     *                           uses the configured default; $permanent=true
     *                           blocks until manually removed.
     */
    public static function block(
        string $ip,
        ?string $reason = null,
        ?int $minutes = null,
        string $source = 'manual',
        bool $permanent = false
    ): array {
        if (!is_valid_ip($ip)) {
            return ['ok' => false, 'error' => 'Invalid IP address.'];
        }
        if (self::isWhitelisted($ip)) {
            return ['ok' => false, 'error' => "Refusing to block whitelisted host {$ip}."];
        }

        $default = (int) config('nids.default_block_minutes', 60);
        if (!$permanent) {
            $minutes = $minutes ?? $default;
            $expiresAt = ($minutes > 0)
                ? date('Y-m-d H:i:s', time() + $minutes * 60)
                : null; // 0 => indefinite but not marked permanent
        } else {
            $minutes = 0;
            $expiresAt = null;
        }

        $res = Runner::run('nids.block', ['ip' => $ip]);

        $db = Database::instance();
        // Deactivate any prior active record for this IP, then insert fresh.
        $db->exec(
            'UPDATE blocked_hosts SET active = 0, unblocked_at = NOW() WHERE ip_address = ? AND active = 1',
            [$ip]
        );
        $id = $db->insert('blocked_hosts', [
            'ip_address' => $ip,
            'reason'     => $reason,
            'source'     => $source,
            'created_by' => Auth::currentActor()['name'],
            'active'     => 1,
            'permanent'  => $permanent ? 1 : 0,
            'blocked_at' => date('Y-m-d H:i:s'),
            'expires_at' => $expiresAt,
        ]);

        AuditLogger::log(
            'nids.block',
            $ip,
            ['reason' => $reason, 'minutes' => $minutes, 'permanent' => $permanent, 'source' => $source],
            $res['ok'] ? 'success' : 'failure',
            $res['ok'] ? null : $res['stderr']
        );

        // Fire an alert for high-signal blocks.
        if ($res['ok']) {
            Notifier::alert(
                'warning',
                'nids',
                "Host blocked: {$ip}",
                sprintf("%s\nExpires: %s\nSource: %s", $reason ?: 'no reason given', $expiresAt ?: 'permanent', $source)
            );
        }

        return [
            'ok'         => $res['ok'],
            'id'         => $id,
            'ip'         => $ip,
            'expires_at' => $expiresAt,
            'permanent'  => $permanent,
            'error'      => $res['ok'] ? null : ($res['stderr'] ?: 'block failed'),
        ];
    }

    public static function unblock(string $ip, string $reason = 'manual unblock'): array
    {
        if (!is_valid_ip($ip)) {
            return ['ok' => false, 'error' => 'Invalid IP address.'];
        }
        $res = Runner::run('nids.unblock', ['ip' => $ip]);
        Database::instance()->exec(
            'UPDATE blocked_hosts SET active = 0, unblocked_at = NOW() WHERE ip_address = ? AND active = 1',
            [$ip]
        );
        AuditLogger::log('nids.unblock', $ip, ['reason' => $reason], $res['ok'] ? 'success' : 'failure');
        return ['ok' => $res['ok'], 'ip' => $ip, 'error' => $res['ok'] ? null : $res['stderr']];
    }

    /** Called by the worker to remove blocks whose timer has elapsed. */
    public static function expireDue(): array
    {
        $db = Database::instance();
        $due = $db->all(
            'SELECT * FROM blocked_hosts
             WHERE active = 1 AND permanent = 0 AND expires_at IS NOT NULL AND expires_at <= NOW()'
        );
        $removed = [];
        foreach ($due as $row) {
            $res = Runner::run('nids.unblock', ['ip' => $row['ip_address']]);
            $db->exec(
                'UPDATE blocked_hosts SET active = 0, unblocked_at = NOW() WHERE id = ?',
                [$row['id']]
            );
            AuditLogger::log('nids.expire', $row['ip_address'], ['block_id' => $row['id']], $res['ok'] ? 'success' : 'failure');
            $removed[] = $row['ip_address'];
        }
        return ['expired' => count($removed), 'ips' => $removed];
    }

    // -----------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------
    public static function recordEvent(
        string $source,
        string $category,
        string $srcIp,
        string $severity = 'low',
        ?int $dstPort = null,
        ?string $signature = null,
        ?string $raw = null
    ): int {
        return Database::instance()->insert('nids_events', [
            'source'    => $source,
            'category'  => $category,
            'severity'  => $severity,
            'src_ip'    => $srcIp,
            'dst_port'  => $dstPort,
            'signature' => $signature,
            'raw'       => $raw ? mb_substr($raw, 0, 2000) : null,
        ]);
    }

    /**
     * Evaluate recent events for a host and auto-block if it crosses the
     * configured threshold within the window. Returns true if blocked.
     */
    public static function evaluateAutoBlock(string $srcIp): bool
    {
        if (self::isWhitelisted($srcIp)) {
            return false;
        }
        $threshold = (int) config('nids.auto_block_threshold', 8);
        $windowMin = (int) config('nids.auto_block_window_min', 10);

        $count = (int) Database::instance()->scalar(
            'SELECT COALESCE(SUM(count),0) FROM nids_events
             WHERE src_ip = ? AND created_at >= (NOW() - INTERVAL ? MINUTE)',
            [$srcIp, $windowMin]
        );

        if ($count < $threshold) {
            return false;
        }
        // Already actively blocked?
        if (self::isBlocked($srcIp)) {
            return false;
        }

        Auth::setSystemActor('nids-auto');
        $res = self::block(
            $srcIp,
            "Auto-blocked: {$count} events in {$windowMin}m",
            (int) config('nids.default_block_minutes', 60),
            'nids'
        );
        return (bool) ($res['ok'] ?? false);
    }

    // -----------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------
    public static function activeBlocks(): array
    {
        $rows = Database::instance()->all(
            'SELECT * FROM blocked_hosts WHERE active = 1 ORDER BY blocked_at DESC'
        );
        // Attach live hit counters from iptables.
        $stats = Runner::run('nids.stats', [], false)['data']['stats'] ?? [];
        foreach ($rows as &$row) {
            $s = $stats[$row['ip_address']] ?? null;
            $row['hits']  = $s['packets'] ?? 0;
            $row['bytes'] = $s['bytes'] ?? 0;
            $row['remaining_seconds'] = $row['expires_at']
                ? max(0, strtotime($row['expires_at']) - time())
                : null;
        }
        return $rows;
    }

    public static function recentEvents(int $limit = 100): array
    {
        $limit = max(1, min($limit, 1000));
        return Database::instance()->all(
            "SELECT * FROM nids_events ORDER BY created_at DESC LIMIT {$limit}"
        );
    }

    public static function topOffenders(int $limit = 10): array
    {
        $limit = max(1, min($limit, 100));
        return Database::instance()->all(
            "SELECT src_ip, COUNT(*) AS events, MAX(severity) AS worst, MAX(created_at) AS last_seen
             FROM nids_events
             WHERE created_at >= (NOW() - INTERVAL 24 HOUR)
             GROUP BY src_ip ORDER BY events DESC LIMIT {$limit}"
        );
    }

    public static function isBlocked(string $ip): bool
    {
        return (bool) Database::instance()->scalar(
            'SELECT 1 FROM blocked_hosts WHERE ip_address = ? AND active = 1 LIMIT 1',
            [$ip]
        );
    }

    public static function isWhitelisted(string $ip): bool
    {
        return in_array($ip, config('nids.whitelist', []), true);
    }

    public static function stats(): array
    {
        $db = Database::instance();
        return [
            'active_blocks'  => (int) $db->scalar('SELECT COUNT(*) FROM blocked_hosts WHERE active = 1'),
            'events_24h'     => (int) $db->scalar('SELECT COUNT(*) FROM nids_events WHERE created_at >= (NOW() - INTERVAL 24 HOUR)'),
            'critical_24h'   => (int) $db->scalar("SELECT COUNT(*) FROM nids_events WHERE severity IN ('high','critical') AND created_at >= (NOW() - INTERVAL 24 HOUR)"),
            'permanent'      => (int) $db->scalar('SELECT COUNT(*) FROM blocked_hosts WHERE active = 1 AND permanent = 1'),
        ];
    }
}

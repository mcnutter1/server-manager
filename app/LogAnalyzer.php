<?php

declare(strict_types=1);

namespace App;

/**
 * Log analysis + performance insight.
 *
 * Tails standard log files (read-only), extracts security signals into the
 * NIDS pipeline, and produces usage/performance summaries for the dashboard.
 */
final class LogAnalyzer
{
    /** Tail the last N lines of a known log source safely. */
    public static function tail(string $sourceKey, int $lines = 200): array
    {
        // Application log streams reported by a managed app's health helper
        // are stored in the DB (app_log_events), not on disk.
        if (str_starts_with($sourceKey, 'app:')) {
            return self::tailAppLog((int) substr($sourceKey, 4), $lines);
        }
        $path = self::resolveSource($sourceKey);
        if ($path === null) {
            return ['ok' => false, 'error' => 'unknown log source'];
        }
        if (!is_readable($path)) {
            return ['ok' => false, 'error' => "cannot read {$path}"];
        }
        $lines = max(1, min($lines, 5000));
        return ['ok' => true, 'path' => $path, 'lines' => self::readLastLines($path, $lines)];
    }

    /**
     * Tail the most recent log entries an application reported through its
     * health helper (ingested into app_log_events by the traffic worker),
     * formatted into human-readable log lines.
     */
    private static function tailAppLog(int $appId, int $lines): array
    {
        $lines = max(1, min($lines, 5000));
        try {
            $rows = Database::instance()->all(
                "SELECT logged_at, created_at, level, src_ip, method, path, status_code, bytes, message
                 FROM app_log_events WHERE app_id = ? ORDER BY id DESC LIMIT {$lines}",
                [$appId]
            );
        } catch (\Throwable $e) {
            return ['ok' => false, 'error' => 'application logs unavailable'];
        }
        $rows = array_reverse($rows); // oldest → newest, like a real tail
        $out = [];
        foreach ($rows as $r) {
            $ts     = (string) ($r['logged_at'] ?: $r['created_at'] ?: '');
            $level  = strtoupper((string) ($r['level'] ?: 'info'));
            $req    = trim((string) ($r['method'] ?? '') . ' ' . (string) ($r['path'] ?? ''));
            $status = $r['status_code'] !== null && $r['status_code'] !== '' ? (string) $r['status_code'] : '';
            $parts  = array_filter(
                [$ts, '[' . $level . ']', (string) ($r['src_ip'] ?? ''), $req, $status, (string) ($r['message'] ?? '')],
                static fn ($v) => $v !== '' && $v !== null
            );
            $out[] = implode(' ', $parts);
        }
        if ($out === []) {
            return ['ok' => true, 'source' => 'app', 'lines' => ['(no application log entries reported yet)']];
        }
        return ['ok' => true, 'source' => 'app', 'lines' => $out];
    }

    /** Map a friendly key to a whitelisted path (prevents traversal). */
    private static function resolveSource(string $key): ?string
    {
        $map = [
            'auth'          => config('nids.auth_log', '/var/log/auth.log'),
            'apache_access' => config('nids.apache_access', '/var/log/apache2/access.log'),
            'apache_error'  => config('nids.apache_error', '/var/log/apache2/error.log'),
            'syslog'        => '/var/log/syslog',
        ];
        return $map[$key] ?? null;
    }

    /**
     * Log sources for the viewer dropdown: the standard system logs plus one
     * stream per managed application that has reported logs through its health
     * helper. Each entry is {key, label, kind}.
     */
    public static function sources(): array
    {
        $sources = [
            ['key' => 'auth',          'label' => 'Auth log',      'kind' => 'system'],
            ['key' => 'apache_access', 'label' => 'Apache access', 'kind' => 'system'],
            ['key' => 'apache_error',  'label' => 'Apache error',  'kind' => 'system'],
            ['key' => 'syslog',        'label' => 'Syslog',        'kind' => 'system'],
        ];

        try {
            $apps = Database::instance()->all(
                "SELECT a.id, a.name, COUNT(e.id) AS n
                 FROM managed_apps a
                 JOIN app_log_events e ON e.app_id = a.id
                 GROUP BY a.id, a.name
                 HAVING n > 0
                 ORDER BY a.name"
            );
            foreach ($apps as $a) {
                $sources[] = [
                    'key'   => 'app:' . (int) $a['id'],
                    'label' => (string) $a['name'],
                    'kind'  => 'app',
                ];
            }
        } catch (\Throwable $e) {
            // app_log_events / managed_apps may not exist yet — system logs only.
        }

        return $sources;
    }


    /** Efficient tail without loading the whole file. */
    private static function readLastLines(string $path, int $lines): array
    {
        $f = fopen($path, 'r');
        if (!$f) {
            return [];
        }
        $buffer = '';
        $chunk = 4096;
        $pos = -1;
        $lineCount = 0;
        fseek($f, 0, SEEK_END);
        $fileSize = ftell($f);
        $read = 0;

        while ($lineCount <= $lines && $read < $fileSize) {
            $seek = min($chunk, $fileSize - $read);
            $read += $seek;
            fseek($f, -$read, SEEK_END);
            $data = fread($f, $seek);
            $buffer = $data . $buffer;
            $lineCount = substr_count($buffer, "\n");
        }
        fclose($f);

        $all = explode("\n", rtrim($buffer, "\n"));
        return array_slice($all, -$lines);
    }

    // -----------------------------------------------------------------
    // Security analysis — feed the NIDS pipeline.
    // -----------------------------------------------------------------
    /**
     * Scan recent auth + apache logs for suspicious patterns, record NIDS
     * events, and evaluate auto-blocking. Intended to run from the worker.
     */
    public static function scanForThreats(int $lines = 1000): array
    {
        $events = 0;
        $suspects = [];

        // --- SSH brute force / invalid users ---
        $auth = self::tail('auth', $lines);
        if ($auth['ok']) {
            foreach ($auth['lines'] as $line) {
                $ip = null;
                $category = null;
                $severity = 'low';

                if (preg_match('/Failed password.*from (\d{1,3}(?:\.\d{1,3}){3})/', $line, $m)) {
                    $ip = $m[1];
                    $category = 'ssh_failed_password';
                    $severity = 'medium';
                } elseif (preg_match('/Invalid user \S+ from (\d{1,3}(?:\.\d{1,3}){3})/', $line, $m)) {
                    $ip = $m[1];
                    $category = 'ssh_invalid_user';
                    $severity = 'medium';
                } elseif (preg_match('/(?:POSSIBLE BREAK-IN|Did not receive identification).*from (\d{1,3}(?:\.\d{1,3}){3})/', $line, $m)) {
                    $ip = $m[1];
                    $category = 'ssh_scan';
                    $severity = 'high';
                }

                if ($ip && !NidsManager::isWhitelisted($ip)) {
                    NidsManager::recordEvent('auth', $category, $ip, $severity, 22, $category, $line);
                    $suspects[$ip] = true;
                    $events++;
                }
            }
        }

        // --- Web attacks (SQLi/XSS/traversal/scanners) ---
        $access = self::tail('apache_access', $lines);
        if ($access['ok']) {
            foreach ($access['lines'] as $line) {
                if (!preg_match('/^(\d{1,3}(?:\.\d{1,3}){3})\b/', $line, $ipm)) {
                    continue;
                }
                $ip = $ipm[1];
                if (NidsManager::isWhitelisted($ip)) {
                    continue;
                }
                $category = self::classifyWebLine($line);
                if ($category !== null) {
                    $sev = in_array($category, ['sqli', 'rce', 'traversal'], true) ? 'high' : 'medium';
                    NidsManager::recordEvent('apache', $category, $ip, $sev, 443, $category, $line);
                    $suspects[$ip] = true;
                    $events++;
                }
            }
        }

        // --- Auto-block evaluation ---
        $blocked = [];
        foreach (array_keys($suspects) as $ip) {
            if (NidsManager::evaluateAutoBlock($ip)) {
                $blocked[] = $ip;
            }
        }

        return ['events' => $events, 'suspects' => count($suspects), 'auto_blocked' => $blocked];
    }

    private static function classifyWebLine(string $line): ?string
    {
        $lower = strtolower($line);
        if (preg_match('/(union\s+select|information_schema|\bor\b\s+1=1|sleep\(|benchmark\()/i', $line)) {
            return 'sqli';
        }
        if (preg_match('/(<script|%3cscript|onerror=|javascript:)/i', $line)) {
            return 'xss';
        }
        if (preg_match('/(\.\.\/|\.\.%2f|\/etc\/passwd|\/proc\/self)/i', $line)) {
            return 'traversal';
        }
        if (preg_match('/(\;|\|)\s*(cat|wget|curl|bash|sh)\s/i', $line) || str_contains($lower, 'cmd=')) {
            return 'rce';
        }
        if (preg_match('/(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster)/i', $line)) {
            return 'scanner';
        }
        // Excessive 404s handled elsewhere; flag admin probing.
        if (preg_match('/\/(wp-login|xmlrpc|phpmyadmin|\.env|\.git\/)/i', $line)) {
            return 'recon';
        }
        return null;
    }

    // -----------------------------------------------------------------
    // Usage / performance summaries from the apache access log.
    // -----------------------------------------------------------------
    public static function accessSummary(int $lines = 5000): array
    {
        $access = self::tail('apache_access', $lines);
        if (!$access['ok']) {
            return ['ok' => false, 'error' => $access['error']];
        }

        $statusCounts = [];
        $topPaths = [];
        $topIps = [];
        $bytes = 0;
        $total = 0;

        foreach ($access['lines'] as $line) {
            if ($line === '') {
                continue;
            }
            $total++;
            // Common/combined log format.
            if (preg_match('/^(\S+).*"[A-Z]+\s(\S+).*"\s(\d{3})\s(\d+|-)/', $line, $m)) {
                $ip = $m[1];
                $path = $m[2];
                $status = $m[3];
                $size = $m[4] === '-' ? 0 : (int) $m[4];

                $bytes += $size;
                $statusCounts[$status] = ($statusCounts[$status] ?? 0) + 1;
                $topPaths[$path] = ($topPaths[$path] ?? 0) + 1;
                $topIps[$ip] = ($topIps[$ip] ?? 0) + 1;
            }
        }

        arsort($topPaths);
        arsort($topIps);
        ksort($statusCounts);

        return [
            'ok'            => true,
            'requests'      => $total,
            'bytes'         => $bytes,
            'status_counts' => $statusCounts,
            'error_rate'    => $total > 0
                ? round((($statusCounts['500'] ?? 0) + ($statusCounts['502'] ?? 0) + ($statusCounts['503'] ?? 0)) / $total * 100, 2)
                : 0,
            'top_paths'     => array_slice($topPaths, 0, 15, true),
            'top_ips'       => array_slice($topIps, 0, 15, true),
        ];
    }

    /**
     * Per-application usage, aggregated from the log entries each managed app
     * reported through its health helper (app_log_events). This is the "usage
     * from the application health reporters" that powers the Logs & Usage tab.
     */
    public static function appUsageSummary(int $hours = 24): array
    {
        $hours = max(1, min($hours, 168));
        try {
            $rows = Database::instance()->all(
                "SELECT a.id, a.name, a.slug,
                        COUNT(e.id) AS requests,
                        COALESCE(SUM(e.bytes), 0) AS bytes,
                        SUM(CASE WHEN e.status_code >= 400 THEN 1 ELSE 0 END) AS errors,
                        COUNT(DISTINCT e.src_ip) AS sources,
                        MAX(e.logged_at) AS last_logged
                 FROM managed_apps a
                 JOIN app_log_events e ON e.app_id = a.id
                 WHERE e.created_at >= (NOW() - INTERVAL {$hours} HOUR)
                 GROUP BY a.id, a.name, a.slug
                 ORDER BY requests DESC"
            );
        } catch (\Throwable $e) {
            return ['ok' => false, 'error' => 'application usage unavailable', 'apps' => []];
        }

        $apps = [];
        $totRequests = 0;
        $totErrors = 0;
        $totBytes = 0;
        foreach ($rows as $r) {
            $req = (int) $r['requests'];
            $err = (int) $r['errors'];
            $totRequests += $req;
            $totErrors += $err;
            $totBytes += (int) $r['bytes'];
            $apps[] = [
                'id'          => (int) $r['id'],
                'name'        => (string) $r['name'],
                'slug'        => (string) $r['slug'],
                'requests'    => $req,
                'bytes'       => (int) $r['bytes'],
                'errors'      => $err,
                'sources'     => (int) $r['sources'],
                'error_rate'  => $req > 0 ? round($err / $req * 100, 2) : 0.0,
                'last_logged' => $r['last_logged'],
            ];
        }

        return [
            'ok'            => true,
            'window_hours'  => $hours,
            'total_apps'    => count($apps),
            'total_requests' => $totRequests,
            'total_errors'  => $totErrors,
            'total_bytes'   => $totBytes,
            'apps'          => $apps,
        ];
    }
}

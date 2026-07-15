<?php

declare(strict_types=1);

namespace App;

/**
 * Stitches together every source of traffic knowledge into one model that the
 * traffic map + tables render from:
 *
 *   allow  - accepted inbound requests parsed from the apache access log
 *   block  - traffic dropped by the firewall (iptables byte/packet counters
 *            via the runner's nids.stats action, cross-referenced with
 *            blocked_hosts / nids_events)
 *   app    - per-app request lines pulled from each managed app's health
 *            helper "logs" action (the app publishes its own recent traffic)
 *
 * Distinct source IPs are geolocated (country / city / ISP / lat-lng) so the
 * front-end can draw flow arcs from each origin to this server and break the
 * numbers down by ISP, country, URL and volume.
 */
final class TrafficAnalyzer
{
    /** Combined-log line: IP ... "METHOD path proto" status bytes ... */
    private const ACCESS_RE =
        '/^(\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"([A-Z]+)\s+(\S+)[^"]*"\s+(\d{3})\s+(\d+|-)/';

    // =================================================================
    // Ingest
    // =================================================================

    /**
     * Run a full ingest cycle. Safe to call from a worker/cron on a short
     * interval; it only reads what is new and rolls everything up.
     *
     * @return array summary of what was ingested
     */
    public static function ingest(): array
    {
        $window = date('Y-m-d H:i:s');
        $allow  = self::ingestApache($window);
        $block  = self::ingestBlocked($window);
        $app    = self::ingestAppLogs($window);

        // Geolocate every distinct IP we just recorded.
        $ips = array_values(array_unique(array_merge(
            $allow['ips'], $block['ips'], $app['ips']
        )));
        if ($ips !== []) {
            GeoLocator::locate($ips);
        }

        self::prune();

        return [
            'ok'       => true,
            'window'   => $window,
            'allow'    => $allow['rows'],
            'block'    => $block['rows'],
            'app'      => $app['rows'],
            'ips'      => count($ips),
        ];
    }

    /**
     * Parse new lines from the apache access log and aggregate per source IP.
     *
     * @return array{rows:int,ips:string[]}
     */
    private static function ingestApache(string $window): array
    {
        $path = (string) config('traffic.apache_access', config('nids.apache_access', '/var/log/apache2/access.log'));
        if ($path === '' || !is_readable($path)) {
            return ['rows' => 0, 'ips' => []];
        }

        $maxLines = (int) config('traffic.max_lines_per_run', 20000);
        $lines = self::readNewLines($path, $maxLines);
        if ($lines === []) {
            return ['rows' => 0, 'ips' => []];
        }

        // Aggregate: ip => [requests, bytes, errors, method, path, status]
        $agg = [];
        foreach ($lines as $line) {
            if (!preg_match(self::ACCESS_RE, $line, $m)) {
                continue;
            }
            $ip = $m[1];
            if (!is_valid_ip($ip)) {
                continue;
            }
            $status = (int) $m[4];
            $bytes  = $m[5] === '-' ? 0 : (int) $m[5];

            if (!isset($agg[$ip])) {
                $agg[$ip] = ['requests' => 0, 'bytes' => 0, 'errors' => 0,
                             'method' => $m[2], 'path' => $m[3], 'status' => $status,
                             'paths' => []];
            }
            $agg[$ip]['requests']++;
            $agg[$ip]['bytes'] += $bytes;
            if ($status >= 400) {
                $agg[$ip]['errors']++;
            }
            $p = $m[3];
            $agg[$ip]['paths'][$p] = ($agg[$ip]['paths'][$p] ?? 0) + 1;
        }

        $db = Database::instance();
        $rows = 0;
        foreach ($agg as $ip => $a) {
            arsort($a['paths']);
            $topPath = (string) array_key_first($a['paths']);
            $db->insert('traffic_events', [
                'window_start'  => $window,
                'src_ip'        => $ip,
                'kind'          => 'allow',
                'method'        => $a['method'],
                'top_path'      => mb_substr($topPath, 0, 255),
                'status_sample' => $a['status'],
                'requests'      => $a['requests'],
                'errors'        => $a['errors'],
                'bytes'         => $a['bytes'],
            ]);
            $rows++;
        }

        return ['rows' => $rows, 'ips' => array_keys($agg)];
    }

    /**
     * Record firewall-dropped traffic from the iptables byte counters, tagged
     * with the reason from blocked_hosts / nids_events where we know it.
     *
     * @return array{rows:int,ips:string[]}
     */
    private static function ingestBlocked(string $window): array
    {
        $stats = Runner::run('nids.stats', [], false)['data']['stats'] ?? [];
        if (!is_array($stats) || $stats === []) {
            return ['rows' => 0, 'ips' => []];
        }

        $db = Database::instance();
        $rows = 0;
        $ips = [];
        foreach ($stats as $ip => $s) {
            if (!is_valid_ip((string) $ip)) {
                continue;
            }
            $packets = (int) ($s['packets'] ?? 0);
            $bytes   = (int) ($s['bytes'] ?? 0);
            if ($packets === 0 && $bytes === 0) {
                continue;
            }
            $reason = $db->scalar(
                'SELECT reason FROM blocked_hosts WHERE ip_address = ? ORDER BY blocked_at DESC LIMIT 1',
                [$ip]
            );
            $db->insert('traffic_events', [
                'window_start'  => $window,
                'src_ip'        => $ip,
                'kind'          => 'block',
                'top_path'      => $reason ? mb_substr((string) $reason, 0, 255) : null,
                'requests'      => $packets,
                'bytes'         => $bytes,
            ]);
            $ips[] = (string) $ip;
            $rows++;
        }

        return ['rows' => $rows, 'ips' => $ips];
    }

    /**
     * Pull per-app request lines from each managed app's health helper and fold
     * them into both app_log_events (raw) and traffic_events (aggregated).
     *
     * @return array{rows:int,ips:string[]}
     */
    private static function ingestAppLogs(string $window): array
    {
        if (!(bool) config('traffic.collect_app_logs', true)) {
            return ['rows' => 0, 'ips' => []];
        }

        $apps = Database::instance()->all(
            "SELECT * FROM managed_apps
             WHERE managed = 1 AND status = 'active'
               AND helper_token IS NOT NULL AND helper_token <> ''
               AND (domain IS NOT NULL OR helper_url IS NOT NULL)"
        );

        $db = Database::instance();
        $rows = 0;
        $ips = [];
        $limit = (int) config('traffic.app_log_lines', 200);

        foreach ($apps as $app) {
            $res = AppManager::callHelper($app, 'logs', ['lines' => $limit]);
            if (!($res['ok'] ?? false)) {
                continue;
            }
            $entries = $res['data']['entries'] ?? $res['data']['logs'] ?? [];
            if (!is_array($entries) || $entries === []) {
                continue;
            }

            // Aggregate per source IP for the map, and keep raw lines for drill-down.
            $agg = [];
            foreach ($entries as $e) {
                $line = self::normalizeAppEntry($e);
                $db->insert('app_log_events', [
                    'app_id'      => (int) $app['id'],
                    'app_slug'    => $app['slug'],
                    'level'       => $line['level'],
                    'src_ip'      => $line['ip'],
                    'method'      => $line['method'],
                    'path'        => $line['path'],
                    'status_code' => $line['status'],
                    'bytes'       => $line['bytes'],
                    'message'     => $line['message'],
                    'logged_at'   => $line['time'],
                ]);

                $ip = $line['ip'];
                if ($ip === null || !is_valid_ip($ip)) {
                    continue;
                }
                if (!isset($agg[$ip])) {
                    $agg[$ip] = ['requests' => 0, 'bytes' => 0, 'errors' => 0,
                                 'method' => $line['method'], 'path' => $line['path'],
                                 'status' => $line['status'], 'paths' => []];
                }
                $agg[$ip]['requests']++;
                $agg[$ip]['bytes'] += (int) $line['bytes'];
                if (($line['status'] ?? 0) >= 400) {
                    $agg[$ip]['errors']++;
                }
                if ($line['path']) {
                    $agg[$ip]['paths'][$line['path']] = ($agg[$ip]['paths'][$line['path']] ?? 0) + 1;
                }
            }

            foreach ($agg as $ip => $a) {
                arsort($a['paths']);
                $topPath = $a['paths'] ? (string) array_key_first($a['paths']) : ($a['path'] ?? null);
                $db->insert('traffic_events', [
                    'window_start'  => $window,
                    'src_ip'        => $ip,
                    'app_id'        => (int) $app['id'],
                    'app_slug'      => $app['slug'],
                    'host'          => $app['domain'] ?? null,
                    'kind'          => 'app',
                    'method'        => $a['method'],
                    'top_path'      => $topPath ? mb_substr($topPath, 0, 255) : null,
                    'status_sample' => $a['status'],
                    'requests'      => $a['requests'],
                    'errors'        => $a['errors'],
                    'bytes'         => $a['bytes'],
                ]);
                $rows++;
                $ips[] = (string) $ip;
            }
        }

        return ['rows' => $rows, 'ips' => $ips];
    }

    // =================================================================
    // Queries used by the API / map
    // =================================================================

    /**
     * Full payload for the map: the server location plus one entry per source
     * IP with geo, network and volume, ready to draw arcs from origin->server.
     */
    public static function mapData(int $hours = 24): array
    {
        $rows = self::sourceAggregate($hours);

        $sources = [];
        foreach ($rows as $r) {
            if ($r['lat'] === null || $r['lng'] === null) {
                continue; // can't place it on the map
            }
            $sources[] = [
                'ip'        => $r['src_ip'],
                'lat'       => (float) $r['lat'],
                'lng'       => (float) $r['lng'],
                'country'   => $r['country'],
                'country_code' => $r['country_code'],
                'city'      => $r['city'],
                'isp'       => $r['isp'],
                'requests'  => (int) $r['requests'],
                'bytes'     => (int) $r['bytes'],
                'errors'    => (int) $r['errors'],
                'blocked'   => (int) $r['blocked_bytes'] > 0,
                'blocked_bytes' => (int) $r['blocked_bytes'],
                'apps'      => $r['apps'] ? explode(',', $r['apps']) : [],
            ];
        }

        return [
            'server' => [
                'lat'   => (float) config('geo.server_lat', 39.0438),
                'lng'   => (float) config('geo.server_lng', -77.4874),
                'label' => (string) config('geo.server_label', config('app.name', 'Server')),
            ],
            'sources' => $sources,
            'window_hours' => $hours,
        ];
    }

    /** Top sources by volume with ISP / country / top URL. */
    public static function topSources(int $hours = 24, int $limit = 25): array
    {
        $rows = self::sourceAggregate($hours);
        usort($rows, static fn ($a, $b) => (int) $b['bytes'] <=> (int) $a['bytes']);
        return array_slice($rows, 0, max(1, $limit));
    }

    /** Volume + request totals grouped by country. */
    public static function byCountry(int $hours = 24, int $limit = 25): array
    {
        $hours = self::clampHours($hours);
        $limit = max(1, min($limit, 500));
        return Database::instance()->all(
            "SELECT COALESCE(g.country, 'Unknown') AS country, g.country_code,
                    SUM(t.requests) AS requests, SUM(t.bytes) AS bytes,
                    COUNT(DISTINCT t.src_ip) AS sources
             FROM traffic_events t
             LEFT JOIN geo_cache g ON g.ip_address = t.src_ip
             WHERE t.created_at >= (NOW() - INTERVAL {$hours} HOUR)
             GROUP BY country, g.country_code
             ORDER BY bytes DESC
             LIMIT {$limit}"
        );
    }

    /** Volume grouped by ISP / owning network. */
    public static function byIsp(int $hours = 24, int $limit = 25): array
    {
        $hours = self::clampHours($hours);
        $limit = max(1, min($limit, 500));
        return Database::instance()->all(
            "SELECT COALESCE(g.isp, 'Unknown') AS isp, g.asn,
                    SUM(t.requests) AS requests, SUM(t.bytes) AS bytes,
                    COUNT(DISTINCT t.src_ip) AS sources
             FROM traffic_events t
             LEFT JOIN geo_cache g ON g.ip_address = t.src_ip
             WHERE t.created_at >= (NOW() - INTERVAL {$hours} HOUR)
             GROUP BY isp, g.asn
             ORDER BY bytes DESC
             LIMIT {$limit}"
        );
    }

    /** Volume grouped by managed app (kind = app / host attribution). */
    public static function byApp(int $hours = 24): array
    {
        $hours = self::clampHours($hours);
        return Database::instance()->all(
            "SELECT COALESCE(t.app_slug, t.host, 'server') AS app,
                    t.app_id,
                    SUM(t.requests) AS requests, SUM(t.bytes) AS bytes,
                    SUM(t.errors) AS errors,
                    COUNT(DISTINCT t.src_ip) AS sources
             FROM traffic_events t
             WHERE t.created_at >= (NOW() - INTERVAL {$hours} HOUR)
               AND t.kind IN ('allow','app')
             GROUP BY app, t.app_id
             ORDER BY bytes DESC"
        );
    }

    /** Headline counters for the top of the traffic view. */
    public static function summary(int $hours = 24): array
    {
        $hours = self::clampHours($hours);
        $db = Database::instance();
        $row = $db->one(
            "SELECT
                SUM(CASE WHEN kind IN ('allow','app') THEN requests ELSE 0 END) AS allowed_requests,
                SUM(CASE WHEN kind IN ('allow','app') THEN bytes ELSE 0 END)    AS allowed_bytes,
                SUM(CASE WHEN kind = 'block' THEN requests ELSE 0 END)          AS blocked_packets,
                SUM(CASE WHEN kind = 'block' THEN bytes ELSE 0 END)             AS blocked_bytes,
                SUM(errors) AS errors,
                COUNT(DISTINCT src_ip) AS sources
             FROM traffic_events
             WHERE created_at >= (NOW() - INTERVAL {$hours} HOUR)"
        ) ?? [];

        $countries = (int) $db->scalar(
            "SELECT COUNT(DISTINCT g.country_code)
             FROM traffic_events t JOIN geo_cache g ON g.ip_address = t.src_ip
             WHERE t.created_at >= (NOW() - INTERVAL {$hours} HOUR) AND g.country_code IS NOT NULL"
        );

        return [
            'allowed_requests' => (int) ($row['allowed_requests'] ?? 0),
            'allowed_bytes'    => (int) ($row['allowed_bytes'] ?? 0),
            'blocked_packets'  => (int) ($row['blocked_packets'] ?? 0),
            'blocked_bytes'    => (int) ($row['blocked_bytes'] ?? 0),
            'errors'           => (int) ($row['errors'] ?? 0),
            'sources'          => (int) ($row['sources'] ?? 0),
            'countries'        => $countries,
            'window_hours'     => $hours,
        ];
    }

    /** Recent per-app log lines for a drill-down panel. */
    public static function appLogs(int $appId, int $limit = 100): array
    {
        $limit = max(1, min($limit, 500));
        return Database::instance()->all(
            "SELECT * FROM app_log_events WHERE app_id = ? ORDER BY id DESC LIMIT {$limit}",
            [$appId]
        );
    }

    // =================================================================
    // Internals
    // =================================================================

    /**
     * Per-source rollup joined to geo, including a blocked-bytes column and the
     * list of apps each IP touched. Shared by mapData / topSources.
     */
    private static function sourceAggregate(int $hours): array
    {
        $hours = self::clampHours($hours);
        return Database::instance()->all(
            "SELECT t.src_ip,
                    SUM(t.requests) AS requests,
                    SUM(t.bytes) AS bytes,
                    SUM(t.errors) AS errors,
                    SUM(CASE WHEN t.kind = 'block' THEN t.bytes ELSE 0 END) AS blocked_bytes,
                    GROUP_CONCAT(DISTINCT NULLIF(t.app_slug, '')) AS apps,
                    g.country, g.country_code, g.city, g.isp, g.lat, g.lng
             FROM traffic_events t
             LEFT JOIN geo_cache g ON g.ip_address = t.src_ip
             WHERE t.created_at >= (NOW() - INTERVAL {$hours} HOUR)
             GROUP BY t.src_ip, g.country, g.country_code, g.city, g.isp, g.lat, g.lng
             ORDER BY bytes DESC"
        );
    }

    /** Clamp an hours window to a sane, safe integer for inlining into SQL. */
    private static function clampHours(int $hours): int
    {
        return max(1, min($hours, 24 * 90)); // up to 90 days
    }

    /** Normalize a raw app-helper log entry into our canonical shape. */
    private static function normalizeAppEntry(mixed $e): array
    {
        if (is_string($e)) {
            // Try to parse an apache-combined-style string; else keep as message.
            if (preg_match(self::ACCESS_RE, $e, $m)) {
                return [
                    'ip' => $m[1], 'method' => $m[2], 'path' => $m[3],
                    'status' => (int) $m[4], 'bytes' => $m[5] === '-' ? 0 : (int) $m[5],
                    'level' => null, 'time' => null, 'message' => $e,
                ];
            }
            return ['ip' => null, 'method' => null, 'path' => null, 'status' => null,
                    'bytes' => null, 'level' => null, 'time' => null, 'message' => $e];
        }
        $e = is_array($e) ? $e : [];
        $time = $e['time'] ?? $e['timestamp'] ?? null;
        if (is_int($time)) {
            $time = date('Y-m-d H:i:s', $time);
        } elseif (is_string($time) && $time !== '' && ($ts = strtotime($time)) !== false) {
            $time = date('Y-m-d H:i:s', $ts);
        } else {
            $time = null;
        }
        return [
            'ip'      => isset($e['ip']) ? (string) $e['ip'] : (isset($e['client']) ? (string) $e['client'] : null),
            'method'  => isset($e['method']) ? (string) $e['method'] : null,
            'path'    => isset($e['path']) ? (string) $e['path'] : (isset($e['url']) ? (string) $e['url'] : null),
            'status'  => isset($e['status']) ? (int) $e['status'] : (isset($e['code']) ? (int) $e['code'] : null),
            'bytes'   => isset($e['bytes']) ? (int) $e['bytes'] : (isset($e['size']) ? (int) $e['size'] : null),
            'level'   => isset($e['level']) ? (string) $e['level'] : null,
            'time'    => $time,
            'message' => isset($e['message']) ? (string) $e['message'] : null,
        ];
    }

    // -----------------------------------------------------------------
    // Log offset tracking (only read what is new each run)
    // -----------------------------------------------------------------

    /** @return string[] new lines appended since the last run (rotation aware). */
    private static function readNewLines(string $path, int $maxLines): array
    {
        $size  = (int) @filesize($path);
        $state = self::offset($path);
        $start = $state['offset'];
        $inode = (string) (@fileinode($path) ?: '');

        // Detect truncation / rotation: file shrank or inode changed.
        if ($start > $size || ($state['inode'] !== '' && $state['inode'] !== $inode)) {
            $start = 0;
        }
        if ($start >= $size) {
            self::setOffset($path, $size, $inode);
            return [];
        }

        $fh = @fopen($path, 'rb');
        if ($fh === false) {
            return [];
        }
        fseek($fh, $start);
        $lines = [];
        while (!feof($fh) && count($lines) < $maxLines) {
            $line = fgets($fh);
            if ($line === false) {
                break;
            }
            $line = rtrim($line, "\r\n");
            if ($line !== '') {
                $lines[] = $line;
            }
        }
        $newOffset = ftell($fh) ?: $size;
        fclose($fh);

        self::setOffset($path, (int) $newOffset, $inode);
        return $lines;
    }

    /** @return array{offset:int,inode:string} */
    private static function offset(string $path): array
    {
        $raw = Database::instance()->scalar(
            'SELECT svalue FROM settings WHERE skey = ?',
            ['traffic:offset:' . $path]
        );
        $data = $raw ? json_decode((string) $raw, true) : null;
        return [
            'offset' => (int) ($data['offset'] ?? 0),
            'inode'  => (string) ($data['inode'] ?? ''),
        ];
    }

    private static function setOffset(string $path, int $offset, string $inode): void
    {
        Database::instance()->exec(
            'INSERT INTO settings (skey, svalue) VALUES (?, ?)
             ON DUPLICATE KEY UPDATE svalue = VALUES(svalue), updated_at = NOW()',
            ['traffic:offset:' . $path, json_encode(['offset' => $offset, 'inode' => $inode])]
        );
    }

    /** Drop aggregated rows + raw app logs older than the retention window. */
    private static function prune(): void
    {
        $days = max(1, min((int) config('traffic.retention_days', 30), 3650));
        $db = Database::instance();
        $db->exec("DELETE FROM traffic_events WHERE created_at < (NOW() - INTERVAL {$days} DAY)");
        $db->exec("DELETE FROM app_log_events WHERE created_at < (NOW() - INTERVAL {$days} DAY)");
    }
}

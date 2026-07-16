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
            'warnings' => $allow['warnings'] ?? [],
        ];
    }

    /**
     * Parse new lines from every apache access log and aggregate per source IP.
     *
     * The log location (traffic.apache_access) may be a single path, an array
     * of paths, or a glob (e.g. /var/log/apache2/*access*.log). For a plain
     * file path we also fold in sibling *access*.log files in the same dir, so
     * per-vhost logs (the manager's own site + each app) are all captured even
     * when config still names the stock access.log.
     *
     * @return array{rows:int,ips:string[],warnings:string[]}
     */
    private static function ingestApache(string|array|null $windowArg = null): array
    {
        // Back-compat: the method used to take the window string as its arg.
        $window = is_string($windowArg) ? $windowArg : date('Y-m-d H:i:s');

        $configured = config('traffic.apache_access', config('nids.apache_access', '/var/log/apache2/*access*.log'));
        [$files, $warnings] = self::resolveAccessLogs($configured);
        if ($files === []) {
            return ['rows' => 0, 'ips' => [], 'warnings' => $warnings];
        }

        $maxLines = (int) config('traffic.max_lines_per_run', 20000);

        // Aggregate across all logs: ip => [requests, bytes, errors, method, path, status]
        $agg = [];
        foreach ($files as $path) {
            $remaining = $maxLines - array_sum(array_map(static fn ($a) => $a['requests'], $agg));
            if ($remaining <= 0) {
                break;
            }
            $lines = self::readNewLines($path, $remaining);
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
        }

        if ($agg === []) {
            return ['rows' => 0, 'ips' => [], 'warnings' => $warnings];
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

        return ['rows' => $rows, 'ips' => array_keys($agg), 'warnings' => $warnings];
    }

    /**
     * Resolve the configured access-log location into a list of readable log
     * files, plus a list of human-readable warnings for anything unreadable
     * (the #1 cause of an empty map: the worker user can't read the logs).
     *
     * @return array{0:string[],1:string[]}
     */
    private static function resolveAccessLogs(string|array|null $configured): array
    {
        $patterns = is_array($configured) ? $configured : [(string) $configured];
        $candidates = [];
        foreach ($patterns as $pat) {
            $pat = trim((string) $pat);
            if ($pat === '') {
                continue;
            }
            if (strpbrk($pat, '*?[') !== false) {
                foreach ((glob($pat) ?: []) as $g) {
                    $candidates[$g] = true;
                }
            } else {
                $candidates[$pat] = true;
                // Fold in sibling per-vhost access logs in the same directory.
                foreach ((glob(dirname($pat) . '/*access*.log') ?: []) as $g) {
                    $candidates[$g] = true;
                }
            }
        }

        $files = [];
        $warnings = [];
        foreach (array_keys($candidates) as $path) {
            if (!is_file($path)) {
                continue;
            }
            if (is_readable($path)) {
                $files[] = $path;
            } else {
                $warnings[] = "access log not readable by " . (function_exists('posix_getpwuid')
                    ? (posix_getpwuid(posix_geteuid())['name'] ?? 'worker') : 'worker')
                    . ": {$path} (add the worker user to the 'adm' group)";
            }
        }

        if ($files === [] && $warnings === []) {
            $shown = is_array($configured) ? implode(', ', $configured) : (string) $configured;
            $warnings[] = "no apache access logs matched: {$shown}";
        }

        return [$files, $warnings];
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
    public static function mapData(int $hours = 24, array $filter = []): array
    {
        $rows = self::sourceAggregate($hours, $filter);

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
                'datacenter' => (bool) ($r['is_datacenter'] ?? false),
                'proxy'      => (bool) ($r['is_proxy'] ?? false),
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
    public static function topSources(int $hours = 24, int $limit = 25, array $filter = []): array
    {
        $rows = self::sourceAggregate($hours, $filter);
        usort($rows, static fn ($a, $b) => (int) $b['bytes'] <=> (int) $a['bytes']);
        return array_slice($rows, 0, max(1, $limit));
    }

    /** Volume + request totals grouped by country. */
    public static function byCountry(int $hours = 24, int $limit = 25, array $filter = []): array
    {
        $hours = self::clampHours($hours);
        $limit = max(1, min($limit, 500));
        $f = self::buildFilter($filter);
        return Database::instance()->all(
            "SELECT COALESCE(g.country, 'Unknown') AS country, g.country_code,
                    SUM(t.requests) AS requests, SUM(t.bytes) AS bytes,
                    COUNT(DISTINCT t.src_ip) AS sources
             FROM traffic_events t
             LEFT JOIN geo_cache g ON g.ip_address = t.src_ip
             WHERE t.created_at >= (NOW() - INTERVAL {$hours} HOUR){$f['sql']}
             GROUP BY country, g.country_code
             ORDER BY bytes DESC
             LIMIT {$limit}",
            $f['params']
        );
    }

    /** Volume grouped by ISP / owning network. */
    public static function byIsp(int $hours = 24, int $limit = 25, array $filter = []): array
    {
        $hours = self::clampHours($hours);
        $limit = max(1, min($limit, 500));
        $f = self::buildFilter($filter);
        return Database::instance()->all(
            "SELECT COALESCE(g.isp, 'Unknown') AS isp, g.asn,
                    SUM(t.requests) AS requests, SUM(t.bytes) AS bytes,
                    COUNT(DISTINCT t.src_ip) AS sources
             FROM traffic_events t
             LEFT JOIN geo_cache g ON g.ip_address = t.src_ip
             WHERE t.created_at >= (NOW() - INTERVAL {$hours} HOUR){$f['sql']}
             GROUP BY isp, g.asn
             ORDER BY bytes DESC
             LIMIT {$limit}",
            $f['params']
        );
    }

    /** Volume grouped by managed app (kind = app / host attribution). */
    public static function byApp(int $hours = 24, array $filter = []): array
    {
        $hours = self::clampHours($hours);
        $f = self::buildFilter($filter);
        return Database::instance()->all(
            "SELECT COALESCE(t.app_slug, t.host, 'server') AS app,
                    t.app_id,
                    SUM(t.requests) AS requests, SUM(t.bytes) AS bytes,
                    SUM(t.errors) AS errors,
                    COUNT(DISTINCT t.src_ip) AS sources
             FROM traffic_events t
             LEFT JOIN geo_cache g ON g.ip_address = t.src_ip
             WHERE t.created_at >= (NOW() - INTERVAL {$hours} HOUR)
               AND t.kind IN ('allow','app'){$f['sql']}
             GROUP BY app, t.app_id
             ORDER BY bytes DESC",
            $f['params']
        );
    }

    /** Headline counters for the top of the traffic view. */
    public static function summary(int $hours = 24, array $filter = []): array
    {
        $hours = self::clampHours($hours);
        $f = self::buildFilter($filter);
        $db = Database::instance();
        $row = $db->one(
            "SELECT
                SUM(CASE WHEN t.kind IN ('allow','app') THEN t.requests ELSE 0 END) AS allowed_requests,
                SUM(CASE WHEN t.kind IN ('allow','app') THEN t.bytes ELSE 0 END)    AS allowed_bytes,
                SUM(CASE WHEN t.kind = 'block' THEN t.requests ELSE 0 END)          AS blocked_packets,
                SUM(CASE WHEN t.kind = 'block' THEN t.bytes ELSE 0 END)             AS blocked_bytes,
                SUM(t.errors) AS errors,
                COUNT(DISTINCT t.src_ip) AS sources
             FROM traffic_events t
             LEFT JOIN geo_cache g ON g.ip_address = t.src_ip
             WHERE t.created_at >= (NOW() - INTERVAL {$hours} HOUR){$f['sql']}",
            $f['params']
        ) ?? [];

        $countries = (int) $db->scalar(
            "SELECT COUNT(DISTINCT g.country_code)
             FROM traffic_events t JOIN geo_cache g ON g.ip_address = t.src_ip
             WHERE t.created_at >= (NOW() - INTERVAL {$hours} HOUR) AND g.country_code IS NOT NULL{$f['sql']}",
            $f['params']
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

    /**
     * Full drill-down for a single application (identified by its app-slug,
     * host, or the literal 'server'): managed-app metadata, activity totals,
     * top source IPs (with geo + network flags), country breakdown, top
     * endpoints, and recent request log lines. Powers the app detail panel.
     */
    public static function appDetail(string $appKey, int $hours = 24): array
    {
        $hours = self::clampHours($hours);
        $db    = Database::instance();
        $match = "COALESCE(NULLIF(t.app_slug, ''), NULLIF(t.host, ''), 'server') = ?";

        $meta = $db->one(
            'SELECT id, name, slug, domain, status, last_health, last_checked
             FROM managed_apps WHERE slug = ? LIMIT 1',
            [$appKey]
        );

        $act = $db->one(
            "SELECT
                SUM(CASE WHEN t.kind IN ('allow','app') THEN t.requests ELSE 0 END) AS requests,
                SUM(CASE WHEN t.kind IN ('allow','app') THEN t.bytes ELSE 0 END)    AS bytes,
                SUM(t.errors) AS errors,
                COUNT(DISTINCT t.src_ip) AS sources,
                MIN(t.created_at) AS first_seen, MAX(t.created_at) AS last_seen
             FROM traffic_events t
             WHERE {$match} AND t.created_at >= (NOW() - INTERVAL {$hours} HOUR)",
            [$appKey]
        ) ?? [];

        $sources = $db->all(
            "SELECT t.src_ip,
                    SUM(CASE WHEN t.kind IN ('allow','app') THEN t.requests ELSE 0 END) AS requests,
                    SUM(t.bytes) AS bytes, SUM(t.errors) AS errors,
                    SUM(CASE WHEN t.kind = 'block' THEN t.bytes ELSE 0 END) AS blocked_bytes,
                    g.country, g.country_code, g.city, g.isp, g.org, g.asn,
                    g.hosting, g.proxy, g.mobile,
                    EXISTS(SELECT 1 FROM blocked_hosts b WHERE b.ip_address = t.src_ip) AS ever_blocked
             FROM traffic_events t
             LEFT JOIN geo_cache g ON g.ip_address = t.src_ip
             WHERE {$match} AND t.created_at >= (NOW() - INTERVAL {$hours} HOUR)
             GROUP BY t.src_ip, g.country, g.country_code, g.city, g.isp, g.org, g.asn,
                      g.hosting, g.proxy, g.mobile
             ORDER BY bytes DESC LIMIT 50",
            [$appKey]
        );
        foreach ($sources as &$r) {
            $net = self::classifyNetwork($r);
            $r['is_datacenter'] = $net['is_datacenter'];
            $r['is_proxy']      = $net['is_proxy'];
            $r['is_mobile']     = $net['is_mobile'];
            $r['ever_blocked']  = (int) ($r['ever_blocked'] ?? 0) > 0;
        }
        unset($r);

        $countries = $db->all(
            "SELECT COALESCE(g.country, 'Unknown') AS country, g.country_code,
                    COUNT(DISTINCT t.src_ip) AS sources,
                    SUM(t.requests) AS requests, SUM(t.bytes) AS bytes
             FROM traffic_events t
             LEFT JOIN geo_cache g ON g.ip_address = t.src_ip
             WHERE {$match} AND t.created_at >= (NOW() - INTERVAL {$hours} HOUR)
             GROUP BY country, g.country_code
             ORDER BY bytes DESC LIMIT 30",
            [$appKey]
        );

        $endpoints = $db->all(
            "SELECT t.top_path AS path, t.method, MAX(t.status_sample) AS status,
                    SUM(t.requests) AS requests, SUM(t.bytes) AS bytes, SUM(t.errors) AS errors
             FROM traffic_events t
             WHERE {$match} AND t.top_path IS NOT NULL AND t.top_path <> ''
               AND t.created_at >= (NOW() - INTERVAL {$hours} HOUR)
             GROUP BY t.top_path, t.method
             ORDER BY requests DESC LIMIT 50",
            [$appKey]
        );

        $recent = [];
        $errors = [];
        $statusCodes = [];
        if ($meta) {
            $appId = (int) $meta['id'];
            $recent = $db->all(
                "SELECT method, path, status_code, bytes, level, message, src_ip,
                        COALESCE(logged_at, created_at) AS at
                 FROM app_log_events WHERE app_id = ? ORDER BY id DESC LIMIT 40",
                [$appId]
            );
            // Recent problem lines: HTTP >= 400 or a warn/error severity level.
            $errors = $db->all(
                "SELECT method, path, status_code, level, message, src_ip,
                        COALESCE(logged_at, created_at) AS at
                 FROM app_log_events
                 WHERE app_id = ?
                   AND (status_code >= 400
                        OR LOWER(level) IN ('warn','warning','error','err','crit','critical','alert','emergency','fatal'))
                   AND COALESCE(logged_at, created_at) >= (NOW() - INTERVAL {$hours} HOUR)
                 ORDER BY id DESC LIMIT 40",
                [$appId]
            );
            // Status-code distribution over the window (from structured app logs).
            $statusCodes = $db->all(
                "SELECT status_code, COUNT(*) AS hits
                 FROM app_log_events
                 WHERE app_id = ? AND status_code IS NOT NULL
                   AND COALESCE(logged_at, created_at) >= (NOW() - INTERVAL {$hours} HOUR)
                 GROUP BY status_code ORDER BY hits DESC LIMIT 20",
                [$appId]
            );
        }

        return [
            'app'  => $appKey,
            'meta' => $meta ?: null,
            'activity' => [
                'requests'   => (int) ($act['requests'] ?? 0),
                'bytes'      => (int) ($act['bytes'] ?? 0),
                'errors'     => (int) ($act['errors'] ?? 0),
                'sources'    => (int) ($act['sources'] ?? 0),
                'first_seen' => $act['first_seen'] ?? null,
                'last_seen'  => $act['last_seen'] ?? null,
            ],
            'sources'       => $sources,
            'countries'     => $countries,
            'endpoints'     => $endpoints,
            'status_codes'  => $statusCodes,
            'errors'        => $errors,
            'recent'        => $recent,
            'window_hours'  => $hours,
        ];
    }

    // =================================================================
    // Entity drill-downs (Traffic Map)
    // =================================================================

    /**
     * Everything we know about a single source IP: geo + owning network,
     * whether it's a data center / proxy, its reputation (blocked history +
     * NIDS threats), a volume/activity summary, and the services, ports and
     * applications it touched. Powers the IP detail panel.
     */
    public static function ipDetail(string $ip, int $hours = 24): array
    {
        $hours = self::clampHours($hours);
        $db = Database::instance();

        $geo = $db->one('SELECT * FROM geo_cache WHERE ip_address = ?', [$ip]);

        // Volume / activity over the window.
        $act = $db->one(
            "SELECT
                SUM(CASE WHEN kind IN ('allow','app') THEN requests ELSE 0 END) AS requests,
                SUM(CASE WHEN kind IN ('allow','app') THEN bytes ELSE 0 END)    AS bytes,
                SUM(errors)                                                     AS errors,
                SUM(CASE WHEN kind = 'block' THEN bytes ELSE 0 END)             AS blocked_bytes,
                SUM(CASE WHEN kind = 'block' THEN requests ELSE 0 END)          AS blocked_packets,
                MIN(created_at) AS first_seen, MAX(created_at) AS last_seen,
                COUNT(*) AS events
             FROM traffic_events
             WHERE src_ip = ? AND created_at >= (NOW() - INTERVAL {$hours} HOUR)",
            [$ip]
        ) ?? [];

        // Services / applications this IP reached (managed app or vhost).
        $services = $db->all(
            "SELECT COALESCE(NULLIF(app_slug, ''), NULLIF(host, ''), 'server') AS service,
                    MAX(app_id) AS app_id,
                    SUM(requests) AS requests, SUM(bytes) AS bytes, SUM(errors) AS errors
             FROM traffic_events
             WHERE src_ip = ? AND kind IN ('allow','app')
               AND created_at >= (NOW() - INTERVAL {$hours} HOUR)
             GROUP BY service ORDER BY bytes DESC LIMIT 50",
            [$ip]
        );

        // Top endpoints / URLs hit.
        $endpoints = $db->all(
            "SELECT top_path AS path, method, MAX(status_sample) AS status,
                    SUM(requests) AS requests, SUM(bytes) AS bytes, SUM(errors) AS errors
             FROM traffic_events
             WHERE src_ip = ? AND top_path IS NOT NULL AND top_path <> ''
               AND created_at >= (NOW() - INTERVAL {$hours} HOUR)
             GROUP BY top_path, method ORDER BY requests DESC LIMIT 50",
            [$ip]
        );

        // Ports this IP probed / attacked (only NIDS records a destination port).
        $ports = $db->all(
            "SELECT dst_port AS port, category, MAX(severity) AS severity, SUM(count) AS hits,
                    MAX(created_at) AS last_seen
             FROM nids_events
             WHERE src_ip = ? AND dst_port IS NOT NULL
               AND created_at >= (NOW() - INTERVAL {$hours} HOUR)
             GROUP BY dst_port, category ORDER BY hits DESC LIMIT 50",
            [$ip]
        );

        // Recent per-app request lines for this IP.
        $recent = $db->all(
            "SELECT app_slug, method, path, status_code, bytes, level, message,
                    COALESCE(logged_at, created_at) AS at
             FROM app_log_events WHERE src_ip = ? ORDER BY id DESC LIMIT 40",
            [$ip]
        );

        return [
            'ip'         => $ip,
            'geo'        => self::geoView($geo),
            'reputation' => self::reputation($ip),
            'activity'   => [
                'requests'        => (int) ($act['requests'] ?? 0),
                'bytes'           => (int) ($act['bytes'] ?? 0),
                'errors'          => (int) ($act['errors'] ?? 0),
                'blocked_bytes'   => (int) ($act['blocked_bytes'] ?? 0),
                'blocked_packets' => (int) ($act['blocked_packets'] ?? 0),
                'events'          => (int) ($act['events'] ?? 0),
                'first_seen'      => $act['first_seen'] ?? null,
                'last_seen'       => $act['last_seen'] ?? null,
            ],
            'services'  => $services,
            'endpoints' => $endpoints,
            'ports'     => $ports,
            'recent'    => $recent,
            'window_hours' => $hours,
        ];
    }

    /**
     * Every source IP owned by an ISP / network, with each IP's volume and the
     * services it touched. Powers the ISP drill-down (ISP -> its IPs).
     */
    public static function ispSources(string $isp, int $hours = 24, int $limit = 250): array
    {
        $hours = self::clampHours($hours);
        $limit = max(1, min($limit, 1000));
        $unknown = ($isp === '' || strcasecmp($isp, 'Unknown') === 0);
        $where   = $unknown ? "(g.isp IS NULL OR g.isp = '')" : 'g.isp = ?';
        $params  = $unknown ? [] : [$isp];

        $rows = Database::instance()->all(
            "SELECT t.src_ip,
                    SUM(CASE WHEN t.kind IN ('allow','app') THEN t.requests ELSE 0 END) AS requests,
                    SUM(t.bytes) AS bytes, SUM(t.errors) AS errors,
                    SUM(CASE WHEN t.kind = 'block' THEN t.bytes ELSE 0 END) AS blocked_bytes,
                    GROUP_CONCAT(DISTINCT NULLIF(COALESCE(t.app_slug, t.host), '')
                        ORDER BY COALESCE(t.app_slug, t.host) SEPARATOR ', ') AS services,
                    g.country, g.country_code, g.city, g.isp, g.org, g.asn,
                    g.hosting, g.proxy, g.mobile,
                    EXISTS(SELECT 1 FROM blocked_hosts b WHERE b.ip_address = t.src_ip) AS ever_blocked
             FROM traffic_events t
             LEFT JOIN geo_cache g ON g.ip_address = t.src_ip
             WHERE {$where} AND t.created_at >= (NOW() - INTERVAL {$hours} HOUR)
             GROUP BY t.src_ip, g.country, g.country_code, g.city, g.isp, g.org, g.asn,
                      g.hosting, g.proxy, g.mobile
             ORDER BY bytes DESC LIMIT {$limit}",
            $params
        );

        foreach ($rows as &$r) {
            $net = self::classifyNetwork($r);
            $r['is_datacenter'] = $net['is_datacenter'];
            $r['is_proxy']      = $net['is_proxy'];
            $r['is_mobile']     = $net['is_mobile'];
            $r['ever_blocked']  = (int) ($r['ever_blocked'] ?? 0) > 0;
        }
        unset($r);

        return [
            'isp'          => $unknown ? 'Unknown' : $isp,
            'sources'      => $rows,
            'window_hours' => $hours,
        ];
    }

    /**
     * Every ISP / network seen in a country, with per-ISP IP counts and volume.
     * Powers the country drill-down (country -> ISPs -> IPs).
     */
    public static function countryIsps(string $code, int $hours = 24, int $limit = 200): array
    {
        $hours = self::clampHours($hours);
        $limit = max(1, min($limit, 1000));
        $unknown = ($code === '' || strcasecmp($code, 'Unknown') === 0);
        $where   = $unknown ? 'g.country_code IS NULL' : 'g.country_code = ?';
        $params  = $unknown ? [] : [strtoupper($code)];

        $rows = Database::instance()->all(
            "SELECT COALESCE(NULLIF(g.isp, ''), 'Unknown') AS isp, g.asn,
                    MAX(g.country) AS country,
                    COUNT(DISTINCT t.src_ip) AS sources,
                    SUM(CASE WHEN t.kind IN ('allow','app') THEN t.requests ELSE 0 END) AS requests,
                    SUM(t.bytes) AS bytes,
                    SUM(CASE WHEN t.kind = 'block' THEN t.bytes ELSE 0 END) AS blocked_bytes,
                    MAX(g.hosting) AS hosting
             FROM traffic_events t
             JOIN geo_cache g ON g.ip_address = t.src_ip
             WHERE {$where} AND t.created_at >= (NOW() - INTERVAL {$hours} HOUR)
             GROUP BY isp, g.asn
             ORDER BY bytes DESC LIMIT {$limit}",
            $params
        );

        foreach ($rows as &$r) {
            $r['is_datacenter'] = self::classifyNetwork($r)['is_datacenter'];
        }
        unset($r);

        return [
            'country_code' => $unknown ? null : strtoupper($code),
            'isps'         => $rows,
            'window_hours' => $hours,
        ];
    }

    // =================================================================
    // Entity detail helpers
    // =================================================================

    /** Shape a geo_cache row for the front-end, adding network classification. */
    private static function geoView(?array $geo): array
    {
        $net = self::classifyNetwork($geo);
        return [
            'country'      => $geo['country'] ?? null,
            'country_code' => $geo['country_code'] ?? null,
            'region'       => $geo['region'] ?? null,
            'city'         => $geo['city'] ?? null,
            'lat'          => isset($geo['lat']) && $geo['lat'] !== null ? (float) $geo['lat'] : null,
            'lng'          => isset($geo['lng']) && $geo['lng'] !== null ? (float) $geo['lng'] : null,
            'isp'          => $geo['isp'] ?? null,
            'org'          => $geo['org'] ?? null,
            'asn'          => $geo['asn'] ?? null,
            'is_datacenter' => $net['is_datacenter'],
            'is_proxy'      => $net['is_proxy'],
            'is_mobile'     => $net['is_mobile'],
        ];
    }

    /**
     * Reputation summary for an IP: current firewall block state, full block
     * history, and any NIDS threat activity ever recorded against it.
     */
    private static function reputation(string $ip): array
    {
        $db = Database::instance();

        $block = $db->one(
            "SELECT COUNT(*) AS total,
                    SUM(CASE WHEN active = 1 AND unblocked_at IS NULL
                              AND (permanent = 1 OR expires_at IS NULL OR expires_at > NOW())
                             THEN 1 ELSE 0 END) AS active,
                    MAX(blocked_at) AS last_blocked_at
             FROM blocked_hosts WHERE ip_address = ?",
            [$ip]
        ) ?? [];
        $lastReason = $db->scalar(
            "SELECT reason FROM blocked_hosts WHERE ip_address = ? ORDER BY blocked_at DESC LIMIT 1",
            [$ip]
        );

        $threat = $db->one(
            "SELECT COUNT(*) AS events, SUM(count) AS hits, MAX(severity) AS max_severity,
                    MAX(created_at) AS last_seen,
                    GROUP_CONCAT(DISTINCT category ORDER BY category SEPARATOR ', ') AS categories
             FROM nids_events WHERE src_ip = ?",
            [$ip]
        ) ?? [];

        $blockedNow  = (int) ($block['active'] ?? 0) > 0;
        $everBlocked = (int) ($block['total'] ?? 0) > 0;
        $threatEvents = (int) ($threat['events'] ?? 0);

        return [
            'blocked_now'     => $blockedNow,
            'ever_blocked'    => $everBlocked,
            'block_count'     => (int) ($block['total'] ?? 0),
            'last_blocked_at' => $block['last_blocked_at'] ?? null,
            'last_reason'     => $lastReason ? (string) $lastReason : null,
            'threat_events'   => $threatEvents,
            'threat_hits'     => (int) ($threat['hits'] ?? 0),
            'threat_severity' => $threat['max_severity'] ?? null,
            'threat_last_seen' => $threat['last_seen'] ?? null,
            'threat_categories' => $threat['categories'] ?? null,
            // A compact verdict for the badge in the UI.
            'flagged'         => $blockedNow || $everBlocked || $threatEvents > 0,
        ];
    }

    /**
     * Classify a network from geo flags, falling back to an ISP/org name
     * heuristic when the provider didn't populate the hosting flag (older
     * cached rows or the 'none' provider).
     *
     * @return array{is_datacenter:bool,is_proxy:bool,is_mobile:bool}
     */
    private static function classifyNetwork(?array $geo): array
    {
        $hosting = isset($geo['hosting']) && $geo['hosting'] !== null ? (bool) $geo['hosting'] : null;
        $proxy   = isset($geo['proxy'])   && $geo['proxy']   !== null ? (bool) $geo['proxy']   : null;
        $mobile  = isset($geo['mobile'])  && $geo['mobile']  !== null ? (bool) $geo['mobile']  : null;

        if ($hosting === null && $geo) {
            $name = strtolower(trim(($geo['isp'] ?? '') . ' ' . ($geo['org'] ?? '')));
            if ($name !== '') {
                static $needles = [
                    'amazon', 'aws', 'ec2', 'google', 'gcp', 'azure', 'microsoft', 'oracle cloud',
                    'digitalocean', 'ovh', 'hetzner', 'linode', 'akamai', 'vultr', 'contabo',
                    'leaseweb', 'datacenter', 'data center', 'hosting', 'colo', 'cloudflare',
                    'fastly', 'scaleway', 'alibaba', 'tencent', 'choopa', 'hostwinds', 'upcloud',
                    'server', 'dedicated', 'vps',
                ];
                foreach ($needles as $n) {
                    if (str_contains($name, $n)) {
                        $hosting = true;
                        break;
                    }
                }
            }
        }

        return [
            'is_datacenter' => (bool) $hosting,
            'is_proxy'      => (bool) $proxy,
            'is_mobile'     => (bool) $mobile,
        ];
    }

    // =================================================================
    // Internals
    // =================================================================

    /**
     * Per-source rollup joined to geo, including a blocked-bytes column and the
     * list of apps each IP touched. Shared by mapData / topSources.
     */
    private static function sourceAggregate(int $hours, array $filter = []): array
    {
        $hours = self::clampHours($hours);
        $f = self::buildFilter($filter);
        $rows = Database::instance()->all(
            "SELECT t.src_ip,
                    SUM(t.requests) AS requests,
                    SUM(t.bytes) AS bytes,
                    SUM(t.errors) AS errors,
                    SUM(CASE WHEN t.kind = 'block' THEN t.bytes ELSE 0 END) AS blocked_bytes,
                    GROUP_CONCAT(DISTINCT NULLIF(t.app_slug, '')) AS apps,
                    MAX(t.top_path) AS top_path,
                    g.country, g.country_code, g.city, g.isp, g.org, g.asn,
                    g.hosting, g.proxy, g.mobile, g.lat, g.lng
             FROM traffic_events t
             LEFT JOIN geo_cache g ON g.ip_address = t.src_ip
             WHERE t.created_at >= (NOW() - INTERVAL {$hours} HOUR){$f['sql']}
             GROUP BY t.src_ip, g.country, g.country_code, g.city, g.isp, g.org, g.asn,
                      g.hosting, g.proxy, g.mobile, g.lat, g.lng
             ORDER BY bytes DESC",
            $f['params']
        );
        foreach ($rows as &$r) {
            $net = self::classifyNetwork($r);
            $r['is_datacenter'] = $net['is_datacenter'];
            $r['is_proxy']      = $net['is_proxy'];
            $r['is_mobile']     = $net['is_mobile'];
        }
        unset($r);
        return $rows;
    }

    /**
     * Translate UI filter tags into an extra WHERE fragment combined with
     * boolean AND / OR. Predicates reference the base table alias `t` and the
     * geo_cache alias `g`, so every query that uses this MUST join geo_cache
     * as `g` and alias traffic_events as `t`.
     *
     * @param array $filter ['tags' => [['t'=>type,'v'=>value], ...], 'logic' => 'and'|'or']
     * @return array{sql:string, params:array} sql starts with " AND ( ... )" or ''
     */
    private static function buildFilter(array $filter): array
    {
        $tags  = isset($filter['tags']) && is_array($filter['tags']) ? $filter['tags'] : [];
        $logic = (isset($filter['logic']) && strtolower((string) $filter['logic']) === 'or') ? 'or' : 'and';

        $preds  = [];
        $params = [];
        foreach ($tags as $tag) {
            if (!is_array($tag)) {
                continue;
            }
            $type = strtolower(trim((string) ($tag['t'] ?? '')));
            $val  = trim((string) ($tag['v'] ?? ''));
            switch ($type) {
                case 'ip':
                    if (is_valid_ip($val)) {
                        $preds[]  = 't.src_ip = ?';
                        $params[] = $val;
                    }
                    break;
                case 'country':
                    if ($val === '' || strcasecmp($val, 'Unknown') === 0) {
                        $preds[] = 'g.country_code IS NULL';
                    } else {
                        $preds[]  = 'g.country_code = ?';
                        $params[] = strtoupper(substr($val, 0, 2));
                    }
                    break;
                case 'isp':
                    if ($val === '' || strcasecmp($val, 'Unknown') === 0) {
                        $preds[] = "(g.isp IS NULL OR g.isp = '')";
                    } else {
                        $preds[]  = 'g.isp = ?';
                        $params[] = $val;
                    }
                    break;
                case 'app':
                    if ($val !== '') {
                        $preds[]  = "COALESCE(NULLIF(t.app_slug, ''), NULLIF(t.host, ''), 'server') = ?";
                        $params[] = $val;
                    }
                    break;
                case 'flag':
                    switch (strtolower($val)) {
                        case 'datacenter':
                        case 'dc':
                            $preds[] = 'g.hosting = 1';
                            break;
                        case 'proxy':
                            $preds[] = 'g.proxy = 1';
                            break;
                        case 'mobile':
                            $preds[] = 'g.mobile = 1';
                            break;
                        case 'blocked':
                            $preds[] = 'EXISTS (SELECT 1 FROM blocked_hosts b WHERE b.ip_address = t.src_ip)';
                            break;
                    }
                    break;
            }
        }

        if (!$preds) {
            return ['sql' => '', 'params' => []];
        }
        $glue = $logic === 'or' ? ' OR ' : ' AND ';
        return ['sql' => ' AND (' . implode($glue, $preds) . ')', 'params' => $params];
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

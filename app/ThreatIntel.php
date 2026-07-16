<?php

declare(strict_types=1);

namespace App;

/**
 * Malicious-IP threat intelligence.
 *
 * Looks an IP address up against well-known threat databases and caches the
 * verdict in the ip_reputation table so we never hammer the upstream feeds.
 *
 *   * Reactive  — {@see lookup()} is called on-demand when an operator drills
 *                 into an IP. A fresh cache row is served instantly; a missing
 *                 row triggers a live check (a handful of DNS lookups).
 *   * Proactive — {@see refreshActive()} runs from the threat-intel cron
 *                 worker, scoring the most active offenders/sources and
 *                 optionally auto-blocking anything found malicious.
 *
 * Providers (all optional, enabled via config('threat_intel.*')):
 *   * DNSBL     — DNS blocklists (Spamhaus, Barracuda, SpamCop, SORBS, ...).
 *                 Free, no API key, IPv4 only. Enabled by default.
 *   * AbuseIPDB — https://www.abuseipdb.com REST API. Requires an API key.
 */
final class ThreatIntel
{
    /** Default DNS blocklist zones -> friendly provider name. */
    private const DEFAULT_DNSBL = [
        'zen.spamhaus.org'        => 'Spamhaus ZEN',
        'b.barracudacentral.org'  => 'Barracuda',
        'bl.spamcop.net'          => 'SpamCop',
        'dnsbl-1.uceprotect.net'  => 'UCEPROTECT',
        'all.s5h.net'             => 's5h',
    ];

    /**
     * Reputation for a single IP. Serves the cached verdict when present;
     * performs a live check when the cache is empty (or when forced).
     *
     * @return array The normalised ip_reputation row.
     */
    public static function lookup(string $ip, bool $force = false): array
    {
        $ip = trim($ip);
        if ($ip === '' || !is_valid_ip($ip)) {
            return self::emptyVerdict($ip, 'error');
        }
        if (self::isPrivate($ip)) {
            return self::store($ip, self::emptyVerdict($ip, 'private'));
        }
        if (!(bool) config('threat_intel.enabled', true)) {
            $row = self::cached($ip);
            return $row ?? self::emptyVerdict($ip, 'disabled');
        }

        $row = self::cached($ip);
        $ttl = (int) config('threat_intel.cache_hours', 12);
        if (!$force && $row !== null) {
            $age = time() - strtotime((string) ($row['checked_at'] ?? 'now'));
            $row['stale'] = $age > $ttl * 3600;
            // Only a completely missing row forces an inline network check; a
            // stale row is served as-is and refreshed by the cron worker.
            return $row;
        }

        return self::check($ip);
    }

    /**
     * Live check an IP against every configured provider and cache the result.
     */
    public static function check(string $ip): array
    {
        $ip = trim($ip);
        if ($ip === '' || !is_valid_ip($ip)) {
            return self::emptyVerdict($ip, 'error');
        }
        if (self::isPrivate($ip)) {
            return self::store($ip, self::emptyVerdict($ip, 'private'));
        }

        $sources    = [];
        $score      = 0;
        $reports    = 0;
        $categories = [];
        $usageType  = null;

        // --- DNS blocklists (free, IPv4 only) ---
        if ((bool) config('threat_intel.dnsbl_enabled', true) && self::isIpv4($ip)) {
            foreach (self::dnsblZones() as $zone => $name) {
                $listing = self::queryDnsbl($ip, $zone);
                if ($listing === null) {
                    continue;
                }
                $sources[] = [
                    'provider' => $name,
                    'zone'     => $zone,
                    'listed'   => true,
                    'result'   => $listing,
                ];
                $score += 25;
                $categories[] = 'dnsbl:' . $name;
            }
        }

        // --- AbuseIPDB (API key required) ---
        $key = trim((string) config('threat_intel.abuseipdb_key', ''));
        if ($key !== '') {
            $abuse = self::queryAbuseIpdb($ip, $key);
            if ($abuse !== null) {
                $confidence = (int) ($abuse['abuseConfidenceScore'] ?? 0);
                $reports   += (int) ($abuse['totalReports'] ?? 0);
                $usageType  = $abuse['usageType'] ?? null;
                $score      = max($score, $confidence);
                $sources[]  = [
                    'provider'   => 'AbuseIPDB',
                    'confidence' => $confidence,
                    'reports'    => (int) ($abuse['totalReports'] ?? 0),
                    'last_report'=> $abuse['lastReportedAt'] ?? null,
                    'country'    => $abuse['countryCode'] ?? null,
                    'usage_type' => $abuse['usageType'] ?? null,
                    'whitelisted'=> (bool) ($abuse['isWhitelisted'] ?? false),
                ];
                if ($confidence > 0) {
                    $categories[] = 'abuseipdb';
                }
            }
        }

        $score      = min(100, $score);
        $threshold  = (int) config('threat_intel.malicious_score', 50);
        $malicious  = $score >= $threshold && $sources !== [];

        $verdict = [
            'ip_address'    => $ip,
            'is_malicious'  => $malicious ? 1 : 0,
            'score'         => $score,
            'total_reports' => $reports,
            'categories'    => $categories ? implode(', ', array_slice(array_unique($categories), 0, 12)) : null,
            'sources'       => $sources,
            'usage_type'    => $usageType,
            'status'        => 'ok',
            'last_listed_at'=> $malicious ? date('Y-m-d H:i:s') : null,
        ];

        return self::store($ip, $verdict);
    }

    /**
     * Proactive sweep: score the most active offenders and recent sources,
     * refreshing any whose cache is stale/missing, and optionally auto-block
     * anything confirmed malicious.
     *
     * @return array{checked:int,malicious:int,blocked:string[]}
     */
    public static function refreshActive(int $limit = 200): array
    {
        $limit = max(1, min($limit, 1000));
        if (!(bool) config('threat_intel.enabled', true)) {
            return ['checked' => 0, 'malicious' => 0, 'blocked' => []];
        }

        $db  = Database::instance();
        $ttl = (int) config('threat_intel.cache_hours', 12);

        // Candidate IPs: recent NIDS offenders + recently blocked + heavy sources.
        $rows = $db->all(
            "SELECT src_ip AS ip FROM nids_events
             WHERE created_at >= (NOW() - INTERVAL 24 HOUR) AND src_ip <> ''
             GROUP BY src_ip ORDER BY SUM(count) DESC LIMIT {$limit}"
        );
        $ips = array_column($rows, 'ip');

        $extra = $db->all(
            "SELECT DISTINCT ip_address AS ip FROM blocked_hosts
             WHERE blocked_at >= (NOW() - INTERVAL 24 HOUR) LIMIT {$limit}"
        );
        foreach (array_column($extra, 'ip') as $ip) {
            $ips[] = $ip;
        }
        $ips = array_values(array_unique(array_filter($ips, static fn ($ip) => $ip !== '' && is_valid_ip($ip))));

        $checked   = 0;
        $malicious = 0;
        $blocked   = [];
        $autoBlock = (bool) config('threat_intel.auto_block', false);
        $minutes   = (int) config('threat_intel.auto_block_minutes', 1440);

        foreach ($ips as $ip) {
            if (self::isPrivate($ip)) {
                continue;
            }
            $row = self::cached($ip);
            $fresh = $row !== null
                && (time() - strtotime((string) $row['checked_at'])) < $ttl * 3600;
            if (!$fresh) {
                $row = self::check($ip);
                $checked++;
            }

            if ((int) ($row['is_malicious'] ?? 0) === 1) {
                $malicious++;
                if ($autoBlock
                    && !NidsManager::isWhitelisted($ip)
                    && !NidsManager::isBlocked($ip)) {
                    $res = NidsManager::block(
                        $ip,
                        'Threat intel: ' . ((string) ($row['categories'] ?? 'malicious IP')),
                        $minutes,
                        'threat-intel',
                        false
                    );
                    if (!empty($res['ok'])) {
                        $blocked[] = $ip;
                    }
                }
            }
        }

        return ['checked' => $checked, 'malicious' => $malicious, 'blocked' => $blocked];
    }

    /** Dashboard summary for the threat-intel feed. */
    public static function stats(): array
    {
        $db = Database::instance();
        return [
            'malicious_known' => (int) $db->scalar('SELECT COUNT(*) FROM ip_reputation WHERE is_malicious = 1'),
            'checked_total'   => (int) $db->scalar('SELECT COUNT(*) FROM ip_reputation'),
            'checked_24h'     => (int) $db->scalar(
                'SELECT COUNT(*) FROM ip_reputation WHERE checked_at >= (NOW() - INTERVAL 24 HOUR)'
            ),
            'enabled'         => (bool) config('threat_intel.enabled', true),
        ];
    }

    // -----------------------------------------------------------------
    // Providers
    // -----------------------------------------------------------------

    /** Query a single DNSBL zone; returns the listing code(s) or null. */
    private static function queryDnsbl(string $ip, string $zone): ?array
    {
        $host = self::reverseIpv4($ip) . '.' . $zone;
        // dns_get_record can be noisy on NXDOMAIN — suppress and inspect result.
        $records = @dns_get_record($host, DNS_A);
        if (!is_array($records) || $records === []) {
            return null;
        }
        $codes = [];
        foreach ($records as $r) {
            if (isset($r['ip'])) {
                $codes[] = $r['ip'];
            }
        }
        return $codes === [] ? null : ['codes' => $codes];
    }

    /** Query AbuseIPDB's check endpoint. Returns the `data` payload or null. */
    private static function queryAbuseIpdb(string $ip, string $key): ?array
    {
        $maxAge = (int) config('threat_intel.abuseipdb_max_age', 90);
        $url = 'https://api.abuseipdb.com/api/v2/check?ipAddress=' . rawurlencode($ip)
            . '&maxAgeInDays=' . max(1, min($maxAge, 365));

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 12,
            CURLOPT_HTTPHEADER     => ['Accept: application/json', 'Key: ' . $key],
        ]);
        $body = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($code < 200 || $code >= 300) {
            return null;
        }
        $decoded = json_decode((string) $body, true);
        return is_array($decoded) && isset($decoded['data']) && is_array($decoded['data'])
            ? $decoded['data']
            : null;
    }

    // -----------------------------------------------------------------
    // Cache
    // -----------------------------------------------------------------

    private static function cached(string $ip): ?array
    {
        $row = Database::instance()->one('SELECT * FROM ip_reputation WHERE ip_address = ?', [$ip]);
        return $row ? self::normalize($row) : null;
    }

    /** Upsert a verdict and return the normalised row. */
    private static function store(string $ip, array $verdict): array
    {
        $sources = $verdict['sources'] ?? [];
        Database::instance()->exec(
            "INSERT INTO ip_reputation
                (ip_address, is_malicious, score, total_reports, categories, sources,
                 usage_type, status, last_listed_at, checked_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
             ON DUPLICATE KEY UPDATE
                is_malicious = VALUES(is_malicious), score = VALUES(score),
                total_reports = VALUES(total_reports), categories = VALUES(categories),
                sources = VALUES(sources), usage_type = VALUES(usage_type),
                status = VALUES(status), last_listed_at = VALUES(last_listed_at),
                checked_at = NOW()",
            [
                $ip,
                (int) ($verdict['is_malicious'] ?? 0),
                (int) ($verdict['score'] ?? 0),
                (int) ($verdict['total_reports'] ?? 0),
                $verdict['categories'] ?? null,
                json_encode(is_array($sources) ? $sources : [], JSON_UNESCAPED_SLASHES),
                $verdict['usage_type'] ?? null,
                (string) ($verdict['status'] ?? 'ok'),
                $verdict['last_listed_at'] ?? null,
            ]
        );
        return self::cached($ip) ?? self::normalize($verdict + ['ip_address' => $ip]);
    }

    private static function normalize(array $r): array
    {
        $sources = $r['sources'] ?? null;
        if (is_string($sources)) {
            $decoded = json_decode($sources, true);
            $sources = is_array($decoded) ? $decoded : [];
        }
        return [
            'ip_address'    => $r['ip_address'] ?? null,
            'is_malicious'  => (int) ($r['is_malicious'] ?? 0) === 1,
            'score'         => (int) ($r['score'] ?? 0),
            'total_reports' => (int) ($r['total_reports'] ?? 0),
            'categories'    => $r['categories'] ?? null,
            'sources'       => is_array($sources) ? $sources : [],
            'usage_type'    => $r['usage_type'] ?? null,
            'status'        => (string) ($r['status'] ?? 'ok'),
            'last_listed_at'=> $r['last_listed_at'] ?? null,
            'checked_at'    => $r['checked_at'] ?? null,
            'stale'         => false,
        ];
    }

    private static function emptyVerdict(string $ip, string $status): array
    {
        return [
            'ip_address'    => $ip,
            'is_malicious'  => 0,
            'score'         => 0,
            'total_reports' => 0,
            'categories'    => null,
            'sources'       => [],
            'usage_type'    => null,
            'status'        => $status,
            'last_listed_at'=> null,
            'checked_at'    => null,
            'stale'         => false,
        ];
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /** @return array<string,string> zone => friendly name */
    private static function dnsblZones(): array
    {
        $cfg = config('threat_intel.dnsbl', null);
        if (is_array($cfg) && $cfg !== []) {
            $out = [];
            foreach ($cfg as $k => $v) {
                // Accept both ['zone' => 'Name'] and ['zone1','zone2'] shapes.
                if (is_int($k)) {
                    $out[(string) $v] = (string) $v;
                } else {
                    $out[(string) $k] = (string) $v;
                }
            }
            return $out;
        }
        return self::DEFAULT_DNSBL;
    }

    private static function reverseIpv4(string $ip): string
    {
        return implode('.', array_reverse(explode('.', $ip)));
    }

    private static function isIpv4(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    private static function isPrivate(string $ip): bool
    {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false;
    }
}

<?php

declare(strict_types=1);

namespace App;

/**
 * Resolves IP addresses to a geographic location + owning network (ISP / ASN).
 *
 * Distinct IPs are resolved once and cached in the geo_cache table so we never
 * hammer the upstream provider. The default provider is ip-api.com's free batch
 * endpoint (no key, HTTP only, ~15 batch requests/min, 100 IPs per batch).
 * Private / reserved IPs are recorded as "private" and never sent upstream.
 *
 * config('geo.*'):
 *   enabled     bool
 *   provider    'ip-api' | 'none'
 *   endpoint    batch endpoint URL
 *   cache_days  how long a cached row is considered fresh
 *   server_lat / server_lng / server_label  where this box sits on the map
 */
final class GeoLocator
{
    /** Fields we ask ip-api for (bit-packed numeric mask keeps the URL short). */
    private const IPAPI_FIELDS = 'status,message,country,countryCode,region,regionName,city,lat,lon,isp,org,as,mobile,proxy,hosting,query';

    /**
     * Resolve many IPs at once. Returns a map keyed by IP address.
     *
     * @param string[] $ips
     * @return array<string,array{country:?string,country_code:?string,region:?string,city:?string,lat:?float,lng:?float,isp:?string,org:?string,asn:?string,status:string}>
     */
    public static function locate(array $ips): array
    {
        $ips = array_values(array_unique(array_filter(array_map('trim', $ips), static fn ($ip) => $ip !== '')));
        if ($ips === []) {
            return [];
        }

        $out = [];
        $misses = [];

        // 1) Serve from cache where fresh.
        $cached = self::cachedRows($ips);
        foreach ($ips as $ip) {
            if (isset($cached[$ip])) {
                $out[$ip] = $cached[$ip];
                continue;
            }
            if (self::isPrivate($ip)) {
                $out[$ip] = self::store($ip, ['status' => 'private']);
                continue;
            }
            $misses[] = $ip;
        }

        if ($misses === [] || !(bool) config('geo.enabled', true)) {
            // Fill any remaining misses with a placeholder so callers get a row.
            foreach ($misses as $ip) {
                $out[$ip] = self::store($ip, ['status' => 'fail']);
            }
            return $out;
        }

        // 2) Resolve misses upstream in batches of 100.
        foreach (array_chunk($misses, 100) as $chunk) {
            $resolved = self::resolveUpstream($chunk);
            foreach ($chunk as $ip) {
                $out[$ip] = self::store($ip, $resolved[$ip] ?? ['status' => 'fail']);
            }
        }

        return $out;
    }

    /** Resolve a single IP (convenience wrapper). */
    public static function one(string $ip): ?array
    {
        $r = self::locate([$ip]);
        return $r[$ip] ?? null;
    }

    // -----------------------------------------------------------------
    // Cache
    // -----------------------------------------------------------------

    /** @param string[] $ips @return array<string,array> */
    private static function cachedRows(array $ips): array
    {
        $days = max(1, min((int) config('geo.cache_days', 14), 3650));
        $placeholders = implode(',', array_fill(0, count($ips), '?'));
        $sql = "SELECT * FROM geo_cache
                WHERE ip_address IN ($placeholders)
                  AND updated_at >= (NOW() - INTERVAL {$days} DAY)";

        $rows = [];
        foreach (Database::instance()->all($sql, $ips) as $row) {
            $rows[$row['ip_address']] = self::normalize($row);
        }
        return $rows;
    }

    /** Persist a resolution and return the normalized row. */
    private static function store(string $ip, array $data): array
    {
        $row = self::normalize($data + ['ip_address' => $ip]);
        Database::instance()->exec(
            'INSERT INTO geo_cache
                (ip_address, country, country_code, region, city, lat, lng, isp, org, asn, hosting, proxy, mobile, status, updated_at)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?, NOW())
             ON DUPLICATE KEY UPDATE
                country=VALUES(country), country_code=VALUES(country_code), region=VALUES(region),
                city=VALUES(city), lat=VALUES(lat), lng=VALUES(lng), isp=VALUES(isp),
                org=VALUES(org), asn=VALUES(asn), hosting=VALUES(hosting), proxy=VALUES(proxy),
                mobile=VALUES(mobile), status=VALUES(status), updated_at=NOW()',
            [
                $ip, $row['country'], $row['country_code'], $row['region'], $row['city'],
                $row['lat'], $row['lng'], $row['isp'], $row['org'], $row['asn'],
                $row['hosting'], $row['proxy'], $row['mobile'], $row['status'],
            ]
        );
        return $row;
    }

    // -----------------------------------------------------------------
    // Upstream providers
    // -----------------------------------------------------------------

    /** @param string[] $ips @return array<string,array> */
    private static function resolveUpstream(array $ips): array
    {
        $provider = (string) config('geo.provider', 'ip-api');
        if ($provider === 'ip-api') {
            return self::resolveIpApi($ips);
        }
        return [];
    }

    /** ip-api.com batch endpoint. @param string[] $ips @return array<string,array> */
    private static function resolveIpApi(array $ips): array
    {
        $endpoint = (string) config('geo.endpoint', 'http://ip-api.com/batch');
        $url = $endpoint . (str_contains($endpoint, '?') ? '&' : '?') . 'fields=' . self::IPAPI_FIELDS;

        $payload = array_map(static fn ($ip) => ['query' => $ip], $ips);
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
            CURLOPT_POSTFIELDS     => json_encode($payload, JSON_UNESCAPED_SLASHES),
        ]);
        $body = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $decoded = json_decode((string) $body, true);
        if ($code < 200 || $code >= 300 || !is_array($decoded)) {
            return [];
        }

        $out = [];
        foreach ($decoded as $entry) {
            if (!is_array($entry) || empty($entry['query'])) {
                continue;
            }
            $ok = ($entry['status'] ?? '') === 'success';
            $out[$entry['query']] = [
                'country'      => $ok ? ($entry['country'] ?? null) : null,
                'country_code' => $ok ? ($entry['countryCode'] ?? null) : null,
                'region'       => $ok ? ($entry['regionName'] ?? null) : null,
                'city'         => $ok ? ($entry['city'] ?? null) : null,
                'lat'          => $ok ? ($entry['lat'] ?? null) : null,
                'lng'          => $ok ? ($entry['lon'] ?? null) : null,
                'isp'          => $ok ? ($entry['isp'] ?? null) : null,
                'org'          => $ok ? ($entry['org'] ?? null) : null,
                'asn'          => $ok ? ($entry['as'] ?? null) : null,
                'hosting'      => $ok && isset($entry['hosting']) ? (int) (bool) $entry['hosting'] : null,
                'proxy'        => $ok && isset($entry['proxy']) ? (int) (bool) $entry['proxy'] : null,
                'mobile'       => $ok && isset($entry['mobile']) ? (int) (bool) $entry['mobile'] : null,
                'status'       => $ok ? 'ok' : 'fail',
            ];
        }
        return $out;
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private static function normalize(array $r): array
    {
        return [
            'ip_address'   => $r['ip_address'] ?? null,
            'country'      => $r['country'] ?? null,
            'country_code' => $r['country_code'] ?? null,
            'region'       => $r['region'] ?? null,
            'city'         => $r['city'] ?? null,
            'lat'          => isset($r['lat']) && $r['lat'] !== null ? (float) $r['lat'] : null,
            'lng'          => isset($r['lng']) && $r['lng'] !== null ? (float) $r['lng'] : null,
            'isp'          => $r['isp'] ?? null,
            'org'          => $r['org'] ?? null,
            'asn'          => $r['asn'] ?? null,
            'hosting'      => isset($r['hosting']) && $r['hosting'] !== null ? (int) (bool) $r['hosting'] : null,
            'proxy'        => isset($r['proxy']) && $r['proxy'] !== null ? (int) (bool) $r['proxy'] : null,
            'mobile'       => isset($r['mobile']) && $r['mobile'] !== null ? (int) (bool) $r['mobile'] : null,
            'status'       => (string) ($r['status'] ?? 'ok'),
        ];
    }

    /** True for private / reserved / loopback ranges that upstream can't resolve. */
    private static function isPrivate(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return true;
        }
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false;
    }
}

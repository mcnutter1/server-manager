<?php

declare(strict_types=1);

namespace App;

/**
 * Small helper functions + a static config accessor.
 */
final class Config
{
    /** Effective config (file values with any DB overrides applied). */
    private static array $data = [];
    /** Pristine file-based config, never mutated by overrides. */
    private static array $fileDefaults = [];

    public static function init(array $data): void
    {
        self::$data = $data;
        self::$fileDefaults = $data;
    }

    /** Dot-notation getter: Config::get('db.host'). */
    public static function get(string $key, mixed $default = null): mixed
    {
        return self::dig(self::$data, $key, $default);
    }

    /**
     * Read the original file-based value, ignoring any runtime DB override.
     * Used by the Settings UI to show the underlying default.
     */
    public static function fileDefault(string $key, mixed $default = null): mixed
    {
        return self::dig(self::$fileDefaults, $key, $default);
    }

    /**
     * Overlay a runtime value onto the effective config using dot-notation.
     * Does not touch the pristine file defaults.
     */
    public static function overlay(string $key, mixed $value): void
    {
        $segments = explode('.', $key);
        $ref = &self::$data;
        foreach ($segments as $i => $segment) {
            if ($i === count($segments) - 1) {
                $ref[$segment] = $value;
                break;
            }
            if (!isset($ref[$segment]) || !is_array($ref[$segment])) {
                $ref[$segment] = [];
            }
            $ref = &$ref[$segment];
        }
        unset($ref);
    }

    private static function dig(array $source, string $key, mixed $default): mixed
    {
        $value = $source;
        foreach (explode('.', $key) as $segment) {
            if (is_array($value) && array_key_exists($segment, $value)) {
                $value = $value[$segment];
            } else {
                return $default;
            }
        }
        return $value;
    }

    public static function all(): array
    {
        return self::$data;
    }
}

/**
 * Convenience helpers used across the codebase.
 */
function config(string $key, mixed $default = null): mixed
{
    return Config::get($key, $default);
}

/** Human readable bytes. */
function human_bytes(float $bytes, int $precision = 1): string
{
    $units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    $bytes = max($bytes, 0);
    $pow = $bytes > 0 ? floor(log($bytes) / log(1024)) : 0;
    $pow = (int) min($pow, count($units) - 1);
    $bytes /= (1024 ** $pow);
    return round($bytes, $precision) . ' ' . $units[$pow];
}

/** Validate an IPv4/IPv6 address. */
function is_valid_ip(string $ip): bool
{
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

/** Best-effort client IP resolution behind an AWS load balancer. */
function client_ip(): string
{
    $candidates = [];
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $candidates = array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']));
    }
    $candidates[] = $_SERVER['REMOTE_ADDR'] ?? '';
    foreach ($candidates as $ip) {
        if ($ip !== '' && is_valid_ip($ip)) {
            return $ip;
        }
    }
    return '0.0.0.0';
}

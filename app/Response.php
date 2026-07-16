<?php

declare(strict_types=1);

namespace App;

/**
 * JSON response helper for the REST API.
 */
final class Response
{
    public static function json(mixed $data, int $status = 200): never
    {
        if (!headers_sent()) {
            http_response_code($status);
            header('Content-Type: application/json; charset=utf-8');
            header('X-Content-Type-Options: nosniff');
        }
        // Raw log lines and request paths pulled from apps can contain bytes
        // that are not valid UTF-8. Substitute them instead of letting
        // json_encode() fail and emit an empty body (which the client then
        // reports as a generic "API error").
        $flags = JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT
            | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR;
        $out = json_encode($data, $flags);
        if ($out === false) {
            $out = json_encode(['ok' => false, 'error' => 'response encoding failed'], $flags)
                ?: '{"ok":false,"error":"response encoding failed"}';
        }
        echo $out;
        exit;
    }

    public static function ok(mixed $data = null, array $extra = []): never
    {
        self::json(array_merge(['ok' => true, 'data' => $data], $extra));
    }

    public static function error(string $message, int $status = 400, array $extra = []): never
    {
        self::json(array_merge(['ok' => false, 'error' => $message], $extra), $status);
    }

    public static function denied(string $message = 'Forbidden'): never
    {
        self::error($message, 403);
    }

    public static function unauthorized(string $message = 'Unauthorized'): never
    {
        self::error($message, 401);
    }

    public static function notFound(string $message = 'Not found'): never
    {
        self::error($message, 404);
    }
}

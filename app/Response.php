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
        echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
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

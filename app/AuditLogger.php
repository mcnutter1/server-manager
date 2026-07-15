<?php

declare(strict_types=1);

namespace App;

/**
 * Records every privileged / mutating action to the audit_log table.
 */
final class AuditLogger
{
    public static function log(
        string $action,
        ?string $target = null,
        array $params = [],
        string $result = 'success',
        ?string $message = null
    ): void {
        $actor = Auth::currentActor();
        try {
            Database::instance()->insert('audit_log', [
                'actor'      => $actor['name'],
                'actor_type' => $actor['type'],
                'action'     => $action,
                'target'     => $target,
                'params'     => $params ? json_encode(self::redact($params)) : null,
                'result'     => $result,
                'message'    => $message,
                'ip_address' => client_ip(),
            ]);
        } catch (\Throwable $e) {
            // Auditing must never break the request; log to error_log instead.
            error_log('[audit] failed: ' . $e->getMessage());
        }
    }

    /** Strip obvious secrets before persisting parameters. */
    private static function redact(array $params): array
    {
        $sensitive = ['token', 'password', 'pass', 'secret', 'api_token', 'helper_token'];
        foreach ($params as $key => $value) {
            if (in_array(strtolower((string) $key), $sensitive, true)) {
                $params[$key] = '***redacted***';
            } elseif (is_array($value)) {
                $params[$key] = self::redact($value);
            }
        }
        return $params;
    }
}

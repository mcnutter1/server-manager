<?php

declare(strict_types=1);

namespace App;

/**
 * Pairing unlock codes.
 *
 * To pair a downstream app, an operator first asks the manager for a short-lived
 * unlock CODE. They present that code to the target app's helper page, which
 * verifies it against this manager (POST /api/pair/verify) before revealing its
 * own enrollment key. This proves the operator is acting from the manager and
 * closes the window where anyone hitting an unpaired helper URL could read its
 * challenge.
 *
 * The plaintext code is never stored — only its SHA-256 hash.
 */
final class PairManager
{
    /** Issue a short-lived unlock code for the operator to present to an app. */
    public static function issueCode(?string $label = null, int $ttl = 900): array
    {
        $ttl  = max(60, min($ttl, 3600));
        $code = self::format(bin2hex(random_bytes(8))); // 64 bits, grouped

        Database::instance()->insert('pairing_codes', [
            'code_hash'  => hash('sha256', $code),
            'label'      => $label !== null && $label !== '' ? $label : null,
            'created_by' => Auth::currentActor()['name'] ?? 'system',
            'expires_at' => date('Y-m-d H:i:s', time() + $ttl),
        ]);

        self::prune();
        AuditLogger::log('pair.code_issued', $label);

        return ['ok' => true, 'code' => $code, 'expires_in' => $ttl];
    }

    /** True if the presented code matches a live, unexpired unlock code. */
    public static function verifyCode(string $code): bool
    {
        $code = trim($code);
        if ($code === '') {
            return false;
        }

        $db  = Database::instance();
        $row = $db->one(
            'SELECT id FROM pairing_codes WHERE code_hash = ? AND expires_at > NOW() LIMIT 1',
            [hash('sha256', $code)]
        );

        if (!$row) {
            return false;
        }

        $db->exec(
            'UPDATE pairing_codes SET used = used + 1, last_used_at = NOW() WHERE id = ?',
            [(int) $row['id']]
        );
        return true;
    }

    /** Drop codes that expired more than a day ago. */
    public static function prune(): void
    {
        Database::instance()->exec(
            'DELETE FROM pairing_codes WHERE expires_at < (NOW() - INTERVAL 1 DAY)'
        );
    }

    private static function format(string $hex): string
    {
        return strtoupper(implode('-', str_split($hex, 4)));
    }
}

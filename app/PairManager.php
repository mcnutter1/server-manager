<?php

declare(strict_types=1);

namespace App;

/**
 * Pairing unlock tokens.
 *
 * To pair a downstream app an operator asks the manager for a short-lived,
 * Ed25519-SIGNED unlock TOKEN and presents it to the target app's helper page.
 * The helper verifies the signature against this manager's public key (baked
 * into the helper at download time, or fetched from /api/pair/pubkey) — so it
 * knows, offline and un-interceptably, that the operator is acting from THIS
 * manager. Only then does it reveal its enrollment payload.
 *
 * Each token carries a unique `jti`; we persist only its SHA-256 hash. The jti
 * is the thread that binds the whole handshake together: the app echoes it back
 * inside its signed enrollment payload, and the manager consumes it exactly once
 * when the secret is claimed. That prevents replay and stops one token from
 * enrolling more than one app.
 */
final class PairManager
{
    /**
     * Issue a short-lived, signed unlock token for the operator to present to
     * an app. Returns the token plus the manager public key (for convenience).
     */
    public static function issueToken(?string $label = null, int $ttl = 900): array
    {
        $ttl = max(60, min($ttl, 3600));
        $jti = bin2hex(random_bytes(16));
        $exp = time() + $ttl;

        $token = PairCrypto::sign([
            'v'   => 2,
            'typ' => 'unlock',
            'jti' => $jti,
            'iss' => rtrim((string) config('app.base_url', ''), '/'),
            'exp' => $exp,
        ]);

        Database::instance()->insert('pairing_codes', [
            'code_hash'  => hash('sha256', $jti),
            'label'      => $label !== null && $label !== '' ? $label : null,
            'created_by' => Auth::currentActor()['name'] ?? 'system',
            'expires_at' => date('Y-m-d H:i:s', $exp),
        ]);

        self::prune();
        AuditLogger::log('pair.token_issued', $label, ['jti' => $jti]);

        return [
            'ok'         => true,
            'token'      => $token,
            'code'       => $token,   // legacy field name kept for the UI/API
            'jti'        => $jti,
            'expires_in' => $ttl,
            'pubkey'     => PairCrypto::publicKeyB64(),
        ];
    }

    /** Backwards-compatible alias — issues a signed token. */
    public static function issueCode(?string $label = null, int $ttl = 900): array
    {
        return self::issueToken($label, $ttl);
    }

    /** The manager's public signing key (base64url). */
    public static function pubKeyB64(): string
    {
        return PairCrypto::publicKeyB64();
    }

    /**
     * Look up the live, un-completed record for a jti.
     *
     * @return array{id:int}|null
     */
    public static function liveToken(string $jti): ?array
    {
        $row = Database::instance()->one(
            'SELECT id FROM pairing_codes
              WHERE code_hash = ? AND completed_at IS NULL AND expires_at > NOW()
              LIMIT 1',
            [hash('sha256', $jti)]
        );
        return $row ? ['id' => (int) $row['id']] : null;
    }

    /**
     * Atomically consume a jti (single use). Returns true only the first time a
     * live, unexpired, not-yet-completed token is redeemed. This is what makes
     * one unlock token enroll exactly one app.
     */
    public static function consumeToken(string $jti): bool
    {
        $affected = Database::instance()->exec(
            'UPDATE pairing_codes
                SET completed_at = NOW(), used = used + 1, last_used_at = NOW()
              WHERE code_hash = ? AND completed_at IS NULL AND expires_at > NOW()',
            [hash('sha256', $jti)]
        );
        return $affected > 0;
    }

    /**
     * Verify a presented unlock token: check the manager signature, type and
     * expiry, and that its jti is still live. Optionally consume it. Used by the
     * public /pair/verify endpoint for helpers that verify online.
     */
    public static function verifyToken(string $token, bool $consume = false): bool
    {
        $doc = PairCrypto::verify($token, PairCrypto::publicKeyB64());
        if (!is_array($doc) || ($doc['typ'] ?? '') !== 'unlock' || empty($doc['jti'])) {
            return false;
        }
        if ((int) ($doc['exp'] ?? 0) < time()) {
            return false;
        }
        $jti = (string) $doc['jti'];
        return $consume ? self::consumeToken($jti) : (self::liveToken($jti) !== null);
    }

    /**
     * Legacy verify used by older helpers: accept either a v2 signed token or a
     * plain code hash. Signed tokens are only peeked (consumed at enroll time).
     */
    public static function verifyCode(string $code): bool
    {
        $code = trim($code);
        if ($code === '') {
            return false;
        }
        if (str_contains($code, '.') && self::verifyToken($code, false)) {
            return true;
        }
        // Legacy plaintext code path (pre-v2 PIN codes).
        $db  = Database::instance();
        $row = $db->one(
            'SELECT id FROM pairing_codes
              WHERE code_hash = ? AND completed_at IS NULL AND expires_at > NOW() LIMIT 1',
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
}

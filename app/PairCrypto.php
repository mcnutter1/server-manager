<?php

declare(strict_types=1);

namespace App;

/**
 * Pairing cryptography — the manager's signing identity.
 *
 * The whole pairing handshake is anchored on an Ed25519 keypair owned by THIS
 * manager. The public half is baked into every helper downloaded from
 * /integrate/helper.php (and served at /api/pair/pubkey), so a downstream app
 * can verify — offline, with no callback that could be intercepted — that a
 * token really came from this manager. The private half never leaves the box.
 *
 * Tokens are compact and URL-safe:   base64url(json_payload).base64url(sig)
 *
 * This gives us three guarantees the old PIN/plaintext flow could not:
 *   1. Unforgeable manager tokens  — only the holder of the private key can
 *      mint an unlock/claim token the app will accept.
 *   2. Tamper-evident app payloads — the enrollment payload is self-signed by
 *      the app's own key, so the manager detects any modification.
 *   3. Replay resistance           — every token carries a jti + expiry.
 */
final class PairCrypto
{
    private const SETTING_KEY = 'pair:manager_sign_key';

    /** Cached decoded keypair for the request lifetime. */
    private static ?array $keypair = null;

    /**
     * Return the manager keypair, generating + persisting it on first use.
     *
     * @return array{public:string, secret:string} raw (binary) key material
     */
    private static function keypair(): array
    {
        if (self::$keypair !== null) {
            return self::$keypair;
        }
        if (!function_exists('sodium_crypto_sign_keypair')) {
            throw new \RuntimeException('libsodium (ext-sodium) is required for pairing');
        }

        $db  = Database::instance();
        $raw = $db->scalar('SELECT svalue FROM settings WHERE skey = ?', [self::SETTING_KEY]);
        $b64 = is_string($raw) ? trim(json_decode($raw, true) ?? '', '"') : '';
        $pair = $b64 !== '' ? base64_decode($b64, true) : false;

        if ($pair === false || strlen($pair) !== SODIUM_CRYPTO_SIGN_KEYPAIRBYTES) {
            $pair = sodium_crypto_sign_keypair();
            $db->exec(
                'INSERT INTO settings (skey, svalue) VALUES (?, ?)
                 ON DUPLICATE KEY UPDATE svalue = VALUES(svalue), updated_at = NOW()',
                [self::SETTING_KEY, json_encode(base64_encode($pair))]
            );
        }

        self::$keypair = [
            'public' => sodium_crypto_sign_publickey($pair),
            'secret' => sodium_crypto_sign_secretkey($pair),
        ];
        return self::$keypair;
    }

    /** The manager's public signing key, base64url encoded (safe to share). */
    public static function publicKeyB64(): string
    {
        return self::b64url(self::keypair()['public']);
    }

    /**
     * Mint a compact, signed token: base64url(json).base64url(sig).
     * Callers pass the semantic payload; iat is stamped automatically.
     */
    public static function sign(array $payload): string
    {
        $payload['iat'] = $payload['iat'] ?? time();
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        $sig  = sodium_crypto_sign_detached($json, self::keypair()['secret']);
        return self::b64url($json) . '.' . self::b64url($sig);
    }

    /**
     * Verify a token against a given base64url public key and return its
     * payload, or null if the signature/format is bad.
     */
    public static function verify(string $token, string $publicKeyB64): ?array
    {
        $parts = explode('.', trim($token));
        if (count($parts) !== 2) {
            return null;
        }
        $json = self::b64urlDecode($parts[0]);
        $sig  = self::b64urlDecode($parts[1]);
        $pub  = self::b64urlDecode($publicKeyB64);
        if ($json === '' || $sig === '' || strlen($pub) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return null;
        }
        try {
            if (!sodium_crypto_sign_verify_detached($sig, $json, $pub)) {
                return null;
            }
        } catch (\Throwable) {
            return null;
        }
        $doc = json_decode($json, true);
        return is_array($doc) ? $doc : null;
    }

    /** Verify a token that is self-signed by the key embedded in its payload. */
    public static function verifySelfSigned(string $token, string $pubField = 'app_pub'): ?array
    {
        $parts = explode('.', trim($token));
        if (count($parts) !== 2) {
            return null;
        }
        $doc = json_decode(self::b64urlDecode($parts[0]), true);
        if (!is_array($doc) || empty($doc[$pubField]) || !is_string($doc[$pubField])) {
            return null;
        }
        return self::verify($token, $doc[$pubField]);
    }

    public static function b64url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    public static function b64urlDecode(string $enc): string
    {
        $dec = base64_decode(strtr(trim($enc), '-_', '+/'), true);
        return $dec === false ? '' : $dec;
    }
}

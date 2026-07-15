<?php

declare(strict_types=1);

namespace App;

/**
 * Integration with the McNutt Cloud Notifications service.
 *
 * POST <endpoint>/api/send.php
 *   Authorization: Bearer <token>
 *   { channel, to, from?, subject?, body?, template_name?, data?, provider? }
 *
 * Alerts are de-duplicated and persisted to the alerts table before dispatch.
 */
final class Notifier
{
    /** Send a raw notification. */
    public static function send(array $payload): array
    {
        if (!config('notifications.enabled', false)) {
            return ['ok' => false, 'error' => 'notifications disabled'];
        }
        $endpoint = (string) config('notifications.endpoint');
        $token    = (string) config('notifications.api_token');
        if ($endpoint === '' || $token === '') {
            return ['ok' => false, 'error' => 'notifications not configured'];
        }

        $ch = curl_init($endpoint);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_HTTPHEADER     => [
                'Authorization: Bearer ' . $token,
                'Content-Type: application/json',
            ],
            CURLOPT_POSTFIELDS     => json_encode($payload, JSON_UNESCAPED_SLASHES),
        ]);
        $body = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err  = curl_error($ch);
        curl_close($ch);

        if ($code >= 200 && $code < 300) {
            return ['ok' => true, 'response' => json_decode((string) $body, true)];
        }
        return ['ok' => false, 'error' => $err ?: "HTTP {$code}", 'response' => $body];
    }

    public static function email(string $to, string $subject, string $body, ?string $from = null): array
    {
        return self::send([
            'channel' => 'email',
            'to'      => $to,
            'from'    => $from ?? config('notifications.default_from'),
            'subject' => $subject,
            'body'    => $body,
        ]);
    }

    public static function sms(string $to, string $body): array
    {
        return self::send(['channel' => 'sms', 'to' => $to, 'body' => $body]);
    }

    /**
     * Raise an operational alert: persist it, de-dupe, then dispatch through
     * the configured channels according to severity.
     */
    public static function alert(string $severity, string $category, string $title, string $body = ''): array
    {
        $fingerprint = sha1($severity . '|' . $category . '|' . $title);
        $db = Database::instance();

        // De-dupe identical alerts within a 30-minute window.
        $recent = $db->one(
            'SELECT id FROM alerts WHERE fingerprint = ? AND created_at >= (NOW() - INTERVAL 30 MINUTE) LIMIT 1',
            [$fingerprint]
        );
        if ($recent) {
            return ['ok' => true, 'deduped' => true, 'alert_id' => (int) $recent['id']];
        }

        $alertId = $db->insert('alerts', [
            'severity'    => $severity,
            'category'    => $category,
            'title'       => $title,
            'body'        => $body,
            'fingerprint' => $fingerprint,
            'notified'    => 0,
        ]);

        $dispatched = false;
        // Critical -> email + SMS; warning -> email; info -> stored only.
        if (in_array($severity, ['critical', 'warning'], true)) {
            $email = config('notifications.alert_email');
            if ($email) {
                self::email($email, "[{$severity}] {$title}", $body ?: $title);
                $dispatched = true;
            }
        }
        if ($severity === 'critical') {
            $sms = config('notifications.alert_sms');
            if ($sms) {
                self::sms($sms, "[CRIT] {$title}");
                $dispatched = true;
            }
        }

        if ($dispatched) {
            $db->exec('UPDATE alerts SET notified = 1 WHERE id = ?', [$alertId]);
        }

        return ['ok' => true, 'alert_id' => $alertId, 'dispatched' => $dispatched];
    }
}

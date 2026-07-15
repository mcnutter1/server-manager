<?php
/**
 * Local machine API token manager.
 *
 *   php bin/token.php create "backup-job" read,services,nids   [expires_days]
 *   php bin/token.php list
 *   php bin/token.php revoke <id>
 *
 * The raw token is shown ONCE on creation. Only its SHA-256 is stored.
 * Use it as:  Authorization: Bearer smgr_xxxxxxxx
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/app/bootstrap.php';

use App\Database;

if (PHP_SAPI !== 'cli') {
    exit(1);
}

$db = Database::instance();
$cmd = $argv[1] ?? 'list';

switch ($cmd) {
    case 'create':
        $name = $argv[2] ?? null;
        if (!$name) {
            fwrite(STDERR, "usage: token.php create <name> <scopes> [expires_days]\n");
            exit(1);
        }
        $scopes = array_filter(array_map('trim', explode(',', $argv[3] ?? 'read')));
        $days = isset($argv[4]) ? (int) $argv[4] : 0;
        $raw = 'smgr_' . bin2hex(random_bytes(24));
        $id = $db->insert('api_tokens', [
            'name'       => $name,
            'token_hash' => hash('sha256', $raw),
            'scopes'     => json_encode(array_values($scopes)),
            'created_by' => 'cli',
            'expires_at' => $days > 0 ? date('Y-m-d H:i:s', time() + $days * 86400) : null,
        ]);
        echo "Created token #{$id} ({$name})\n";
        echo "Scopes: " . implode(',', $scopes) . "\n";
        echo "TOKEN (store now, shown once):\n  {$raw}\n";
        break;

    case 'list':
        $rows = $db->all('SELECT id, name, scopes, last_used_at, expires_at, revoked, created_at FROM api_tokens ORDER BY id DESC');
        foreach ($rows as $r) {
            printf("#%d  %-20s scopes=%-30s revoked=%d  last=%s\n",
                $r['id'], $r['name'], $r['scopes'], $r['revoked'], $r['last_used_at'] ?? 'never');
        }
        if (!$rows) {
            echo "No tokens.\n";
        }
        break;

    case 'revoke':
        $id = (int) ($argv[2] ?? 0);
        $db->exec('UPDATE api_tokens SET revoked = 1 WHERE id = ?', [$id]);
        echo "Revoked token #{$id}\n";
        break;

    default:
        fwrite(STDERR, "unknown command: {$cmd}\n");
        exit(1);
}

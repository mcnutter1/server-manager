<?php
/**
 * Database migration runner.
 *
 * Applies every pending SQL file in sql/migrations/ (ordered by filename)
 * exactly once, recording each in the schema_migrations table so it is
 * never re-run. Migration files are written to be idempotent, so running
 * this against a database that was bootstrapped from sql/schema.sql simply
 * records the baseline as applied without changing anything.
 *
 * Usage:
 *   php bin/migrate.php            apply all pending migrations
 *   php bin/migrate.php --status   show applied / pending, apply nothing
 *   php bin/migrate.php --help
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/app/bootstrap.php';

use App\Database;

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

$args      = array_slice($argv, 1);
$statusOnly = in_array('--status', $args, true);
$help       = in_array('--help', $args, true) || in_array('-h', $args, true);

if ($help) {
    fwrite(STDOUT, <<<TXT
Usage:
  php bin/migrate.php            Apply all pending migrations.
  php bin/migrate.php --status   List applied / pending migrations only.
  php bin/migrate.php --help     Show this help.

Migration files live in sql/migrations/ and are named NNNN_name.sql.
They are applied in ascending filename order and recorded in the
schema_migrations table so each runs exactly once.

TXT);
    exit(0);
}

$dir = dirname(__DIR__) . '/sql/migrations';

/**
 * Split a SQL file into individual statements, honouring single-quoted
 * strings, double-quoted identifiers, line comments and block comments so
 * that semicolons inside any of them do not split a statement.
 */
function split_sql_statements(string $sql): array
{
    $statements = [];
    $buf        = '';
    $len        = strlen($sql);
    $inSingle   = false;
    $inDouble   = false;
    $inLine     = false;
    $inBlock    = false;

    for ($i = 0; $i < $len; $i++) {
        $ch   = $sql[$i];
        $next = $i + 1 < $len ? $sql[$i + 1] : '';

        if ($inLine) {
            if ($ch === "\n") {
                $inLine = false;
                $buf   .= $ch;
            }
            continue;
        }
        if ($inBlock) {
            if ($ch === '*' && $next === '/') {
                $inBlock = false;
                $i++;
            }
            continue;
        }
        if (!$inSingle && !$inDouble) {
            if ($ch === '-' && $next === '-') { $inLine = true;  $i++; continue; }
            if ($ch === '/' && $next === '*') { $inBlock = true; $i++; continue; }
        }
        if ($ch === "'" && !$inDouble) { $inSingle = !$inSingle; $buf .= $ch; continue; }
        if ($ch === '"' && !$inSingle) { $inDouble = !$inDouble; $buf .= $ch; continue; }

        if ($ch === ';' && !$inSingle && !$inDouble) {
            $stmt = trim($buf);
            if ($stmt !== '') {
                $statements[] = $stmt;
            }
            $buf = '';
            continue;
        }
        $buf .= $ch;
    }

    $stmt = trim($buf);
    if ($stmt !== '') {
        $statements[] = $stmt;
    }

    return $statements;
}

try {
    $db  = Database::instance();
    $pdo = $db->pdo();
} catch (\Throwable $e) {
    fwrite(STDERR, 'Cannot connect to database: ' . $e->getMessage() . "\n");
    exit(1);
}

// Migration bookkeeping table.
$pdo->exec(
    'CREATE TABLE IF NOT EXISTS schema_migrations (
        version    VARCHAR(190) NOT NULL,
        filename   VARCHAR(255) NOT NULL,
        checksum   CHAR(64)     NULL,
        applied_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (version)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
);

$applied = [];
foreach ($db->all('SELECT version FROM schema_migrations') as $row) {
    $applied[$row['version']] = true;
}

$files = glob($dir . '/*.sql') ?: [];
sort($files, SORT_STRING);

if (!$files) {
    fwrite(STDOUT, "No migration files found in {$dir}\n");
    exit(0);
}

if ($statusOnly) {
    fwrite(STDOUT, "Migration status:\n");
    foreach ($files as $file) {
        $version = basename($file, '.sql');
        $mark    = isset($applied[$version]) ? 'applied' : 'pending';
        fwrite(STDOUT, sprintf("  [%-7s] %s\n", $mark, $version));
    }
    exit(0);
}

$pending = 0;
foreach ($files as $file) {
    $version = basename($file, '.sql');
    if (isset($applied[$version])) {
        continue;
    }

    $sql = file_get_contents($file);
    if ($sql === false) {
        fwrite(STDERR, "Cannot read migration: {$file}\n");
        exit(1);
    }

    $checksum   = hash('sha256', $sql);
    $statements = split_sql_statements($sql);

    fwrite(STDOUT, "Applying {$version} (" . count($statements) . " statements)...\n");

    foreach ($statements as $idx => $stmt) {
        try {
            $pdo->exec($stmt);
        } catch (\Throwable $e) {
            fwrite(STDERR, sprintf(
                "  FAILED on statement #%d of %s: %s\n",
                $idx + 1,
                $version,
                $e->getMessage()
            ));
            fwrite(STDERR, "Migration halted. No further migrations applied.\n");
            exit(1);
        }
    }

    $stmt = $pdo->prepare(
        'INSERT INTO schema_migrations (version, filename, checksum)
         VALUES (:v, :f, :c)'
    );
    $stmt->execute([
        ':v' => $version,
        ':f' => basename($file),
        ':c' => $checksum,
    ]);

    fwrite(STDOUT, "  ok\n");
    $pending++;
}

if ($pending === 0) {
    fwrite(STDOUT, "Database is up to date; nothing to apply.\n");
} else {
    fwrite(STDOUT, "Applied {$pending} migration(s).\n");
}

exit(0);

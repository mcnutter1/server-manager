<?php

declare(strict_types=1);

namespace App;

use PDO;
use PDOException;

/**
 * Thin PDO wrapper (singleton) with convenience query helpers.
 */
final class Database
{
    private static ?Database $instance = null;
    private PDO $pdo;

    private function __construct()
    {
        $host = (string) config('db.host', '127.0.0.1');
        $port = (int) config('db.port', 3306);
        $name = (string) config('db.name', 'server_manager');
        $charset = (string) config('db.charset', 'utf8mb4');

        $dsn = "mysql:host={$host};port={$port};dbname={$name};charset={$charset}";

        try {
            $this->pdo = new PDO(
                $dsn,
                (string) config('db.user', 'root'),
                (string) config('db.pass', ''),
                [
                    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES   => false,
                ]
            );
        } catch (PDOException $e) {
            throw new \RuntimeException('Database connection failed: ' . $e->getMessage(), 0, $e);
        }
    }

    public static function instance(): Database
    {
        return self::$instance ??= new self();
    }

    public function pdo(): PDO
    {
        return $this->pdo;
    }

    /** Run a query and return all rows. */
    public function all(string $sql, array $params = []): array
    {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    /** Run a query and return the first row (or null). */
    public function one(string $sql, array $params = []): ?array
    {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /** Return a single scalar column from the first row. */
    public function scalar(string $sql, array $params = []): mixed
    {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchColumn();
    }

    /** Execute a write statement, return affected rows. */
    public function exec(string $sql, array $params = []): int
    {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->rowCount();
    }

    /** Insert helper — returns the new id. */
    public function insert(string $table, array $data): int
    {
        $cols = array_keys($data);
        $placeholders = array_map(static fn ($c) => ':' . $c, $cols);
        $sql = sprintf(
            'INSERT INTO %s (%s) VALUES (%s)',
            $table,
            implode(', ', $cols),
            implode(', ', $placeholders)
        );
        $stmt = $this->pdo->prepare($sql);
        foreach ($data as $key => $value) {
            $stmt->bindValue(':' . $key, $value);
        }
        $stmt->execute();
        return (int) $this->pdo->lastInsertId();
    }
}

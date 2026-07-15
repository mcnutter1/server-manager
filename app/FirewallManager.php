<?php

declare(strict_types=1);

namespace App;

/**
 * iptables visibility — parses rules, hit counters and byte counts for the UI.
 * Mutations to the block chain are handled by NidsManager; this class is
 * primarily read/report oriented plus snapshotting.
 */
final class FirewallManager
{
    /**
     * Parse `iptables -L -n -v --line-numbers` into structured chains.
     */
    public static function rules(string $table = 'filter'): array
    {
        $res = Runner::run('iptables.list', ['table' => $table], false);
        if (!$res['ok']) {
            return ['ok' => false, 'error' => $res['stderr'] ?: 'failed to read iptables', 'chains' => []];
        }

        $chains = [];
        $current = null;

        foreach (explode("\n", $res['stdout']) as $line) {
            $line = rtrim($line);
            if ($line === '') {
                continue;
            }

            if (preg_match('/^Chain\s+(\S+)\s+\((.*)\)/', $line, $m)) {
                $current = $m[1];
                $chains[$current] = [
                    'name'   => $current,
                    'policy' => $m[2],
                    'rules'  => [],
                ];
                continue;
            }

            // Header line.
            if (str_starts_with(ltrim($line), 'num') || str_contains($line, 'pkts bytes target')) {
                continue;
            }

            if ($current !== null && preg_match('/^\s*(\d+)\s+/', $line)) {
                $cols = preg_split('/\s+/', trim($line));
                // num pkts bytes target prot opt in out source destination [extra...]
                $chains[$current]['rules'][] = [
                    'num'    => (int) ($cols[0] ?? 0),
                    'pkts'   => self::parseCount($cols[1] ?? '0'),
                    'bytes'  => self::parseCount($cols[2] ?? '0'),
                    'target' => $cols[3] ?? '',
                    'prot'   => $cols[4] ?? '',
                    'in'     => $cols[6] ?? '',
                    'out'    => $cols[7] ?? '',
                    'source' => $cols[8] ?? '',
                    'dest'   => $cols[9] ?? '',
                    'extra'  => implode(' ', array_slice($cols, 10)),
                ];
            }
        }

        return ['ok' => true, 'table' => $table, 'chains' => array_values($chains)];
    }

    /** iptables prints counts like "1234", "12K", "3M". Normalise to int. */
    private static function parseCount(string $value): int
    {
        $value = trim($value);
        if (preg_match('/^([\d.]+)([KMGT])$/i', $value, $m)) {
            $mult = ['K' => 1e3, 'M' => 1e6, 'G' => 1e9, 'T' => 1e12][strtoupper($m[2])];
            return (int) ((float) $m[1] * $mult);
        }
        return (int) $value;
    }

    /** Summary stats for the dashboard. */
    public static function summary(): array
    {
        $data = self::rules('filter');
        $totalRules = 0;
        $drops = 0;
        $accepts = 0;
        foreach ($data['chains'] ?? [] as $chain) {
            foreach ($chain['rules'] as $rule) {
                $totalRules++;
                if ($rule['target'] === 'DROP' || $rule['target'] === 'REJECT') {
                    $drops++;
                }
                if ($rule['target'] === 'ACCEPT') {
                    $accepts++;
                }
            }
        }
        return [
            'total_rules' => $totalRules,
            'drop_rules'  => $drops,
            'accept_rules' => $accepts,
            'chains'      => count($data['chains'] ?? []),
        ];
    }

    /** Listening ports (attack surface view). */
    public static function listeningPorts(): array
    {
        $res = Runner::run('net.listening', [], false);
        $ports = [];
        foreach (explode("\n", $res['stdout']) as $line) {
            if (!preg_match('/^(tcp|udp)/', $line)) {
                continue;
            }
            $cols = preg_split('/\s+/', trim($line));
            if (count($cols) >= 5) {
                $local = $cols[4] ?? '';
                $port = substr(strrchr($local, ':') ?: '', 1);
                $ports[] = [
                    'proto'   => $cols[0],
                    'local'   => $local,
                    'port'    => $port,
                    'process' => $cols[6] ?? '',
                ];
            }
        }
        return $ports;
    }

    /** Persist a snapshot of the current ruleset for change tracking. */
    public static function snapshot(): int
    {
        $data = self::rules('filter');
        $ruleCount = 0;
        foreach ($data['chains'] ?? [] as $c) {
            $ruleCount += count($c['rules']);
        }
        return Database::instance()->insert('firewall_snapshots', [
            'table_name' => 'filter',
            'rules_json' => json_encode($data['chains'] ?? [], JSON_UNESCAPED_SLASHES),
            'rule_count' => $ruleCount,
        ]);
    }
}

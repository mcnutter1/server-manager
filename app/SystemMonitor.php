<?php

declare(strict_types=1);

namespace App;

/**
 * System health + resource monitoring.
 *
 * Reads /proc and standard tools directly (no elevated privileges needed) to
 * report CPU, memory, disk, load, network and uptime. Produces a health score
 * used by the dashboard and the alerting pipeline.
 */
final class SystemMonitor
{
    /** Full snapshot for the dashboard. */
    public static function snapshot(): array
    {
        $cpu  = self::cpu();
        $mem  = self::memory();
        $disk = self::disk('/');
        $load = self::loadAverage();
        $net  = self::network();

        $snapshot = [
            'hostname'   => gethostname() ?: php_uname('n'),
            'os'         => self::osRelease(),
            'kernel'     => php_uname('r'),
            'arch'       => php_uname('m'),
            'uptime'     => self::uptime(),
            'time'       => date('c'),
            'cpu'        => $cpu,
            'memory'     => $mem,
            'disk'       => $disk,
            'load'       => $load,
            'network'    => $net,
            'processes'  => self::processCount(),
        ];
        $snapshot['health'] = self::health($snapshot);
        return $snapshot;
    }

    // -----------------------------------------------------------------
    // CPU
    // -----------------------------------------------------------------
    public static function cpu(): array
    {
        $cores = self::coreCount();
        $first = self::readCpuLine();
        usleep(200000); // 200ms sample window
        $second = self::readCpuLine();

        $pct = 0.0;
        if ($first && $second) {
            $idleDelta  = ($second['idle'] + $second['iowait']) - ($first['idle'] + $first['iowait']);
            $totalDelta = $second['total'] - $first['total'];
            if ($totalDelta > 0) {
                $pct = round((1 - $idleDelta / $totalDelta) * 100, 1);
            }
        }
        return [
            'usage_pct' => max(0.0, min(100.0, $pct)),
            'cores'     => $cores,
            'model'     => self::cpuModel(),
        ];
    }

    private static function readCpuLine(): ?array
    {
        if (!is_readable('/proc/stat')) {
            return null;
        }
        $line = fgets(fopen('/proc/stat', 'r'));
        if ($line === false || strncmp($line, 'cpu ', 4) !== 0) {
            return null;
        }
        $parts = preg_split('/\s+/', trim($line));
        array_shift($parts); // "cpu"
        $vals = array_map('intval', $parts);
        [$user, $nice, $system, $idle, $iowait] = array_pad($vals, 5, 0);
        return [
            'idle'   => $idle,
            'iowait' => $iowait,
            'total'  => array_sum($vals),
        ];
    }

    private static function cpuModel(): string
    {
        if (is_readable('/proc/cpuinfo')) {
            foreach (file('/proc/cpuinfo') as $line) {
                if (stripos($line, 'model name') === 0) {
                    return trim(explode(':', $line, 2)[1] ?? 'CPU');
                }
            }
        }
        return 'CPU';
    }

    private static function coreCount(): int
    {
        if (is_readable('/proc/cpuinfo')) {
            $count = substr_count(file_get_contents('/proc/cpuinfo'), 'processor');
            if ($count > 0) {
                return $count;
            }
        }
        return (int) (shell_exec('nproc 2>/dev/null') ?: 1);
    }

    // -----------------------------------------------------------------
    // Memory
    // -----------------------------------------------------------------
    public static function memory(): array
    {
        $data = [];
        if (is_readable('/proc/meminfo')) {
            foreach (file('/proc/meminfo') as $line) {
                if (preg_match('/^(\w+):\s+(\d+)/', $line, $m)) {
                    $data[$m[1]] = (int) $m[2] * 1024; // kB -> bytes
                }
            }
        }
        $total = $data['MemTotal'] ?? 0;
        $avail = $data['MemAvailable'] ?? ($data['MemFree'] ?? 0);
        $used  = max(0, $total - $avail);
        $swapTotal = $data['SwapTotal'] ?? 0;
        $swapFree  = $data['SwapFree'] ?? 0;
        $swapUsed  = max(0, $swapTotal - $swapFree);

        return [
            'total'      => $total,
            'used'       => $used,
            'available'  => $avail,
            'used_pct'   => $total > 0 ? round($used / $total * 100, 1) : 0.0,
            'swap_total' => $swapTotal,
            'swap_used'  => $swapUsed,
            'swap_pct'   => $swapTotal > 0 ? round($swapUsed / $swapTotal * 100, 1) : 0.0,
        ];
    }

    // -----------------------------------------------------------------
    // Disk
    // -----------------------------------------------------------------
    public static function disk(string $path = '/'): array
    {
        $total = @disk_total_space($path) ?: 0;
        $free  = @disk_free_space($path) ?: 0;
        $used  = max(0, $total - $free);
        return [
            'path'     => $path,
            'total'    => (float) $total,
            'used'     => (float) $used,
            'free'     => (float) $free,
            'used_pct' => $total > 0 ? round($used / $total * 100, 1) : 0.0,
        ];
    }

    /** All mounted filesystems (best-effort via df). */
    public static function mounts(): array
    {
        $out = shell_exec("df -P -B1 2>/dev/null") ?: '';
        $rows = [];
        foreach (array_slice(explode("\n", trim($out)), 1) as $line) {
            $p = preg_split('/\s+/', trim($line));
            if (count($p) >= 6) {
                $rows[] = [
                    'filesystem' => $p[0],
                    'total'      => (float) $p[1],
                    'used'       => (float) $p[2],
                    'free'       => (float) $p[3],
                    'used_pct'   => (float) rtrim($p[4], '%'),
                    'mount'      => $p[5],
                ];
            }
        }
        return $rows;
    }

    // -----------------------------------------------------------------
    // Load + uptime + processes
    // -----------------------------------------------------------------
    public static function loadAverage(): array
    {
        $load = function_exists('sys_getloadavg') ? sys_getloadavg() : [0, 0, 0];
        $cores = max(1, self::coreCount());
        return [
            '1'          => round($load[0], 2),
            '5'          => round($load[1], 2),
            '15'         => round($load[2], 2),
            'per_core_1' => round($load[0] / $cores, 2),
        ];
    }

    public static function uptime(): array
    {
        $seconds = 0.0;
        if (is_readable('/proc/uptime')) {
            $seconds = (float) explode(' ', file_get_contents('/proc/uptime'))[0];
        }
        return [
            'seconds' => (int) $seconds,
            'human'   => self::humanUptime((int) $seconds),
        ];
    }

    private static function humanUptime(int $seconds): string
    {
        $d = intdiv($seconds, 86400);
        $h = intdiv($seconds % 86400, 3600);
        $m = intdiv($seconds % 3600, 60);
        $parts = [];
        if ($d) $parts[] = "{$d}d";
        if ($h) $parts[] = "{$h}h";
        $parts[] = "{$m}m";
        return implode(' ', $parts);
    }

    public static function processCount(): int
    {
        $glob = glob('/proc/[0-9]*');
        return $glob ? count($glob) : 0;
    }

    public static function network(): array
    {
        $rx = 0;
        $tx = 0;
        if (is_readable('/proc/net/dev')) {
            foreach (array_slice(file('/proc/net/dev'), 2) as $line) {
                if (!str_contains($line, ':')) {
                    continue;
                }
                [$iface, $rest] = explode(':', $line, 2);
                $iface = trim($iface);
                if ($iface === 'lo') {
                    continue;
                }
                $cols = preg_split('/\s+/', trim($rest));
                $rx += (int) ($cols[0] ?? 0);
                $tx += (int) ($cols[8] ?? 0);
            }
        }
        return ['rx_bytes' => $rx, 'tx_bytes' => $tx];
    }

    // -----------------------------------------------------------------
    // Top processes (by CPU / memory)
    // -----------------------------------------------------------------
    public static function topProcesses(int $limit = 10): array
    {
        $out = shell_exec('ps -eo pid,comm,%cpu,%mem,rss --sort=-%cpu 2>/dev/null') ?: '';
        $rows = [];
        foreach (array_slice(explode("\n", trim($out)), 1, $limit) as $line) {
            $p = preg_split('/\s+/', trim($line), 5);
            if (count($p) >= 5) {
                $rows[] = [
                    'pid'  => (int) $p[0],
                    'name' => $p[1],
                    'cpu'  => (float) $p[2],
                    'mem'  => (float) $p[3],
                    'rss'  => (int) $p[4] * 1024,
                ];
            }
        }
        return $rows;
    }

    // -----------------------------------------------------------------
    // OS release + health scoring
    // -----------------------------------------------------------------
    private static function osRelease(): string
    {
        if (is_readable('/etc/os-release')) {
            foreach (file('/etc/os-release') as $line) {
                if (str_starts_with($line, 'PRETTY_NAME=')) {
                    return trim(explode('=', $line, 2)[1], "\"\n ");
                }
            }
        }
        return php_uname('s') . ' ' . php_uname('r');
    }

    /**
     * Compute an overall health verdict from thresholds.
     * @return array{status:string,score:int,reasons:array}
     */
    public static function health(array $snapshot): array
    {
        $reasons = [];
        $status = 'healthy';

        $checks = [
            ['cpu',  $snapshot['cpu']['usage_pct'],   config('monitoring.cpu_warn', 75),  config('monitoring.cpu_crit', 90),  'CPU usage'],
            ['mem',  $snapshot['memory']['used_pct'], config('monitoring.mem_warn', 80),  config('monitoring.mem_crit', 92),  'Memory usage'],
            ['disk', $snapshot['disk']['used_pct'],   config('monitoring.disk_warn', 80), config('monitoring.disk_crit', 90), 'Disk usage'],
        ];

        $score = 100;
        foreach ($checks as [$key, $value, $warn, $crit, $label]) {
            if ($value >= $crit) {
                $reasons[] = "{$label} critical ({$value}%)";
                $status = 'critical';
                $score -= 30;
            } elseif ($value >= $warn) {
                $reasons[] = "{$label} elevated ({$value}%)";
                if ($status !== 'critical') {
                    $status = 'warning';
                }
                $score -= 15;
            }
        }

        $loadWarn = (float) config('monitoring.load_warn', 4.0);
        if (($snapshot['load']['1'] ?? 0) >= $loadWarn) {
            $reasons[] = "Load average high ({$snapshot['load']['1']})";
            if ($status === 'healthy') {
                $status = 'warning';
            }
            $score -= 10;
        }

        return [
            'status'  => $status,
            'score'   => max(0, $score),
            'reasons' => $reasons,
        ];
    }
}

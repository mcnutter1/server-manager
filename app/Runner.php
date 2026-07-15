<?php

declare(strict_types=1);

namespace App;

/**
 * PHP bridge to runner/runner.py.
 *
 * The web tier holds NO direct privileges. Every privileged action is a
 * whitelisted "action key" dispatched to the Python runner over sudo, with a
 * shared token and a JSON request on stdin. Results are logged to command_log.
 */
final class Runner
{
    /**
     * Execute a whitelisted runner action.
     *
     * @return array{ok:bool,exit_code:int,stdout:string,stderr:string,data:array}
     */
    public static function run(string $action, array $args = [], bool $log = true): array
    {
        $python  = (string) config('runner.python', '/usr/bin/python3');
        $script  = (string) config('runner.script');
        $token   = (string) config('runner.token');
        $timeout = (int) config('runner.timeout', 30);
        $useSudo = (bool) config('runner.use_sudo', true);
        $sudo    = (string) config('runner.sudo_binary', '/usr/bin/sudo');

        if ($script === '' || !is_file($script)) {
            return self::failure("runner script not found at {$script}");
        }

        // Build the argv array — no shell interpolation anywhere.
        $cmd = [];
        if ($useSudo) {
            $cmd[] = $sudo;
            $cmd[] = '-n';               // never prompt for a password
        }
        $cmd[] = $python;
        $cmd[] = $script;

        $request = json_encode([
            'token'  => $token,
            'action' => $action,
            'args'   => $args,
        ], JSON_UNESCAPED_SLASHES);

        $started = microtime(true);
        $result = self::proc($cmd, $request, $timeout);
        $durationMs = (int) round((microtime(true) - $started) * 1000);

        $decoded = json_decode($result['stdout'], true);
        if (!is_array($decoded)) {
            $decoded = [
                'ok'        => false,
                'error'     => 'runner returned invalid output',
                'exit_code' => $result['exit_code'],
                'stdout'    => $result['stdout'],
                'stderr'    => $result['stderr'],
            ];
        }

        $normalized = [
            'ok'        => (bool) ($decoded['ok'] ?? false),
            'exit_code' => (int) ($decoded['exit_code'] ?? $result['exit_code']),
            'stdout'    => (string) ($decoded['stdout'] ?? ''),
            'stderr'    => (string) ($decoded['stderr'] ?? ($decoded['error'] ?? '')),
            'data'      => (array) ($decoded['data'] ?? []),
            'error'     => $decoded['error'] ?? null,
        ];

        if ($log) {
            self::logCommand($action, $args, $normalized, $durationMs);
        }

        return $normalized;
    }

    /**
     * Low-level process execution with stdin piping via proc_open.
     */
    private static function proc(array $cmd, string $stdin, int $timeout): array
    {
        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        // Use exec-style array where supported (PHP 7.4+ accepts array cmd).
        $process = @proc_open($cmd, $descriptors, $pipes);
        if (!\is_resource($process)) {
            return ['exit_code' => 127, 'stdout' => '', 'stderr' => 'failed to start runner'];
        }

        fwrite($pipes[0], $stdin);
        fclose($pipes[0]);

        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);

        $stdout = '';
        $stderr = '';
        $deadline = microtime(true) + $timeout;

        do {
            $status = proc_get_status($process);
            $stdout .= stream_get_contents($pipes[1]) ?: '';
            $stderr .= stream_get_contents($pipes[2]) ?: '';
            if (!$status['running']) {
                break;
            }
            if (microtime(true) > $deadline) {
                proc_terminate($process, 9);
                $stderr .= "\nrunner timed out after {$timeout}s";
                break;
            }
            usleep(20000);
        } while (true);

        // Drain any remaining output.
        $stdout .= stream_get_contents($pipes[1]) ?: '';
        $stderr .= stream_get_contents($pipes[2]) ?: '';

        fclose($pipes[1]);
        fclose($pipes[2]);
        $exit = proc_close($process);

        return ['exit_code' => $exit, 'stdout' => $stdout, 'stderr' => $stderr];
    }

    private static function failure(string $message): array
    {
        return [
            'ok'        => false,
            'exit_code' => 1,
            'stdout'    => '',
            'stderr'    => $message,
            'data'      => [],
            'error'     => $message,
        ];
    }

    private static function logCommand(string $action, array $args, array $result, int $durationMs): void
    {
        try {
            $actor = Auth::currentActor();
            Database::instance()->insert('command_log', [
                'actor'       => $actor['name'],
                'command_key' => $action,
                'arguments'   => json_encode($args, JSON_UNESCAPED_SLASHES),
                'exit_code'   => $result['exit_code'],
                'duration_ms' => $durationMs,
                'stdout'      => mb_substr($result['stdout'], 0, 60000),
                'stderr'      => mb_substr($result['stderr'], 0, 20000),
                'ip_address'  => client_ip(),
            ]);
        } catch (\Throwable $e) {
            error_log('[runner] command_log failed: ' . $e->getMessage());
        }
    }

    /** List of allowed action keys (mirrors runner.py HANDLERS). */
    public static function actions(): array
    {
        return [
            'service.status', 'service.start', 'service.stop', 'service.restart',
            'service.reload', 'service.list', 'journal.tail', 'iptables.list',
            'nids.block', 'nids.unblock', 'nids.stats', 'net.listening',
        ];
    }
}

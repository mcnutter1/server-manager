<?php

declare(strict_types=1);

namespace App;

/**
 * systemd service management via the privileged runner.
 */
final class ServiceManager
{
    /** List all services with a "critical" flag from config. */
    public static function list(): array
    {
        $res = Runner::run('service.list', [], false);
        $services = $res['data']['services'] ?? [];
        $critical = config('monitoring.critical_services', []);

        foreach ($services as &$svc) {
            $name = str_replace('.service', '', $svc['unit']);
            $svc['name']     = $name;
            $svc['critical'] = in_array($name, $critical, true);
        }
        unset($svc);

        // Sort: critical first, then failed/inactive, then alphabetical.
        usort($services, static function ($a, $b) {
            if ($a['critical'] !== $b['critical']) {
                return $b['critical'] <=> $a['critical'];
            }
            $rank = static fn ($s) => $s['active'] === 'failed' ? 0 : ($s['active'] === 'active' ? 2 : 1);
            $ra = $rank($a);
            $rb = $rank($b);
            if ($ra !== $rb) {
                return $ra <=> $rb;
            }
            return strcmp($a['unit'], $b['unit']);
        });

        return $services;
    }

    /** Detailed status of a single service. */
    public static function status(string $service): array
    {
        $res = Runner::run('service.status', ['service' => $service], false);
        $d = $res['data'];
        return [
            'service'       => $service,
            'active_state'  => $d['ActiveState'] ?? 'unknown',
            'sub_state'     => $d['SubState'] ?? '',
            'load_state'    => $d['LoadState'] ?? '',
            'enabled'       => ($d['UnitFileState'] ?? '') === 'enabled',
            'unit_file'     => $d['UnitFileState'] ?? '',
            'main_pid'      => (int) ($d['MainPID'] ?? 0),
            'started_at'    => $d['ExecMainStartTimestamp'] ?? '',
        ];
    }

    /** Perform start|stop|restart|reload, audited. */
    public static function action(string $service, string $verb): array
    {
        $allowed = ['start', 'stop', 'restart', 'reload'];
        if (!in_array($verb, $allowed, true)) {
            throw new \InvalidArgumentException('Invalid service verb.');
        }

        $before = self::status($service);
        $res = Runner::run("service.{$verb}", ['service' => $service]);
        $after = self::status($service);

        AuditLogger::log(
            "service.{$verb}",
            $service,
            ['from' => $before['active_state'], 'to' => $after['active_state']],
            $res['ok'] ? 'success' : 'failure',
            $res['ok'] ? null : ($res['stderr'] ?: 'command failed')
        );

        // Record the transition for history.
        try {
            Database::instance()->insert('service_events', [
                'service'   => $service,
                'state'     => $after['active_state'],
                'sub_state' => $after['sub_state'],
                'detail'    => "action={$verb} by " . Auth::currentActor()['name'],
            ]);
        } catch (\Throwable $e) {
            error_log('[services] event log failed: ' . $e->getMessage());
        }

        return [
            'ok'     => $res['ok'],
            'verb'   => $verb,
            'status' => $after,
            'stderr' => $res['stderr'],
        ];
    }

    /** Health roll-up of the critical services only. */
    public static function criticalHealth(): array
    {
        $out = [];
        foreach (config('monitoring.critical_services', []) as $svc) {
            $status = self::status($svc);
            $out[] = [
                'name'    => $svc,
                'state'   => $status['active_state'],
                'healthy' => $status['active_state'] === 'active',
            ];
        }
        return $out;
    }
}

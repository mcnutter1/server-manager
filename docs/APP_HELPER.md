# Managed App Helper Framework

Server Manager talks to each managed application through a tiny, uniform
**helper endpoint** that the app ships. This gives the central platform a
common way to interface with apps that all have their own code and database.

## Contract

```
POST https://<app-domain>/<helper_path>          (default: srvmgr/helper.php)
Header:  X-Srvmgr-Token: <shared secret>          (managed_apps.helper_token)
Body:    { "action": "<name>", ...params }
Reply:   { "ok": true, "data": { ... } }
```

The token is a shared secret stored (encrypted at rest is recommended) in the
`managed_apps.helper_token` column and sent on every call. The helper MUST
reject requests whose token does not match, in constant time.

## Standard actions

| action        | purpose                                             |
|---------------|-----------------------------------------------------|
| `health`      | Return `{status:"ok"|"degraded", db:bool, ...}`     |
| `stats`       | App-specific counters (users, rows, queue depth…)   |
| `version`     | Deployed version / git SHA                          |
| `components`  | App-declared sub-processes / components (see below) |
| `commands`    | App-declared CLI commands this platform can invoke  |
| `command`     | Execute one declared command (`{command, args}`)    |
| `migrate`     | Run pending DB migrations (guard carefully!)        |
| `clear_cache` | Flush the app cache                                 |
| `maintenance` | Toggle maintenance mode (`{on:true|false}`)         |

Apps may add their own actions; unknown actions should return
`{ "ok": false, "error": "unknown action" }` with HTTP 400.

## Extensible capabilities (common information model)

The helper is deliberately open-ended: beyond the fixed actions above, each app
declares **its own** health surface and command set. Server Manager renders
whatever an app exposes uniformly, so every app can surface exactly the things
that matter to it (workers, queues, integrations, datastores, cron jobs, …)
while still fitting one common information model.

### `components` — custom health surface

Return the sub-processes / components the app runs. Each component follows this
model (only `id`, `name` and `status` are required):

```json
{
  "components": [
    {
      "id": "queue-worker",
      "name": "Queue worker",
      "kind": "process",            // process|service|worker|queue|datastore|integration|job|custom
      "status": "ok",               // ok|healthy|degraded|down|unknown
      "summary": "3 running · 12 jobs/min",
      "metrics": { "workers": 3, "queue_depth": 12 },
      "detail": "optional longer text",
      "commands": ["worker.restart", "worker.stats"]   // command keys tied to this component
    }
  ]
}
```

Any component reporting `degraded`/`down` pulls the app's overall health down.
Components are stored with each health check and shown in the health report.

### `commands` — app-declared CLI commands

Return the commands the app is willing to run. Server Manager offers these as
buttons on the health report (next to a component) and in the CLI Runner.

```json
{
  "commands": [
    {
      "key": "worker.restart",
      "name": "Restart worker",
      "description": "Gracefully restart the queue worker",
      "component": "queue-worker",         // optional link back to a component
      "dangerous": false,                  // true => UI confirms first
      "params": [
        { "name": "graceful", "type": "bool", "label": "Graceful", "default": true }
      ]
    }
  ]
}
```

### `command` — execute one

Server Manager POSTs `{ "action": "command", "command": "worker.restart",
"args": { "graceful": true } }`. The helper MUST only run commands it declared
in `commands` (the app owns the allow-list) and return
`{ "ok": true, "data": { "output": "…" } }`.


## Drop-in reference

Copy [`app-helper-sample.php`](app-helper-sample.php) into your app at
`srvmgr/helper.php`, set the token, and wire the `health`/`stats`/`components`/
`commands` bodies to your app's internals. Then in Server Manager:

1. **Register** the app (Applications → Register) — name + path only, no
   pairing info.
2. **Pair** it (Applications → Pair app) — generate the unlock token, paste it
   on the app's helper page, then paste the app's enrollment payload back. Only
   those two keys are needed; the shared secret never gets copied by hand.

## Security notes

* The helper runs **inside the app**, using the app's own DB credentials —
  Server Manager never receives app database passwords.
* Always require HTTPS and the shared token.
* Keep destructive actions (`migrate`) behind an extra confirmation flag.

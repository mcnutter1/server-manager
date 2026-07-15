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
| `migrate`     | Run pending DB migrations (guard carefully!)        |
| `clear_cache` | Flush the app cache                                 |
| `maintenance` | Toggle maintenance mode (`{on:true|false}`)         |

Apps may add their own actions; unknown actions should return
`{ "ok": false, "error": "unknown action" }` with HTTP 400.

## Drop-in reference

Copy [`app-helper-sample.php`](app-helper-sample.php) into your app at
`srvmgr/helper.php`, set the token, and wire the `health`/`stats` bodies to
your app's internals. Register the app in Server Manager (Applications →
Register) with the matching `helper_token` and `domain`.

## Security notes

* The helper runs **inside the app**, using the app's own DB credentials —
  Server Manager never receives app database passwords.
* Always require HTTPS and the shared token.
* Keep destructive actions (`migrate`) behind an extra confirmation flag.

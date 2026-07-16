# AI / LLM Diagnostics Interface

A **read-only**, key-protected window into the platform so an AI agent (or a
human operator) can work out *why a downstream app's services aren't working* —
by inspecting logs, the database, the audit trail and **live** helper/API
interactions.

Everything here is read-only. Nothing in this interface can restart a service,
change a setting, block an IP, or write to the database.

---

## 1. Getting a key

The interface is gated by an API token carrying the `diag` scope. Create one on
the server and hand the raw value to the agent (it is shown **once**):

```bash
php bin/token.php create ai-diag diag 7      # name=ai-diag, scope=diag, expires in 7 days
```

Or generate one from the browser: **Settings → AI diagnostics access → Generate
key**. The key is shown once; copy it and hand it to the agent. The same page
lists existing keys and lets you revoke them.

Revoke it at any time:

```bash
php bin/token.php list
php bin/token.php revoke <id>
```

The raw token looks like `smgr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`. Only its
SHA-256 is stored server-side.

## 2. Authenticating

Send the token as a bearer credential on every request:

```
Authorization: Bearer smgr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Base URL is the manager's API root, e.g. `https://manage.example.com/api`.

```bash
curl -s https://manage.example.com/api/diag \
  -H "Authorization: Bearer $DIAG_TOKEN" | jq
```

All responses are JSON in the platform's standard envelope:
`{ "ok": true, "data": { ... } }`.

## 3. Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET  | `/api/diag` | Self-describing catalogue of these endpoints. |
| GET  | `/api/diag/overview` | Versions, DB connectivity, and 24h counts. |
| GET  | `/api/diag/apps` | Every registered app with pairing + last health. |
| GET  | `/api/diag/apps/{id}/probe` | **Live-probe** an app helper; RAW response per action. |
| GET  | `/api/diag/apps/{id}/health-checks` | Recent stored health-check history (decoded). |
| GET  | `/api/diag/logs` | Recent per-app log events. |
| GET  | `/api/diag/audit` | Recent audit-log entries (privileged/mutating actions). |
| GET  | `/api/diag/schema` | List tables, or columns for one table. |
| POST | `/api/diag/query` | Guarded read-only `SELECT`. |

### GET `/api/diag/overview`

App/runtime versions, whether the database is reachable, and rolling 24h
counters (apps total/paired/unhealthy, log events, health checks, audit rows,
audit failures). Start here to confirm the platform itself is healthy.

### GET `/api/diag/apps`

Lists apps with `id`, `slug`, `name`, `domain`, `status`, `helper_url`,
`paired` (has both a helper URL and token), `last_health`, `last_checked`. Use
the `id` for the probe/health-check endpoints.

### GET `/api/diag/apps/{id}/probe` — the main debugging tool

Calls the app's helper **live** and returns the RAW result of each action so
you can see exactly what the app returned. Optional `?actions=` is a
comma-separated subset of `health,version,stats,components,commands,logs,ping`
(default: `health,version,stats,components,commands`).

```bash
curl -s "https://manage.example.com/api/diag/apps/12/probe?actions=components,commands" \
  -H "Authorization: Bearer $DIAG_TOKEN" | jq
```

Each probe entry contains:

| Field | Meaning |
|-------|---------|
| `http_status` | HTTP status returned by the helper (0 = never connected). |
| `ms` | Round-trip time in milliseconds. |
| `ok` | `true` only if HTTP 2xx **and** body parsed as JSON with `ok != false`. |
| `parsed` | The decoded `data` payload (or full JSON) when it parsed. |
| `raw` | First 4 KB of the raw response body (present even when JSON fails). |
| `transport_error` | cURL/network error (DNS, TLS, timeout) if the call never completed. |
| `app_error` | The helper's own `error` string, if it reported one. |
| `note` | Set to `response body was not valid JSON` when the body wasn't JSON. |

**How to read it when services aren't working:**

- `transport_error` present → networking/TLS/DNS or the helper URL is wrong or
  the app is down. Check `helper_url` on the app.
- `http_status` 401/403 → the `helper_token` (pairing secret) is wrong or the
  helper is rejecting the signature. Re-pair the app.
- `http_status` 404 → helper path wrong / helper not deployed.
- `http_status` 500 or `note: not valid JSON` → the helper crashed; the `raw`
  snippet usually contains the PHP error or stack trace.
- `ok: true` but `commands`/`components` empty → the app simply hasn't
  implemented those actions yet (expected for a minimal helper).
- `app_error` set → the app rejected the action; read the message.

### GET `/api/diag/apps/{id}/health-checks?limit=20`

The last stored health checks for an app, with the JSON `detail` decoded so you
can see which component statuses were recorded over time.

### GET `/api/diag/logs`

Recent rows from `app_log_events`. Filters (all optional):

| Param | Meaning |
|-------|---------|
| `app_id` | Restrict to one app. |
| `level` | e.g. `error`, `warning`, `info`. |
| `status_min` | Only events with `status_code >= N` (e.g. `500`). |
| `q` | Substring match on path or message. |
| `hours` | Look-back window (default 24, max 720). |
| `limit` | Max rows (default 100, max 1000). |

```bash
curl -s "https://manage.example.com/api/diag/logs?app_id=12&status_min=500&hours=6" \
  -H "Authorization: Bearer $DIAG_TOKEN" | jq
```

### GET `/api/diag/audit`

Recent `audit_log` entries. Filters: `action`, `target`, `actor` (substring),
`result` (`success`/`failure`/`denied`), `hours`, `limit`. Look here to see the
platform's own helper/API calls to an app (`action` like `app.helper`,
`app.command`) and whether they succeeded.

### GET `/api/diag/schema`

Without params: lists tables with approximate row counts. With `?table=<name>`:
returns the column definitions for that table so you can craft a query.

```bash
curl -s "https://manage.example.com/api/diag/schema?table=app_health_checks" \
  -H "Authorization: Bearer $DIAG_TOKEN" | jq
```

### POST `/api/diag/query` — guarded read-only SQL

Runs a **single** `SELECT` (or `WITH`) statement. Body:

```json
{ "sql": "SELECT id, slug, last_health FROM managed_apps ORDER BY id", "limit": 100 }
```

Guardrails (enforced server-side):

- Must begin with `SELECT` or `WITH`.
- No `;` — single statement only (stacked queries are rejected).
- File-access and timing gadgets are blocked (`INTO OUTFILE/DUMPFILE`,
  `LOAD_FILE`, `SLEEP`, `BENCHMARK`, `GET_LOCK`).
- A `LIMIT` is appended when absent; every result set is capped at 1000 rows.

Response: `{ ok, row_count, columns, rows }`.

## 4. Suggested workflow for "app X's services aren't working"

1. `GET /api/diag/overview` — confirm the platform + DB are healthy.
2. `GET /api/diag/apps` — find the app's `id` and check `paired` / `last_health`.
3. `GET /api/diag/apps/{id}/probe` — read `health`, `components`, `commands`.
   The `transport_error` / `http_status` / `app_error` / `raw` fields point
   straight at the failure (network, auth, crash, or unimplemented action).
4. `GET /api/diag/apps/{id}/health-checks` — see whether it was ever healthy and
   when it changed.
5. `GET /api/diag/logs?app_id={id}&status_min=500` — recent errors from the app.
6. `GET /api/diag/audit?target={slug}` — did the manager's own calls to the app
   fail (auth/signature)?
7. If needed, `GET /api/diag/schema` then `POST /api/diag/query` for a precise
   read against any table.

## 5. Security notes

- Read-only by design; no endpoint mutates state.
- Gated by the `diag` scope. Issue a short-lived token and revoke it when done.
- The raw SQL runner is deliberately powerful but SELECT-only, single-statement,
  and row-capped. Treat the `diag` token like an admin credential.
- Tokens are stored only as SHA-256 hashes and honour `expires_at` / `revoked`.

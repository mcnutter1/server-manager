# Server Manager

The operations, visibility, and management platform — the central nervous
system for a shared Ubuntu/AWS server. Fully API‑driven, with a modern
responsive UI built on **PHP · MySQL · jQuery · JSON**, backed by a protected
**Python runner** for privileged actions.

---

## Features

| Area | What you get |
|------|--------------|
| **System health** | Live CPU / memory / disk / load / network / uptime with a rolling health score and 6h trend charts. |
| **Services** | List, inspect, start / stop / restart / reload `systemd` units. Critical services are pinned and monitored. |
| **Firewall** | iptables rule visibility with per‑rule packet/byte **hit counters**, chain policies, and listening‑port attack surface. |
| **NIDS** | Log‑driven intrusion detection (SSH brute force, SQLi, XSS, traversal, RCE, scanners) feeding an event store + **auto‑block** engine. |
| **Host blocking** | Block/unblock any IP via API, with **timers** (auto‑expiry), permanent blocks, whitelist protection, and live hit counts. |
| **Applications** | Registry of individually‑deployed apps under `/var/www`, **discovery** of unmanaged apps, and a common **helper framework** to interface with each app. |
| **Logs & usage** | Safe log tailing, HTTP status/usage/performance summaries, top paths & IPs, error‑rate tracking. |
| **CLI runner** | Emulate whitelisted CLI commands through the API via a hardened Python runner — never arbitrary shell. |
| **Alerts** | Threshold + service + security alerts dispatched through the McNutt Cloud **Notifications** service (email/SMS). |
| **Audit** | Every privileged/mutating action is recorded with actor, target, params, result and IP. |
| **Auth** | SSO + API keys through **McNutt Cloud Auth**, plus local machine tokens for automation. |

---

## Architecture

```
Browser (SPA, jQuery)  ──►  public/index.php  ──►  McNutt Cloud Auth (SSO)
       │  XHR (JSON)
       ▼
public/api/index.php  (REST router)
       │
       ▼
app/*.php  (SystemMonitor, ServiceManager, FirewallManager,
            NidsManager, AppManager, LogAnalyzer, Notifier, Runner)
       │                                    │
       ▼ (read /proc, logs)                 ▼ (privileged)
   MySQL  ◄── bin/ workers (cron/systemd)   sudo → runner/runner.py
                                               (whitelisted actions only)
```

**Privilege separation:** the web tier holds **no** direct privileges. Every
privileged operation (systemctl, iptables) is a whitelisted *action key*
dispatched to `runner/runner.py` through `sudo`, authenticated by a shared
token, validated argument‑by‑argument, and executed with `argv` arrays (never
`shell=True`).

---

## Directory layout

```
config/            config.sample.php        app + db + auth + runner + nids config
client_helper/     auth.php, config.php      McNutt Cloud Auth SSO/API helper
sql/               schema.sql                MySQL schema
app/               *.php                     core library (namespaced App\)
public/            index.php, api/, assets/  web root (DocumentRoot here)
runner/            runner.py, .runner_token  privileged action runner
bin/               *.php                      cron/systemd workers + token CLI
deploy/            sudoers, vhost, systemd    deployment artifacts + install.sh
docs/              APP_HELPER.md, sample      managed‑app helper framework
```

---

## Install (Ubuntu, Apache, MySQL)

Download the repo and run the one‑shot installer as root — it does everything:

```bash
git clone <repo> server-manager && cd server-manager
sudo bash deploy/install.sh
```

The installer will:

1. Install packages (Apache, MySQL/MariaDB, PHP + extensions, certbot, python3, git, rsync).
2. Copy the app into `APP_DIR` (default `/var/www/server-manager`).
3. **Create the MySQL database + user** and load the schema.
4. **Generate `config/config.php` + `client_helper/config.php`** with real values (DB creds, runner token, `app_secret`, notifications, domain, timezone).
5. Generate the privileged **runner token** (`root:root 600`) and matching config.
6. Install the **sudoers** entry, the **Apache vhost**, and (optionally) a **Let's Encrypt** certificate with HTTPS redirect.
7. Install + enable the **systemd worker timers**.
8. Wire up **GitHub credentials** (ASKPASS + PAT) so `deploy/update.sh` can self‑update.
9. Create a first **local admin API token** and print it once.

It prompts for the domain, DB name/user, `app_secret`, notifications token,
Let's Encrypt, and (optional) GitHub repo/PAT. For a **non‑interactive**
install, provide everything via env vars:

```bash
sudo -E NONINTERACTIVE=1 \
  SERVER_NAME=manage.mcnutt.cloud APP_SECRET=… NOTIFY_TOKEN=… \
  ENABLE_SSL=y SERVER_ADMIN_EMAIL=ops@mcnutt.cloud \
  REPO_URL=https://github.com/you/server-manager.git GIT_BRANCH=main GITHUB_PAT=… \
  bash deploy/install.sh
```

> DocumentRoot is set to `public/`. The vhost denies web access to `app/`,
> `config/`, `runner/`, `sql/`, `bin/`, `client_helper/`, `deploy/`, `docs/`,
> `storage/`.

Finally, **register `app_id=server-manager`** with McNutt Cloud Auth using the
`app_secret` the installer used, so SSO can redirect back.

## Updating

Pull the latest code from GitHub (uses the stored PAT via ASKPASS) and mirror
the working tree to `origin/BRANCH`, preserving local secrets:

```bash
sudo bash deploy/update.sh
```

`update.sh` re‑executes itself from a temp copy first, so it can **self‑update**
safely (a `git reset --hard` may replace the script mid‑run). It preserves
`config/config.php`, `client_helper/config.php`, `runner/.runner_token` and
`deploy/.deploy.env`, re‑applies the (idempotent) schema, fixes permissions,
and reloads Apache + the worker timers. Repo URL/branch are read from
`deploy/.deploy.env` (written by the installer).

---

## Authentication

* **Users** authenticate via McNutt Cloud SSO. Only roles in
  `auth.allowed_roles` may load the UI; mutating actions require
  `auth.admin_roles`.
* **Machines** use either a McNutt Cloud API key or a **local token**:

  ```bash
  php bin/token.php create "backup-job" read,services,nids 90
  # → smgr_xxxxxxxx   (store once)
  curl -H "Authorization: Bearer smgr_xxxxxxxx" https://manage.mcnutt.cloud/api/system/overview
  ```

Local tokens are scoped: `read, services, firewall, nids, apps, runner, admin`.

---

## REST API (selected)

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| GET  | `/api/system/overview` | read | Dashboard roll‑up |
| GET  | `/api/system/metrics` | read | Live snapshot |
| GET  | `/api/system/metrics/history?hours=6` | read | Trend series |
| GET  | `/api/services` | read | All services |
| POST | `/api/services/{name}/{start\|stop\|restart\|reload}` | services | Control a service |
| GET  | `/api/firewall/rules?table=filter` | read | Parsed iptables + hits |
| GET  | `/api/firewall/ports` | read | Listening ports |
| GET  | `/api/nids/blocks` | read | Active blocks + timers + hits |
| POST | `/api/nids/block` | nids | `{ip,reason,minutes,permanent,source}` |
| POST | `/api/nids/unblock` | nids | `{ip}` |
| GET  | `/api/nids/events` / `/offenders` | read | Detected activity |
| GET  | `/api/apps` | read | Managed apps |
| GET  | `/api/apps/discover` | apps | Find unmanaged apps in `/var/www` |
| POST | `/api/apps` | apps | Register/adopt an app |
| POST | `/api/apps/{id}/helper` | apps | Call the app's helper action |
| GET  | `/api/logs/tail?source=auth&lines=200` | read | Tail a whitelisted log |
| GET  | `/api/logs/access-summary` | read | Usage/performance summary |
| POST | `/api/logs/scan` | nids | Run a threat scan now |
| GET  | `/api/runner/actions` | read | Whitelisted runner actions |
| POST | `/api/runner/exec` | runner | `{action,args}` |
| GET  | `/api/audit` | read | Audit trail |

All responses are JSON: `{ "ok": true, "data": … }` or
`{ "ok": false, "error": "…" }`.

---

## Host blocking with timers

```bash
# Block for 30 minutes
curl -X POST https://manage.mcnutt.cloud/api/nids/block \
  -H "Authorization: Bearer smgr_…" -H "Content-Type: application/json" \
  -d '{"ip":"203.0.113.5","reason":"brute force","minutes":30}'
```

`bin/nids-worker.php` (every minute) expires blocks whose timer has elapsed and
runs the threat scan, auto‑blocking hosts that cross
`nids.auto_block_threshold` events within `nids.auto_block_window_min`.
Whitelisted IPs (`nids.whitelist`) are never blocked. Blocks live in a
dedicated `SRVMGR_BLOCK` iptables chain so they never collide with your other
rules.

---

## Managing your apps

Each app keeps its own code + database. Server Manager interfaces through a
uniform **helper endpoint** the app ships (default `srvmgr/helper.php`). See
[docs/APP_HELPER.md](docs/APP_HELPER.md) and the drop‑in
[docs/app-helper-sample.php](docs/app-helper-sample.php). Register apps in the
UI (Applications → Register) or via `POST /api/apps`; use **Discover** to find
unmanaged apps under `/var/www` and adopt them.

---

## Security model

* Web tier → runner via `sudo -n` with a shared token; **whitelisted actions
  only**, all arguments validated (IP/service‑name regexes), `argv` execution.
* Log paths and runner actions are whitelisted — no path traversal or command
  injection surface exposed to the API.
* Secrets are redacted from the audit log; local tokens are stored as SHA‑256.
* Every mutation is authenticated, authorized by role/scope, and audited.

---

## Background workers

| Worker | Cadence | Responsibility |
|--------|---------|----------------|
| `bin/collect-metrics.php` | 1 min | Store metrics, monitor critical services, raise resource/service alerts, 30‑day retention. |
| `bin/nids-worker.php` | 1 min | Expire timed blocks, scan logs for threats, auto‑block. |

Run via the provided systemd timers (preferred) or cron:

```
* * * * * www-data /usr/bin/php /var/www/server-manager/bin/collect-metrics.php >/dev/null 2>&1
* * * * * www-data /usr/bin/php /var/www/server-manager/bin/nids-worker.php     >/dev/null 2>&1
```

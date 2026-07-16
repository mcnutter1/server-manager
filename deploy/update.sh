#!/usr/bin/env bash
# =====================================================================
# Server Manager — updater.
#
# Pulls the latest code from GitHub using stored credentials and mirrors
# the working tree to origin/BRANCH, preserving local secrets. It also
# UPDATES ITSELF: the script re-executes from a temp copy first so a
# `git reset --hard` can safely replace deploy/update.sh mid-run.
#
# Usage:  sudo bash deploy/update.sh
# =====================================================================
set -euo pipefail

# ---------------------------------------------------------------------
# Self-update guard: run from a temp copy so the on-disk script can be
# overwritten by the git sync without corrupting this running process.
# ---------------------------------------------------------------------
if [ -z "${SM_FROM_TMP:-}" ]; then
    _tmp="$(mktemp /tmp/srvmgr-update.XXXXXX.sh)"
    cp "$0" "$_tmp"; chmod +x "$_tmp"
    export SM_FROM_TMP=1 SM_ORIG_ARGV0="$0"
    exec "$_tmp" "$@"
fi
trap 'rm -f "$0"' EXIT   # remove the temp copy when done

# ---------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------
APP_DIR="${APP_DIR:-/var/www/server-manager}"
RUN_AS="${RUN_AS:-www-data}"
ASKPASS="${ASKPASS:-/usr/local/bin/git-askpass-github.sh}"
TOKEN_FILE="${TOKEN_FILE:-/etc/secrets/github_pat}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/server-manager}"

# Load REPO_URL / GIT_BRANCH persisted by install.sh (deploy/.deploy.env).
if [ -f "$APP_DIR/deploy/.deploy.env" ]; then
    # shellcheck disable=SC1091
    source "$APP_DIR/deploy/.deploy.env"
fi
REPO_URL="${REPO_URL:-}"
BRANCH="${GIT_BRANCH:-main}"

# Server-side copies that MUST survive a mirror deploy.
PRESERVE_LOCAL=(
    "config/config.php"
    "client_helper/config.php"
    "runner/.runner_token"
    "deploy/.deploy.env"
)

export GIT_ASKPASS="$ASKPASS"
export GIT_TERMINAL_PROMPT=0

c_info() { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok()   { printf '\033[1;32m[✓]\033[0m %s\n' "$*"; }
c_warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()    { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

require_root() { [ "$(id -u)" -eq 0 ] || die "Run with sudo/root."; }
as_user() { sudo -u "$RUN_AS" --preserve-env=GIT_ASKPASS,GIT_TERMINAL_PROMPT bash -lc "$*"; }

check_prereqs() {
    [ -n "$REPO_URL" ] || die "REPO_URL not set. Run install.sh with a repo, or set it in $APP_DIR/deploy/.deploy.env"
    [ -f "$ASKPASS" ]    || die "ASKPASS helper missing at $ASKPASS (re-run install.sh)."
    [ -f "$TOKEN_FILE" ] || die "GitHub token missing at $TOKEN_FILE (re-run install.sh)."
    chgrp "$RUN_AS" "$ASKPASS" 2>/dev/null || true; chmod 750 "$ASKPASS"
    chgrp -R "$RUN_AS" "$(dirname "$TOKEN_FILE")" 2>/dev/null || true
    chmod 710 "$(dirname "$TOKEN_FILE")"; chmod 640 "$TOKEN_FILE"
    # Trust the working dir system-wide so root and the web user can run git
    # here without "dubious ownership" errors.
    git config --system --add safe.directory "$APP_DIR" 2>/dev/null || true
}

ensure_repo_initialized() {
    if [ ! -d "$APP_DIR/.git" ]; then
        c_info "Initialising git repo in $APP_DIR (no clone)…"
        as_user "cd '$APP_DIR' && git init -q"
        as_user "cd '$APP_DIR' && (git remote add origin '$REPO_URL' 2>/dev/null || git remote set-url origin '$REPO_URL')"
        as_user "cd '$APP_DIR' && git fetch origin '$BRANCH' --prune"
        as_user "cd '$APP_DIR' && git checkout -B '$BRANCH' --track origin/'$BRANCH'" || true
        as_user "cd '$APP_DIR' && git config core.fileMode false"
    else
        as_user "cd '$APP_DIR' && git remote set-url origin '$REPO_URL'"
        as_user "cd '$APP_DIR' && git config core.fileMode false"
    fi
}

auth_smoke_test() {
    c_info "Testing GitHub auth…"
    as_user "git ls-remote '$REPO_URL'" >/dev/null || die "GitHub auth failed (check PAT)."
    c_ok "Auth OK."
}

recover_git_state() {
    as_user "cd '$APP_DIR' && { \
        git rebase --abort 2>/dev/null || true; \
        git merge --abort 2>/dev/null || true; \
        git cherry-pick --abort 2>/dev/null || true; \
        git am --abort 2>/dev/null || true; \
        git reset -q 2>/dev/null || true; }"
}

backup_local() {
    mkdir -p "$BACKUP_DIR"; chown "$RUN_AS:$RUN_AS" "$BACKUP_DIR"
    local ts; ts="$(date +%Y%m%d-%H%M%S)"
    # Drift patch for review.
    as_user "cd '$APP_DIR' && git diff 'origin/$BRANCH' -- . > '$BACKUP_DIR/local-drift.$ts.patch' 2>/dev/null || true"
    # Stash preserved files.
    local f
    for f in "${PRESERVE_LOCAL[@]}"; do
        if [ -f "$APP_DIR/$f" ]; then
            mkdir -p "$BACKUP_DIR/preserve/$(dirname "$f")"
            cp -a "$APP_DIR/$f" "$BACKUP_DIR/preserve/$f"
        fi
    done
}

restore_local() {
    local f
    for f in "${PRESERVE_LOCAL[@]}"; do
        if [ -f "$BACKUP_DIR/preserve/$f" ]; then
            mkdir -p "$APP_DIR/$(dirname "$f")"
            cp -a "$BACKUP_DIR/preserve/$f" "$APP_DIR/$f"
            c_info "Preserved local $f"
        fi
    done
    # Lock the secrets back down.
    chown root:root "$APP_DIR/runner/.runner_token" 2>/dev/null || true
    chmod 600 "$APP_DIR/runner/.runner_token" 2>/dev/null || true
    chmod 640 "$APP_DIR/config/config.php" "$APP_DIR/client_helper/config.php" 2>/dev/null || true
}

sync_to_origin() {
    c_info "Fetching origin/$BRANCH…"
    as_user "cd '$APP_DIR' && git fetch origin '$BRANCH' --prune"
    recover_git_state
    backup_local
    c_info "Local changes vs origin (if any):"
    as_user "cd '$APP_DIR' && git status --porcelain || true"
    c_info "Mirroring working tree to origin/$BRANCH…"
    as_user "cd '$APP_DIR' && git checkout -f -B '$BRANCH' 'origin/$BRANCH'"
    as_user "cd '$APP_DIR' && git reset --hard 'origin/$BRANCH'"
    as_user "cd '$APP_DIR' && git branch --set-upstream-to=origin/'$BRANCH' '$BRANCH' 2>/dev/null || true"
    restore_local
    c_info "Now at:"
    as_user "cd '$APP_DIR' && git log -1 --oneline"
}

apply_migrations() {
    # Preferred path: versioned, tracked migrations via bin/migrate.php. Each
    # migration is recorded in schema_migrations and applied at most once, so
    # this is cheap on repeat updates. Runs as the web user (reads config.php).
    if [ -f "$APP_DIR/bin/migrate.php" ] && [ -d "$APP_DIR/sql/migrations" ]; then
        c_info "Applying database migrations…"
        if as_user "cd '$APP_DIR' && php bin/migrate.php"; then
            c_ok "Migrations applied."
            return
        fi
        c_warn "migrate.php failed — falling back to full schema load."
    fi

    # Fallback: idempotent full-schema load (all tables use IF NOT EXISTS).
    if [ -f "$APP_DIR/sql/schema.sql" ]; then
        c_info "Applying schema (idempotent)…"
        # Authenticate with the SAME app DB credentials the platform uses
        # (from config.php) rather than relying on root's socket auth, which
        # may not be configured. Credentials go through a 0600 defaults file
        # so the password never appears in the process list.
        local defaults; defaults="$(mktemp /tmp/srvmgr-my.XXXXXX.cnf)"
        chmod 600 "$defaults"
        local dbn
        dbn="$(php -r '
            $c = @require $argv[1];
            if (!is_array($c) || empty($c["db"])) { fwrite(STDERR, "no db config\n"); exit(1); }
            $d = $c["db"];
            $f = fopen($argv[2], "w");
            fwrite($f, "[client]\n");
            fwrite($f, "host="     . ($d["host"] ?? "127.0.0.1") . "\n");
            fwrite($f, "port="     . ($d["port"] ?? 3306) . "\n");
            fwrite($f, "user="     . ($d["user"] ?? "") . "\n");
            fwrite($f, "password=" . ($d["pass"] ?? "") . "\n");
            fclose($f);
            echo $d["name"] ?? "server_manager";
        ' "$APP_DIR/config/config.php" "$defaults" 2>/dev/null || true)"
        [ -n "$dbn" ] || dbn="server_manager"

        # Strip the schema's own CREATE DATABASE (may span lines) + USE so a
        # custom DB name works, then load into the target database.
        if awk '
                skip { if ($0 ~ /;/) skip=0; next }
                /^[[:space:]]*CREATE DATABASE/ { if ($0 !~ /;/) skip=1; next }
                /^[[:space:]]*USE[[:space:]]/  { next }
                { print }
            ' "$APP_DIR/sql/schema.sql" | mysql --defaults-extra-file="$defaults" "$dbn"; then
            c_ok "Schema applied."
        else
            c_warn "Schema apply failed (see mysql error above)."
        fi
        rm -f "$defaults"
    fi
}

fix_perms() {
    chown -R "$RUN_AS:$RUN_AS" "$APP_DIR"
    find "$APP_DIR" -type d -exec chmod 755 {} \;
    find "$APP_DIR" -type f -exec chmod 644 {} \;
    chmod 755 "$APP_DIR/runner/runner.py" 2>/dev/null || true
    chmod +x "$APP_DIR"/deploy/*.sh 2>/dev/null || true
    mkdir -p "$APP_DIR/storage/cache"; chmod -R 2775 "$APP_DIR/storage"
    chown root:root "$APP_DIR/runner/.runner_token" 2>/dev/null || true
    chmod 600 "$APP_DIR/runner/.runner_token" 2>/dev/null || true
    chmod 640 "$APP_DIR/config/config.php" "$APP_DIR/client_helper/config.php" 2>/dev/null || true
}

reload_services() {
    ensure_traffic_timer
    ensure_threatintel_timer
    systemctl daemon-reload 2>/dev/null || true
    systemctl restart srvmgr-metrics.timer srvmgr-nids.timer srvmgr-traffic.timer srvmgr-threatintel.timer 2>/dev/null || true
    apache2ctl configtest >/dev/null 2>&1 && systemctl reload apache2 2>/dev/null || c_warn "apache reload skipped."
}

# Install the traffic worker unit + timer on existing deployments that predate
# the traffic map feature. Idempotent: only writes when the unit is missing.
ensure_traffic_timer() {
    # The traffic worker parses apache access logs (root:adm 640). Make sure the
    # worker user can read them, else the map shows no "allow" traffic. Safe to
    # run every update; takes effect on the next worker run.
    usermod -aG adm "$RUN_AS" 2>/dev/null || true

    [ -f /etc/systemd/system/srvmgr-traffic.timer ] && return 0
    local php_bin; php_bin="$(command -v php)"
    [ -n "$php_bin" ] || return 0
    c_info "Installing traffic worker timer…"

    cat > /etc/systemd/system/srvmgr-traffic.service <<EOF
[Unit]
Description=Server Manager traffic worker (map ingest + geolocate)
After=mysql.service mariadb.service
[Service]
Type=oneshot
User=${RUN_AS}
ExecStart=${php_bin} ${APP_DIR}/bin/traffic-worker.php
EOF

    cat > /etc/systemd/system/srvmgr-traffic.timer <<'EOF'
[Unit]
Description=Run Server Manager traffic worker every 2 minutes
[Timer]
OnBootSec=120
OnUnitActiveSec=120
AccuracySec=15s
Unit=srvmgr-traffic.service
[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload 2>/dev/null || true
    systemctl enable --now srvmgr-traffic.timer >/dev/null 2>&1 || true
}

# Install the threat-intel worker unit + timer on existing deployments that
# predate the malicious-IP feature. Idempotent: only writes when missing.
ensure_threatintel_timer() {
    [ -f /etc/systemd/system/srvmgr-threatintel.timer ] && return 0
    local php_bin; php_bin="$(command -v php)"
    [ -n "$php_bin" ] || return 0
    c_info "Installing threat-intel worker timer…"

    cat > /etc/systemd/system/srvmgr-threatintel.service <<EOF
[Unit]
Description=Server Manager threat-intel worker (malicious IP feeds)
After=mysql.service mariadb.service network-online.target
Wants=network-online.target
[Service]
Type=oneshot
User=${RUN_AS}
ExecStart=${php_bin} ${APP_DIR}/bin/threat-intel.php
EOF

    cat > /etc/systemd/system/srvmgr-threatintel.timer <<'EOF'
[Unit]
Description=Run Server Manager threat-intel worker every 15 minutes
[Timer]
OnBootSec=180
OnUnitActiveSec=900
AccuracySec=30s
Unit=srvmgr-threatintel.service
[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload 2>/dev/null || true
    systemctl enable --now srvmgr-threatintel.timer >/dev/null 2>&1 || true
}

main() {
    require_root
    c_info "Server Manager updater — $APP_DIR @ $BRANCH"
    check_prereqs
    ensure_repo_initialized
    auth_smoke_test
    sync_to_origin
    apply_migrations
    fix_perms
    reload_services
    c_ok "Update complete."
}

main "$@"

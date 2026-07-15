#!/usr/bin/env bash
# =====================================================================
# Server Manager — one-shot installer for Ubuntu (AWS).
#
# Download the repo anywhere (git clone or unzip), then run:
#     sudo bash deploy/install.sh
#
# It will:
#   * install packages (Apache, MySQL/MariaDB, PHP, certbot, python3, …)
#   * copy the app into APP_DIR (default /var/www/server-manager)
#   * create the MySQL database + user and load the schema
#   * generate config/config.php + client_helper/config.php with real values
#   * generate the privileged runner token
#   * install sudoers, the Apache vhost, and (optionally) a Let's Encrypt cert
#   * install + enable the systemd worker timers
#   * wire up GitHub credentials so deploy/update.sh can self-update
#   * create a first local admin API token
#
# Every setting can be provided via environment variables (see DEFAULTS
# below) for a non-interactive install:  NONINTERACTIVE=1 sudo -E bash …
# =====================================================================
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------
c_info()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok()    { printf '\033[1;32m[✓]\033[0m %s\n' "$*"; }
c_warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_err()   { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; }
die()     { c_err "$*"; exit 1; }

# On any error, tell the operator the install can simply be re-run — every
# step is idempotent and will resume where it left off.
on_error() {
    c_err "Install failed (line ${1:-?}, exit ${2:-?})."
    c_err "Fix the cause, then re-run:  sudo bash \"${BASH_SOURCE[0]}\""
    c_err "It is idempotent and will RESUME the partial install."
}
trap 'on_error "$LINENO" "$?"' ERR

require_root() { [ "$(id -u)" -eq 0 ] || die "Run with sudo/root."; }

rand_str() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-40}"; echo; }

# prompt VAR "Question" "default" [secret]
prompt() {
    local __var="$1" __q="$2" __def="${3:-}" __secret="${4:-}" __ans
    if [ -n "${!__var:-}" ]; then return; fi          # already set via env
    if [ "${NONINTERACTIVE:-0}" = "1" ]; then printf -v "$__var" '%s' "$__def"; return; fi
    if [ "$__secret" = "secret" ]; then
        read -rsp "$__q: " __ans; echo
    else
        read -rp "$__q [${__def}]: " __ans
    fi
    printf -v "$__var" '%s' "${__ans:-$__def}"
}

# Literal, first-occurrence file replacement (safe for any characters).
replace_once() {
    python3 - "$1" "$2" "$3" <<'PY'
import sys
path, old, new = sys.argv[1:4]
s = open(path).read()
if old not in s:
    sys.stderr.write(f"[warn] pattern not found in {path}: {old[:40]}...\n")
open(path, 'w').write(s.replace(old, new, 1))
PY
}

# Literal, all-occurrences file replacement.
replace_all() {
    python3 - "$1" "$2" "$3" <<'PY'
import sys
path, old, new = sys.argv[1:4]
s = open(path).read()
open(path, 'w').write(s.replace(old, new))
PY
}

# Detect a previous or crashed/incomplete install and, if found, reuse the
# existing identifiers so this run REPAIRS/RESUMES rather than clobbering it.
detect_prior_install() {
    local dir="${APP_DIR}" found=() f v dbn
    [ -f "$dir/config/config.php" ]                              && found+=("config/config.php")
    [ -f "$dir/client_helper/config.php" ]                       && found+=("client_helper/config.php")
    [ -d "$dir/.git" ]                                           && found+=("git repo")
    [ -f "$dir/runner/.runner_token" ]                           && found+=("runner token")
    [ -f /etc/sudoers.d/server-manager ]                         && found+=("sudoers")
    [ -f /etc/apache2/sites-available/server-manager.conf ]      && found+=("apache vhost")
    [ -f /etc/systemd/system/srvmgr-metrics.timer ]              && found+=("systemd timers")

    # Pull the real DB name from an existing config for the DB existence check.
    dbn="${DB_NAME}"
    if [ -f "$dir/config/config.php" ] && command -v php >/dev/null 2>&1; then
        v="$(php -r '$c=@require $argv[1]; if(is_array($c)) printf("%s\n%s\n",$c["db"]["name"]??"",$c["db"]["user"]??"");' "$dir/config/config.php" 2>/dev/null)"
        [ -n "$(sed -n 1p <<<"$v")" ] && dbn="$(sed -n 1p <<<"$v")"
    fi
    if command -v mysql >/dev/null 2>&1 && mysql -N -e "SHOW DATABASES LIKE '${dbn}'" 2>/dev/null | grep -q .; then
        found+=("database '${dbn}'")
    fi

    [ ${#found[@]} -eq 0 ] && return 0

    echo
    c_warn "Existing / partial install detected:"
    for f in "${found[@]}"; do echo "        - $f"; done
    echo
    c_info "The installer is idempotent — it will REPAIR/RESUME this install,"
    c_info "reusing the current DB name/user, password and runner token."

    # Reuse existing identifiers so prompts are skipped and nothing is renamed.
    if [ -n "${v:-}" ]; then
        [ -z "${DB_NAME:-}" -o "${DB_NAME}" = "server_manager" ] && DB_NAME="$(sed -n 1p <<<"$v")"
        [ -z "${DB_USER:-}" -o "${DB_USER}" = "server_manager" ] && DB_USER="$(sed -n 2p <<<"$v")"
        DB_NAME="${DB_NAME:-$(sed -n 1p <<<"$v")}"
        DB_USER="${DB_USER:-$(sed -n 2p <<<"$v")}"
    fi

    if [ "${NONINTERACTIVE:-0}" != "1" ] && [ "${FORCE_RESUME:-0}" != "1" ]; then
        local __c; read -rp "Continue and repair this install? [Y/n]: " __c
        case "${__c,,}" in n*) die "Aborted by user.";; esac
    fi
    echo
}

# ---------------------------------------------------------------------
# Defaults (override via env)
# ---------------------------------------------------------------------
require_root

APP_DIR="${APP_DIR:-/var/www/server-manager}"
WEB_USER="${WEB_USER:-www-data}"
TIMEZONE="${TIMEZONE:-America/New_York}"

DB_HOST="${DB_HOST:-127.0.0.1}"
DB_NAME="${DB_NAME:-server_manager}"
DB_USER="${DB_USER:-server_manager}"
DB_PASS="${DB_PASS:-}"                       # generated if empty

APP_ID="${APP_ID:-server-manager}"
APP_SECRET="${APP_SECRET:-}"                 # shared secret w/ McNutt Cloud Auth
LOGIN_BASE="${LOGIN_BASE:-https://login.mcnutt.cloud}"
COOKIE_DOMAIN="${COOKIE_DOMAIN:-.mcnutt.cloud}"

NOTIFY_ENDPOINT="${NOTIFY_ENDPOINT:-https://notify.mcnutt.cloud/api/send.php}"
NOTIFY_TOKEN="${NOTIFY_TOKEN:-}"
ALERT_EMAIL="${ALERT_EMAIL:-ops@mcnutt.cloud}"

REPO_URL="${REPO_URL:-}"                     # for update.sh self-updates
GIT_BRANCH="${GIT_BRANCH:-main}"
GITHUB_PAT="${GITHUB_PAT:-}"

echo
c_info "Server Manager installer — source: $SRC_DIR"
echo

prompt SERVER_NAME    "Public domain (ServerName)"          "manage.mcnutt.cloud"
prompt APP_DIR        "Install directory"                    "$APP_DIR"

# If a prior/partial install exists in APP_DIR, reuse its identifiers and
# confirm before repairing/resuming.
detect_prior_install

prompt SERVER_ADMIN_EMAIL "Admin email (Let's Encrypt + alerts)" "$ALERT_EMAIL"
prompt DB_NAME        "MySQL database name"                  "$DB_NAME"
prompt DB_USER        "MySQL username"                       "$DB_USER"
prompt APP_SECRET     "McNutt Cloud Auth app_secret"         "$(rand_str 48)"
prompt NOTIFY_TOKEN   "Notifications API token"              "changeme"
prompt REPO_URL       "GitHub repo URL (for updates, blank to skip)" ""
ALERT_EMAIL="${SERVER_ADMIN_EMAIL}"

if [ "${ENABLE_SSL:-}" = "" ]; then
    prompt ENABLE_SSL "Provision HTTPS with Let's Encrypt now? (y/n)" "y"
fi

[ -n "$DB_PASS" ] || DB_PASS="$(rand_str 40)"
RUNNER_TOKEN="${RUNNER_TOKEN:-$(rand_str 48)}"

# =====================================================================
# 1) Packages
# =====================================================================
install_packages() {
    c_info "Installing system packages…"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq \
        apache2 php libapache2-mod-php php-cli php-mysql php-curl php-mbstring php-xml \
        git rsync curl iptables python3 ca-certificates >/dev/null

    # MySQL server (fall back to MariaDB).
    if ! command -v mysql >/dev/null; then
        apt-get install -y -qq mysql-server >/dev/null 2>&1 \
            || apt-get install -y -qq mariadb-server >/dev/null
    fi
    systemctl enable --now mysql   >/dev/null 2>&1 || systemctl enable --now mariadb >/dev/null 2>&1 || true
    systemctl enable --now apache2 >/dev/null 2>&1 || true

    # certbot only when we intend to use it.
    [ "${ENABLE_SSL,,}" = "y" ] && ensure_certbot
    c_ok "Packages installed."
}

# Install a WORKING certbot. The apt package (certbot 2.9.0) ships a
# pyOpenSSL that is incompatible with the system 'cryptography' and dies with
# "module 'lib' has no attribute 'GEN_EMAIL'". Certbot's own recommendation is
# the snap build, which bundles its own deps. We prefer snap and fall back to
# apt only if snap is unavailable.
ensure_certbot() {
    # Already have a working snap certbot?
    if [ -x /snap/bin/certbot ] && /snap/bin/certbot --version >/dev/null 2>&1; then
        ln -sf /snap/bin/certbot /usr/bin/certbot
        return 0
    fi
    # Is the current certbot (if any) actually functional?
    if command -v certbot >/dev/null 2>&1 && certbot --version >/dev/null 2>&1; then
        return 0
    fi

    c_info "Installing certbot via snap (recommended)…"
    # Remove the broken apt certbot to avoid PATH/dep conflicts.
    apt-get remove -y -qq certbot python3-certbot-apache >/dev/null 2>&1 || true
    if ! command -v snap >/dev/null 2>&1; then
        apt-get install -y -qq snapd >/dev/null 2>&1 || true
        systemctl enable --now snapd.socket >/dev/null 2>&1 || true
        systemctl start snapd >/dev/null 2>&1 || true
    fi
    if command -v snap >/dev/null 2>&1; then
        snap install core >/dev/null 2>&1 || true
        snap refresh core >/dev/null 2>&1 || true
        if snap install --classic certbot >/dev/null 2>&1; then
            ln -sf /snap/bin/certbot /usr/bin/certbot
            c_ok "certbot (snap) installed."
            return 0
        fi
    fi
    # Last resort: apt (may still be broken, but better than nothing).
    c_warn "snap certbot unavailable; falling back to apt certbot."
    apt-get install -y -qq certbot python3-certbot-apache >/dev/null 2>&1 || c_warn "certbot install failed; skipping SSL."
}

# =====================================================================
# 2) Copy files into place
# =====================================================================
copy_files() {
    mkdir -p "$APP_DIR"
    if [ "$(realpath "$SRC_DIR")" = "$(realpath "$APP_DIR")" ]; then
        c_info "Source is already the install directory; skipping copy."
    else
        c_info "Copying application to $APP_DIR…"
        rsync -a --exclude 'config/config.php' --exclude 'client_helper/config.php' \
              "$SRC_DIR"/ "$APP_DIR"/
        c_ok "Files copied."
    fi
    mkdir -p "$APP_DIR/storage/cache"
}

# =====================================================================
# 3) Database
# =====================================================================
setup_database() {
    c_info "Creating MySQL database '$DB_NAME' and user '$DB_USER'…"
    mysql <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
CREATE USER IF NOT EXISTS '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
ALTER USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
ALTER USER '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL

    c_info "Loading schema…"
    # Strip the schema's own CREATE DATABASE (which may span multiple lines,
    # up to its terminating ';') and USE statements so a custom DB name works.
    # Schema is fully idempotent (CREATE TABLE IF NOT EXISTS), so re-runs after
    # a crash are safe.
    awk '
        skip { if ($0 ~ /;/) skip=0; next }
        /^[[:space:]]*CREATE DATABASE/ { if ($0 !~ /;/) skip=1; next }
        /^[[:space:]]*USE[[:space:]]/  { next }
        { print }
    ' "$APP_DIR/sql/schema.sql" | mysql "$DB_NAME"
    c_ok "Database ready."
}

# Re-read authoritative secrets from an existing config.php so a resumed
# (post-crash) install keeps the DB password / runner token in sync instead
# of regenerating fresh values that would no longer match the stored config.
load_existing_secrets() {
    local cfg="$APP_DIR/config/config.php"
    [ -f "$cfg" ] || return 0
    command -v php >/dev/null || return 0
    local vals
    vals="$(php -r '$c=@require $argv[1]; if(!is_array($c))exit; printf("%s\n%s\n%s\n%s\n", $c["db"]["name"]??"", $c["db"]["user"]??"", $c["db"]["pass"]??"", $c["runner"]["token"]??"");' "$cfg" 2>/dev/null)" || return 0
    [ -n "$vals" ] || return 0
    DB_NAME="$(sed -n 1p <<<"$vals")"
    DB_USER="$(sed -n 2p <<<"$vals")"
    DB_PASS="$(sed -n 3p <<<"$vals")"
    RUNNER_TOKEN="$(sed -n 4p <<<"$vals")"
    c_info "Reusing DB + runner credentials from existing config.php."
}

# =====================================================================
# 4) Config files
# =====================================================================
generate_config() {
    local cfg="$APP_DIR/config/config.php"
    if [ -f "$cfg" ]; then
        c_warn "config/config.php exists — leaving it untouched."
    else
        cp "$APP_DIR/config/config.sample.php" "$cfg"
        replace_once "$cfg" "'base_url'    => 'https://manage.mcnutt.cloud'," "'base_url'    => 'https://${SERVER_NAME}',"
        replace_once "$cfg" "'timezone'    => 'America/New_York'," "'timezone'    => '${TIMEZONE}',"
        replace_once "$cfg" "'host'     => '127.0.0.1'," "'host'     => '${DB_HOST}',"
        replace_once "$cfg" "'name'     => 'server_manager'," "'name'     => '${DB_NAME}',"
        replace_once "$cfg" "'user'     => 'server_manager'," "'user'     => '${DB_USER}',"
        replace_once "$cfg" "'pass'     => 'CHANGE_ME'," "'pass'     => '${DB_PASS}',"
        replace_once "$cfg" "'script'      => '/var/www/server-manager/runner/runner.py'," "'script'      => '${APP_DIR}/runner/runner.py',"
        replace_once "$cfg" "'token'       => 'CHANGE_ME_LONG_RANDOM_TOKEN'," "'token'       => '${RUNNER_TOKEN}',"
        replace_once "$cfg" "'endpoint'   => 'https://notify.mcnutt.cloud/api/send.php'," "'endpoint'   => '${NOTIFY_ENDPOINT}',"
        replace_once "$cfg" "'api_token'  => 'CHANGE_ME'," "'api_token'  => '${NOTIFY_TOKEN}',"
        replace_once "$cfg" "'alert_email' => 'ops@mcnutt.cloud'," "'alert_email' => '${ALERT_EMAIL}',"
        c_ok "Wrote config/config.php"
    fi

    local hcfg="$APP_DIR/client_helper/config.php"
    if [ -f "$hcfg" ]; then
        c_warn "client_helper/config.php exists — leaving it untouched."
    else
        cp "$APP_DIR/client_helper/config.sample.php" "$hcfg"
        replace_once "$hcfg" "'app_secret'        => 'replace_with_strong_shared_secret'," "'app_secret'        => '${APP_SECRET}',"
        replace_once "$hcfg" "'app_id'            => 'server-manager'," "'app_id'            => '${APP_ID}',"
        replace_once "$hcfg" "'cookie_domain'     => '.mcnutt.cloud'," "'cookie_domain'     => '${COOKIE_DOMAIN}',"
        replace_all  "$hcfg" "https://login.mcnutt.cloud" "${LOGIN_BASE}"
        c_ok "Wrote client_helper/config.php"
    fi
}

# =====================================================================
# 5) Runner token
# =====================================================================
setup_runner_token() {
    local tf="$APP_DIR/runner/.runner_token"
    # Always write so the on-disk token stays in sync with config.runner.token
    # (RUNNER_TOKEN is loaded from an existing config.php on a resumed install).
    printf '%s' "$RUNNER_TOKEN" > "$tf"
    chown root:root "$tf"; chmod 600 "$tf"
    chmod 755 "$APP_DIR/runner/runner.py"
    c_ok "Runner token installed (root:root 600)."
}

# =====================================================================
# 6) Permissions
# =====================================================================
fix_perms() {
    c_info "Setting ownership + permissions…"
    chown -R "$WEB_USER:$WEB_USER" "$APP_DIR"
    find "$APP_DIR" -type d -exec chmod 755 {} \;
    find "$APP_DIR" -type f -exec chmod 644 {} \;
    chmod 755 "$APP_DIR/runner/runner.py"
    chmod +x "$APP_DIR"/deploy/*.sh 2>/dev/null || true
    chmod -R 2775 "$APP_DIR/storage"
    # Config + token stay tight.
    chmod 640 "$APP_DIR/config/config.php" "$APP_DIR/client_helper/config.php" 2>/dev/null || true
    chown root:root "$APP_DIR/runner/.runner_token"; chmod 600 "$APP_DIR/runner/.runner_token"
    c_ok "Permissions set."
}

# =====================================================================
# 7) Sudoers (web user may run ONLY the runner as root, no password)
# =====================================================================
install_sudoers() {
    local f=/etc/sudoers.d/server-manager
    cat > "$f" <<EOF
# Managed by Server Manager installer — do not edit by hand.
${WEB_USER} ALL=(root) NOPASSWD: /usr/bin/python3 ${APP_DIR}/runner/runner.py
Defaults!/usr/bin/python3 !requiretty
EOF
    chmod 440 "$f"
    if visudo -cf "$f" >/dev/null; then
        c_ok "Sudoers installed."
    else
        rm -f "$f"; die "sudoers validation failed."
    fi
}

# =====================================================================
# 8) Apache vhost
# =====================================================================
install_vhost() {
    c_info "Configuring Apache…"
    a2enmod rewrite headers ssl >/dev/null 2>&1 || true
    local site=/etc/apache2/sites-available/server-manager.conf
    cat > "$site" <<EOF
<VirtualHost *:80>
    ServerName ${SERVER_NAME}
    DocumentRoot ${APP_DIR}/public

    <Directory ${APP_DIR}/public>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    # Never expose internals.
    <DirectoryMatch "${APP_DIR}/(app|config|runner|sql|bin|client_helper|deploy|docs|storage)">
        Require all denied
    </DirectoryMatch>

    ErrorLog  \${APACHE_LOG_DIR}/server-manager-error.log
    CustomLog \${APACHE_LOG_DIR}/server-manager-access.log combined
</VirtualHost>
EOF
    a2ensite server-manager >/dev/null 2>&1 || true
    apache2ctl configtest >/dev/null 2>&1 && systemctl reload apache2 || c_warn "apache configtest reported issues."
    c_ok "Apache vhost enabled for ${SERVER_NAME}."
}

# =====================================================================
# 9) Let's Encrypt
# =====================================================================
install_cert() {
    if [ "${ENABLE_SSL,,}" != "y" ]; then
        c_warn "Skipping HTTPS (ENABLE_SSL != y)."
        return
    fi
    ensure_certbot
    if ! command -v certbot >/dev/null || ! certbot --version >/dev/null 2>&1; then
        c_warn "certbot not available/working; skipping HTTPS."
        return
    fi
    c_info "Requesting Let's Encrypt certificate for ${SERVER_NAME}…"
    if certbot --apache -d "${SERVER_NAME}" --non-interactive --agree-tos \
        -m "${SERVER_ADMIN_EMAIL}" --redirect >/dev/null 2>&1; then
        c_ok "HTTPS provisioned + auto-redirect enabled."
    else
        c_warn "certbot failed (DNS not pointed yet?). Re-run later: sudo certbot --apache -d ${SERVER_NAME}"
    fi
}

# =====================================================================
# 10) systemd worker timers
# =====================================================================
install_workers() {
    c_info "Installing worker timers…"
    local php_bin; php_bin="$(command -v php)"

    cat > /etc/systemd/system/srvmgr-metrics.service <<EOF
[Unit]
Description=Server Manager metrics + service monitor
After=mysql.service mariadb.service
[Service]
Type=oneshot
User=${WEB_USER}
ExecStart=${php_bin} ${APP_DIR}/bin/collect-metrics.php
EOF

    cat > /etc/systemd/system/srvmgr-nids.service <<EOF
[Unit]
Description=Server Manager NIDS worker (expire blocks + threat scan)
After=mysql.service mariadb.service
[Service]
Type=oneshot
User=${WEB_USER}
ExecStart=${php_bin} ${APP_DIR}/bin/nids-worker.php
EOF

    cat > /etc/systemd/system/srvmgr-traffic.service <<EOF
[Unit]
Description=Server Manager traffic worker (map ingest + geolocate)
After=mysql.service mariadb.service
[Service]
Type=oneshot
User=${WEB_USER}
ExecStart=${php_bin} ${APP_DIR}/bin/traffic-worker.php
EOF

    cat > /etc/systemd/system/srvmgr-metrics.timer <<'EOF'
[Unit]
Description=Run Server Manager metrics collector every minute
[Timer]
OnBootSec=60
OnUnitActiveSec=60
AccuracySec=10s
Unit=srvmgr-metrics.service
[Install]
WantedBy=timers.target
EOF

    cat > /etc/systemd/system/srvmgr-nids.timer <<'EOF'
[Unit]
Description=Run Server Manager NIDS worker every minute
[Timer]
OnBootSec=90
OnUnitActiveSec=60
AccuracySec=10s
Unit=srvmgr-nids.service
[Install]
WantedBy=timers.target
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

    systemctl daemon-reload
    systemctl enable --now srvmgr-metrics.timer srvmgr-nids.timer srvmgr-traffic.timer >/dev/null 2>&1 || true
    c_ok "Worker timers enabled."
}

# =====================================================================
# 11) GitHub credentials for update.sh
# =====================================================================
setup_github() {
    [ -n "$REPO_URL" ] || { c_warn "No REPO_URL; skipping GitHub update wiring."; return; }

    # ASKPASS helper.
    local askpass=/usr/local/bin/git-askpass-github.sh
    cat > "$askpass" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  *'Username for '*github.com*) echo "x-access-token" ;;
  *'Password for '*github.com*) cat /etc/secrets/github_pat ;;
  *) echo "" ;;
esac
EOF
    chmod 750 "$askpass"; chgrp "$WEB_USER" "$askpass" 2>/dev/null || true

    # PAT storage.
    mkdir -p /etc/secrets
    if [ -n "$GITHUB_PAT" ]; then
        printf '%s' "$GITHUB_PAT" > /etc/secrets/github_pat
    elif [ ! -f /etc/secrets/github_pat ] && [ "${NONINTERACTIVE:-0}" != "1" ]; then
        read -rsp "GitHub Personal Access Token (blank to skip): " GITHUB_PAT; echo
        [ -n "$GITHUB_PAT" ] && printf '%s' "$GITHUB_PAT" > /etc/secrets/github_pat
    fi
    if [ -f /etc/secrets/github_pat ]; then
        chgrp -R "$WEB_USER" /etc/secrets; chmod 710 /etc/secrets; chmod 640 /etc/secrets/github_pat
    fi

    # Initialise git in APP_DIR for future pulls. Trust the dir system-wide so
    # both root and the web user can run git here (avoids "dubious ownership").
    git config --system --add safe.directory "$APP_DIR" 2>/dev/null || true
    if [ ! -d "$APP_DIR/.git" ]; then
        sudo -u "$WEB_USER" git -C "$APP_DIR" init -q
    fi
    sudo -u "$WEB_USER" git -C "$APP_DIR" remote set-url origin "$REPO_URL" 2>/dev/null \
        || sudo -u "$WEB_USER" git -C "$APP_DIR" remote add origin "$REPO_URL"
    sudo -u "$WEB_USER" git -C "$APP_DIR" config core.fileMode false
    # Persist branch for update.sh.
    printf 'REPO_URL=%s\nGIT_BRANCH=%s\n' "$REPO_URL" "$GIT_BRANCH" > "$APP_DIR/deploy/.deploy.env"
    chown "$WEB_USER:$WEB_USER" "$APP_DIR/deploy/.deploy.env"
    c_ok "GitHub update credentials configured."
}

# =====================================================================
# 12) First local admin API token
# =====================================================================
create_admin_token() {
    c_info "Creating first local admin API token…"
    ADMIN_TOKEN_OUT="$(sudo -u "$WEB_USER" php "$APP_DIR/bin/token.php" create "installer-admin" "read,services,firewall,nids,apps,runner,admin" 365 2>/dev/null | grep -Eo 'smgr_[A-Za-z0-9]+' || true)"
    [ -n "$ADMIN_TOKEN_OUT" ] && c_ok "Admin token created." || c_warn "Token creation skipped (create later with bin/token.php)."
}

# ---------------------------------------------------------------------
main() {
    install_packages
    copy_files
    generate_config
    load_existing_secrets
    setup_database
    setup_runner_token
    install_sudoers
    install_workers
    fix_perms
    install_vhost
    install_cert
    setup_github
    create_admin_token

    local scheme="http"; [ "${ENABLE_SSL,,}" = "y" ] && scheme="https"
    echo
    c_ok "Server Manager installed."
    echo   "-----------------------------------------------------------------"
    echo   "  URL:            ${scheme}://${SERVER_NAME}/"
    echo   "  Install dir:    ${APP_DIR}"
    echo   "  Database:       ${DB_NAME}  (user ${DB_USER})"
    echo   "  DB password:    ${DB_PASS}"
    echo   "  Runner token:   (stored in runner/.runner_token + config)"
    [ -n "${ADMIN_TOKEN_OUT:-}" ] && echo "  Admin API token: ${ADMIN_TOKEN_OUT}"
    echo   "-----------------------------------------------------------------"
    echo   "  Register app_id='${APP_ID}' with McNutt Cloud Auth using the"
    echo   "  app_secret you provided so SSO can redirect back here."
    echo   "  Update later with:  sudo bash ${APP_DIR}/deploy/update.sh"
    echo   "-----------------------------------------------------------------"
    c_warn "Save the DB password + admin token now — they are not shown again."
}

main "$@"

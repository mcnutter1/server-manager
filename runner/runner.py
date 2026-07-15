#!/usr/bin/env python3
"""
Server Manager — privileged action runner.

This is the ONLY component that executes privileged system commands. PHP (the
web tier) never runs shell commands directly; instead it invokes this script
through sudo and passes a JSON request on stdin. The runner:

  * authenticates the caller with a shared token,
  * only executes actions from a fixed whitelist (no arbitrary shell),
  * validates and sanitises every argument,
  * returns a structured JSON result on stdout.

Usage (from PHP):
    echo '<json>' | sudo /usr/bin/python3 runner.py

Request shape:
    {
      "token":  "<shared secret>",
      "action": "service.status",
      "args":   { "service": "apache2" }
    }

Response shape:
    { "ok": true, "action": "...", "exit_code": 0,
      "stdout": "...", "stderr": "...", "data": {...} }

Security notes:
  * Deploy read-only (root:root, 0755). The token lives in an env file
    (runner/.runner_token, 0600) or is passed via SRVMGR_RUNNER_TOKEN.
  * Grant the web user a narrow sudoers entry (see deploy/sudoers.sample).
  * Every action name is a key — arguments can never inject extra commands
    because we always use argv arrays (never shell=True).
"""

import json
import os
import re
import shutil
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_TIMEOUT = 25            # seconds per command
CHAIN = os.environ.get("SRVMGR_NIDS_CHAIN", "SRVMGR_BLOCK")

# Validation patterns.
RE_SERVICE = re.compile(r"^[a-zA-Z0-9._@-]{1,120}$")
RE_IPV4 = re.compile(r"^(\d{1,3})(\.\d{1,3}){3}$")
RE_IPV6 = re.compile(r"^[0-9a-fA-F:]{2,45}$")
RE_UNIT_JOURNAL = re.compile(r"^[a-zA-Z0-9._@-]{1,120}$")


def _bin(name, *fallbacks):
    """Resolve a binary path, trying common locations."""
    found = shutil.which(name)
    if found:
        return found
    for path in fallbacks:
        if os.path.exists(path):
            return path
    return name


IPTABLES = _bin("iptables", "/usr/sbin/iptables", "/sbin/iptables")
SYSTEMCTL = _bin("systemctl", "/usr/bin/systemctl", "/bin/systemctl")
JOURNALCTL = _bin("journalctl", "/usr/bin/journalctl")
SS = _bin("ss", "/usr/bin/ss", "/sbin/ss")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def fail(message, code=1):
    print(json.dumps({"ok": False, "error": message, "exit_code": code}))
    sys.exit(0)


def run(argv, timeout=DEFAULT_TIMEOUT):
    """Run a command as an argv array (never shell=True)."""
    start = time.time()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return {"exit_code": 127, "stdout": "", "stderr": f"not found: {argv[0]}", "ms": 0}
    except subprocess.TimeoutExpired:
        return {"exit_code": 124, "stdout": "", "stderr": "timeout", "ms": int((time.time() - start) * 1000)}
    return {
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "ms": int((time.time() - start) * 1000),
    }


def valid_ip(ip):
    if not isinstance(ip, str):
        return False
    if RE_IPV4.match(ip):
        return all(0 <= int(o) <= 255 for o in ip.split("."))
    return bool(RE_IPV6.match(ip))


def valid_service(name):
    return isinstance(name, str) and bool(RE_SERVICE.match(name))


def load_token():
    token = os.environ.get("SRVMGR_RUNNER_TOKEN", "")
    if token:
        return token
    token_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".runner_token")
    if os.path.exists(token_file):
        with open(token_file, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    return ""


# ---------------------------------------------------------------------------
# Action handlers
# ---------------------------------------------------------------------------
def ensure_chain():
    """Create the dedicated block chain and hook it into INPUT once."""
    run([IPTABLES, "-N", CHAIN])  # ignore "exists"
    check = run([IPTABLES, "-C", "INPUT", "-j", CHAIN])
    if check["exit_code"] != 0:
        run([IPTABLES, "-I", "INPUT", "1", "-j", CHAIN])


def action_service_status(args):
    svc = args.get("service", "")
    if not valid_service(svc):
        fail("invalid service name")
    props = run([SYSTEMCTL, "show", svc,
                 "--property=ActiveState,SubState,LoadState,UnitFileState,MainPID,ExecMainStartTimestamp"])
    data = {}
    for line in props["stdout"].splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k] = v
    return {"ok": True, "data": data, **props}


def action_service_action(args, verb):
    svc = args.get("service", "")
    if not valid_service(svc):
        fail("invalid service name")
    if verb not in ("start", "stop", "restart", "reload"):
        fail("invalid verb")
    res = run([SYSTEMCTL, verb, svc])
    return {"ok": res["exit_code"] == 0, **res}


def action_service_list(args):
    res = run([SYSTEMCTL, "list-units", "--type=service", "--all",
               "--no-legend", "--no-pager", "--plain"])
    services = []
    for line in res["stdout"].splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4:
            services.append({
                "unit": parts[0],
                "load": parts[1],
                "active": parts[2],
                "sub": parts[3],
                "description": parts[4] if len(parts) > 4 else "",
            })
    return {"ok": True, "data": {"services": services}, "exit_code": res["exit_code"], "stdout": "", "stderr": res["stderr"]}


def action_journal(args):
    unit = args.get("unit", "")
    lines = int(args.get("lines", 100))
    lines = max(1, min(lines, 2000))
    argv = [JOURNALCTL, "--no-pager", "-n", str(lines), "-o", "short-iso"]
    if unit:
        if not RE_UNIT_JOURNAL.match(unit):
            fail("invalid unit")
        argv += ["-u", unit]
    res = run(argv)
    return {"ok": True, **res}


def action_iptables_list(args):
    table = args.get("table", "filter")
    if table not in ("filter", "nat", "mangle", "raw"):
        fail("invalid table")
    res = run([IPTABLES, "-t", table, "-L", "-n", "-v", "--line-numbers"])
    return {"ok": res["exit_code"] == 0, **res}


def action_block_host(args):
    ip = args.get("ip", "")
    if not valid_ip(ip):
        fail("invalid ip")
    ensure_chain()
    # Idempotent: only add if not present.
    check = run([IPTABLES, "-C", CHAIN, "-s", ip, "-j", "DROP"])
    if check["exit_code"] == 0:
        return {"ok": True, "data": {"already": True}, "exit_code": 0, "stdout": "", "stderr": ""}
    res = run([IPTABLES, "-A", CHAIN, "-s", ip, "-j", "DROP"])
    return {"ok": res["exit_code"] == 0, **res}


def action_unblock_host(args):
    ip = args.get("ip", "")
    if not valid_ip(ip):
        fail("invalid ip")
    ensure_chain()
    res = {"exit_code": 0, "stdout": "", "stderr": "", "ms": 0}
    # Remove all matching rules.
    while run([IPTABLES, "-C", CHAIN, "-s", ip, "-j", "DROP"])["exit_code"] == 0:
        res = run([IPTABLES, "-D", CHAIN, "-s", ip, "-j", "DROP"])
        if res["exit_code"] != 0:
            break
    return {"ok": True, **res}


def action_block_stats(args):
    """Return per-IP packet/byte counters from the block chain."""
    ensure_chain()
    res = run([IPTABLES, "-L", CHAIN, "-n", "-v", "-x"])
    stats = {}
    for line in res["stdout"].splitlines():
        parts = line.split()
        # pkts bytes target prot opt in out source destination
        if len(parts) >= 8 and parts[2] == "DROP":
            src = parts[7]
            try:
                stats[src] = {"packets": int(parts[0]), "bytes": int(parts[1])}
            except ValueError:
                continue
    return {"ok": True, "data": {"stats": stats}, "exit_code": res["exit_code"], "stdout": "", "stderr": res["stderr"]}


def action_listening_ports(args):
    res = run([SS, "-tulnp"])
    return {"ok": True, **res}


HANDLERS = {
    "service.status":   action_service_status,
    "service.start":    lambda a: action_service_action(a, "start"),
    "service.stop":     lambda a: action_service_action(a, "stop"),
    "service.restart":  lambda a: action_service_action(a, "restart"),
    "service.reload":   lambda a: action_service_action(a, "reload"),
    "service.list":     action_service_list,
    "journal.tail":     action_journal,
    "iptables.list":    action_iptables_list,
    "nids.block":       action_block_host,
    "nids.unblock":     action_unblock_host,
    "nids.stats":       action_block_stats,
    "net.listening":    action_listening_ports,
}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    try:
        raw = sys.stdin.read()
        request = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        fail("invalid json request")

    expected = load_token()
    provided = request.get("token", "")
    if not expected:
        fail("runner token not configured on host")
    # Constant-time comparison.
    if not provided or not _consteq(provided, expected):
        fail("unauthorized", code=401)

    action = request.get("action", "")
    args = request.get("args", {}) or {}
    if action not in HANDLERS:
        fail(f"unknown action: {action}")

    try:
        result = HANDLERS[action](args)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        fail(f"runner error: {exc}")

    result.setdefault("ok", True)
    result["action"] = action
    print(json.dumps(result))


def _consteq(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0


if __name__ == "__main__":
    main()

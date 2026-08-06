#!/usr/bin/env python3
"""HoudiniRMM extra product features: audit, scripts, tags, 2FA helpers, uninstall wait."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import threading
import time
from pathlib import Path
from typing import Any

DATA = Path("/opt/nezha/agent-builder/data")
AUDIT_PATH = DATA / "audit.jsonl"
META_PATH = DATA / "device_meta.json"
SCRIPTS_PATH = DATA / "scripts.json"
SECURITY_PATH = DATA / "security.json"
_lock = threading.Lock()


def _read_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8") or "null") or default
    except Exception:
        return default


def _write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


# ---------- audit ----------
def audit(action: str, detail: dict | None = None, actor: str = "admin") -> None:
    row = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "actor": actor,
        "action": action,
        "detail": detail or {},
    }
    with _lock:
        DATA.mkdir(parents=True, exist_ok=True)
        with AUDIT_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def list_audit(limit: int = 200) -> list[dict]:
    if not AUDIT_PATH.exists():
        return []
    lines = AUDIT_PATH.read_text(encoding="utf-8", errors="ignore").splitlines()
    out = []
    for line in lines[-max(1, min(limit, 1000)) :]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    out.reverse()
    return out


# ---------- device meta (tags/notes/site) ----------
def load_meta() -> dict:
    with _lock:
        return _read_json(META_PATH, {})


def save_meta(meta: dict) -> None:
    with _lock:
        _write_json(META_PATH, meta)


def get_device_meta(device_id: int | str) -> dict:
    meta = load_meta()
    return dict(meta.get(str(device_id)) or {"tags": [], "notes": "", "site": "", "customer": ""})


def set_device_meta(device_id: int | str, patch: dict) -> dict:
    meta = load_meta()
    key = str(device_id)
    cur = dict(meta.get(key) or {"tags": [], "notes": "", "site": "", "customer": ""})
    if "tags" in patch:
        tags = patch["tags"]
        if isinstance(tags, str):
            tags = [x.strip() for x in tags.split(",") if x.strip()]
        cur["tags"] = list(tags)[:30]
    for k in ("notes", "site", "customer"):
        if k in patch:
            cur[k] = str(patch[k] or "")[:2000]
    meta[key] = cur
    save_meta(meta)
    return cur


# ---------- scripts library ----------
def load_scripts() -> list[dict]:
    with _lock:
        data = _read_json(SCRIPTS_PATH, {"scripts": []})
    return list(data.get("scripts") or [])


def save_scripts(scripts: list[dict]) -> None:
    with _lock:
        _write_json(SCRIPTS_PATH, {"scripts": scripts})


def upsert_script(body: dict) -> dict:
    scripts = load_scripts()
    sid = str(body.get("id") or secrets.token_hex(8))
    name = (body.get("name") or "Untitled").strip()[:120]
    shell = (body.get("shell") or "bash").strip()[:32]
    content = str(body.get("content") or "")[:100_000]
    row = {
        "id": sid,
        "name": name,
        "shell": shell,
        "content": content,
        "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    found = False
    for i, s in enumerate(scripts):
        if s.get("id") == sid:
            scripts[i] = row
            found = True
            break
    if not found:
        row["created"] = row["updated"]
        scripts.insert(0, row)
    save_scripts(scripts[:200])
    return row


def delete_script(sid: str) -> bool:
    scripts = load_scripts()
    n = len(scripts)
    scripts = [s for s in scripts if s.get("id") != sid]
    save_scripts(scripts)
    return len(scripts) < n


# ---------- security / 2FA / roles ----------
def load_security() -> dict:
    with _lock:
        sec = _read_json(
            SECURITY_PATH,
            {
                "totp_enabled": False,
                "totp_secret": "",
                "roles": {"admin": "admin"},
                "default_role": "admin",
            },
        )
    return sec


def save_security(sec: dict) -> None:
    with _lock:
        _write_json(SECURITY_PATH, sec)


def role_for(user: str) -> str:
    sec = load_security()
    roles = sec.get("roles") or {}
    return str(roles.get(user) or sec.get("default_role") or "admin")


def can_do(role: str, action: str) -> bool:
    role = (role or "admin").lower()
    if role == "admin":
        return True
    if role == "tech":
        return action in {
            "devices.read",
            "devices.uninstall",
            "devices.delete",
            "scripts.read",
            "scripts.run",
            "packages.read",
            "packages.build",
            "terminal",
            "meta.write",
            "audit.read",
        }
    if role == "readonly":
        return action in {"devices.read", "scripts.read", "packages.read", "audit.read"}
    return False


# TOTP (RFC 6238) without external deps
def _totp_code(secret_b32: str, for_time: float | None = None, step: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32.upper().replace(" ", ""), casefold=True)
    counter = int((for_time if for_time is not None else time.time()) // step)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    code = code_int % (10**digits)
    return str(code).zfill(digits)


def totp_verify(secret_b32: str, code: str, window: int = 1) -> bool:
    code = (code or "").strip()
    if not code.isdigit():
        return False
    now = time.time()
    for w in range(-window, window + 1):
        if hmac.compare_digest(_totp_code(secret_b32, now + w * 30), code):
            return True
    return False


def totp_new_secret() -> str:
    # 20 bytes -> base32
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def totp_provisioning_uri(secret: str, account: str = "admin", issuer: str = "HoudiniRMM") -> str:
    # pad secret for URI
    pad = secret + ("=" * ((8 - len(secret) % 8) % 8))
    from urllib.parse import quote

    label = quote(f"{issuer}:{account}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


def offline_summary(devices: list[dict], warn_minutes: int = 10) -> dict:
    now = time.time()
    offline = []
    stale = []
    for d in devices:
        if not d.get("online"):
            offline.append({"id": d.get("id"), "name": d.get("name"), "last_active": d.get("last_active")})
        else:
            # optional stale check from last_active string not always parseable
            pass
    return {
        "offline_count": len(offline),
        "offline": offline[:50],
        "warn_minutes": warn_minutes,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
    }
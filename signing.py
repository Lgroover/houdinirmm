#!/usr/bin/env python3
"""Certum/PFX code signing integration for the HoudiniRMM agent builder."""
import subprocess, os, json, time
from pathlib import Path

SIGN_PFX = Path("/opt/nezha/agent-builder/cert.pfx")
SIGN_PASS = os.environ.get("SIGN_PASS", "")
SIGN_COUNTS_PATH = Path("/opt/nezha/agent-builder/data/sign_counts.json")
SIGN_MAX_USER = 4  # free users get 4 signs/month
SIGN_MAX_ADMIN = float("inf")

def load_sign_counts() -> dict:
    try:
        return json.loads(SIGN_COUNTS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}

def save_sign_counts(data: dict) -> None:
    SIGN_COUNTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    SIGN_COUNTS_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")

def can_sign(uid: int, is_admin: bool = False) -> bool:
    if is_admin:
        return True
    counts = load_sign_counts()
    key = str(uid)
    now = time.time()
    # Keep only this month's entries
    counts[key] = [t for t in counts.get(key, []) if now - t < 2592000]  # 30 days
    if len(counts.get(key, [])) >= SIGN_MAX_USER:
        return False
    return True

def record_sign(uid: int) -> None:
    counts = load_sign_counts()
    key = str(uid)
    now = time.time()
    counts.setdefault(key, []).append(now)
    # Clean old entries
    counts[key] = [t for t in counts[key] if now - t < 2592000]
    save_sign_counts(counts)

def sign_exe(exe_path: Path, product_name: str = "HoudiniRMM") -> Path:
    """Sign an EXE using osslsigncode with PFX certificate. Returns signed path."""
    if not SIGN_PFX.exists():
        raise FileNotFoundError(f"Certificate not found at {SIGN_PFX}")
    if not SIGN_PASS:
        raise ValueError("SIGN_PASS environment variable not set")

    signed = exe_path.with_suffix(".signed.exe")
    args = [
        "osslsigncode", "sign",
        "-pkcs12", str(SIGN_PFX),
        "-pass", SIGN_PASS,
        "-h", "sha256",
        "-n", product_name,
        "-i", "https://rmm.houdini.fastmoneyclaim.com",
        "-t", "http://timestamp.digicert.com",
        "-in", str(exe_path),
        "-out", str(signed),
    ]
    result = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f"osslsigncode failed: {result.stderr or result.stdout}")
    # Replace original with signed
    signed.replace(exe_path)
    return exe_path

def get_sign_remaining(uid: int, is_admin: bool = False) -> dict:
    if is_admin:
        return {"unlimited": True, "remaining": "unlimited"}
    counts = load_sign_counts()
    key = str(uid)
    now = time.time()
    used = len([t for t in counts.get(key, []) if now - t < 2592000])
    return {"unlimited": False, "used": used, "remaining": max(0, SIGN_MAX_USER - used), "limit": SIGN_MAX_USER}

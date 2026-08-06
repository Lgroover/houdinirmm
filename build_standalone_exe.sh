#!/bin/bash
set -euo pipefail
export HOME=/root
export GOCACHE=/var/cache/go-build
export GOPATH=/root/go
export PATH=/usr/local/go/bin:/root/go/bin:/usr/bin:/bin:/usr/local/bin:$PATH
ROOT=/opt/nezha/agent-builder
BRANDING=$ROOT/data/branding.json
CACHE=$ROOT/cache
WINZIP=$CACHE/nezha-agent_windows_amd64.zip
PAYLOAD=$ROOT/wininstaller/payload
OUTDIR=$ROOT/out
mkdir -p "$PAYLOAD" "$OUTDIR" "$ROOT/wininstaller"

AGENT_VERSION="v2.3.1"
VERFILE="$WINZIP.version"
NEED_DL=0
if [ ! -f "$WINZIP" ]; then NEED_DL=1; fi
if [ -f "$VERFILE" ]; then
  CUR=$(cat "$VERFILE" 2>/dev/null || true)
  if [ "$CUR" != "$AGENT_VERSION" ]; then NEED_DL=1; fi
fi
if [ "$NEED_DL" = 1 ]; then
  echo "Downloading nezha-agent $AGENT_VERSION..."
  curl -L -o "$WINZIP.tmp" "https://github.com/nezhahq/agent/releases/download/$AGENT_VERSION/nezha-agent_windows_amd64.zip" || \
  curl -L -o "$WINZIP.tmp" "https://github.com/naiba/nezha/releases/download/$AGENT_VERSION/nezha-agent_windows_amd64.zip"
  mv "$WINZIP.tmp" "$WINZIP"
  echo "$AGENT_VERSION" > "$VERFILE"
fi
unzip -o "$WINZIP" -d "$PAYLOAD" 2>/dev/null || true
for f in "$PAYLOAD"/*; do
  if [ -f "$f" ] && [ "$(basename "$f")" != "branding.json" ] && [ "$(basename "$f")" != "config.yml" ]; then
    chmod +x "$f" 2>/dev/null || true
  fi
done

python3 << 'PY'
import json, pathlib, sys, subprocess
sys.path.insert(0, "/opt/nezha/agent-builder")
b = json.loads(pathlib.Path("/opt/nezha/agent-builder/data/branding.json").read_text())
try:
    from app import make_config
    cfg = make_config(b)
except Exception as e:
    def yn(v): return "true" if v else "false"
    cfg = f"""client_secret: {b['client_secret']}
server: {b['server']}
tls: {yn(bool(b.get('tls')))}
debug: {yn(bool(b.get('debug')))}
disable_auto_update: {yn(bool(b.get('disable_auto_update')))}
disable_command_execute: {yn(bool(b.get('disable_command_execute')))}
disable_force_update: {yn(bool(b.get('disable_force_update')))}
disable_nat: {yn(bool(b.get('disable_nat')))}
disable_send_query: {yn(bool(b.get('disable_send_query')))}
gpu: {yn(bool(b.get('gpu')))}
insecure_tls: {yn(bool(b.get('insecure_tls')))}
ip_report_period: {int(b.get('ip_report_period') or 1800)}
report_delay: {int(b.get('report_delay') or 3)}
self_update_period: {int(b.get('self_update_period') or 0)}
skip_connection_count: {yn(bool(b.get('skip_connection_count')))}
skip_procs_count: {yn(bool(b.get('skip_procs_count')))}
temperature: {yn(bool(b.get('temperature')))}
use_atomgit_to_upgrade: {yn(bool(b.get('use_atomgit_to_upgrade')))}
use_gitee_to_upgrade: {yn(bool(b.get('use_gitee_to_upgrade')))}
use_ipv6_country_code: {yn(bool(b.get('use_ipv6_country_code')))}
"""
    print("fallback make_config", e)
pathlib.Path("/opt/nezha/agent-builder/wininstaller/payload/config.yml").write_text(cfg)
pathlib.Path("/opt/nezha/agent-builder/wininstaller/payload/branding.json").write_text(json.dumps(b, indent=2))
print("embedded server", b.get("server"), "tls", b.get("tls"), "gpu", b.get("gpu"))
print(cfg[:400])

# Convert icon to ICO and regenerate .syso if icon exists
from PIL import Image
data_dir = pathlib.Path("/opt/nezha/agent-builder/data")
win_dir = pathlib.Path("/opt/nezha/agent-builder/wininstaller")
icon_path = None
for p in data_dir.glob("icon.*"):
    icon_path = p
    break
if icon_path and icon_path.exists():
    ico_path = win_dir / "icon.ico"
    try:
        img = Image.open(icon_path)
        sizes = [(16,16), (32,32), (48,48), (64,64), (96,96), (128,128), (256,256)]
        valid_sizes = [s for s in sizes if img.size[0] >= s[0] and img.size[1] >= s[1]]
        if not valid_sizes:
            valid_sizes = [img.size]
        img.save(ico_path, format="ICO", sizes=valid_sizes)
        print("Icon converted to", ico_path)
    except Exception as e:
        print("Icon conversion failed:", e)
        ico_path = None
    if ico_path and ico_path.exists():
        syso_path = win_dir / "rsrc_windows_amd64.syso"
        manifest_path = win_dir / "app.manifest"
        try:
            subprocess.run(["/root/go/bin/rsrc", "-manifest", str(manifest_path), "-ico", str(ico_path), "-arch", "amd64", "-o", str(syso_path)], check=True)
            print("Generated .syso with icon", syso_path)
        except Exception as e:
            print("rsrc failed:", e)
else:
    print("No icon found in", data_dir)
PY

if [ ! -f $ROOT/wininstaller/go.mod ]; then
  echo -e "module houdini-installer\n\ngo 1.22" > $ROOT/wininstaller/go.mod
fi

PRODUCT=$(python3 -c "import json;print(json.load(open('$BRANDING')).get('product_name') or 'HoudiniRMM')")
SAFE=$(echo "$PRODUCT" | tr -cd 'A-Za-z0-9._-' | head -c 40)
STAMP=$(date +%Y%m%d-%H%M%S)
OUTFILE="$OUTDIR/${SAFE}-Setup-windows-amd64-${STAMP}.exe"

cd "$ROOT/wininstaller"
# Use CGO_ENABLED=1 with mingw cross compiler so external linker preserves .rsrc section from .syso
CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$OUTFILE" .
ls -lh "$OUTFILE"
echo "OUT=$OUTFILE"

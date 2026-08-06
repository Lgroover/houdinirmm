# HoudiniRMM Agent Builder

Custom dashboard + agent builder for [Nezha Monitoring](https://github.com/nezhahq/agent) v2.3.x.

## Features

- **Device dashboard** with live monitoring, bulk actions, tags/notes
- **Agent package builder** — Windows EXE/ZIP, Linux ZIP, macOS ZIP
- **PowerShell one-liner installer** — copy-paste into any Windows machine
- **ScreenConnect deployment** — upload MSI, deploy to online Windows devices
- **Telegram notifications** — device online/offline, install reports
- **Code signing** — use your own signed agent EXE for all builds
- **Custom branding** — product name, icon, server config

## Files

| Path | Description |
|---|---|
| `app.py` | Main application (Python HTTP server) |
| `login.html` | Login page |
| `build_standalone_exe.sh` | Go build script for embedded Windows EXE |
| `houdini_features.py` | Feature helpers (audit, meta, scripts, terminal) |
| `wininstaller/` | Go source for the embedded Windows installer |
| `static/` | Installer scripts (PS1, VBS, BAT, MSI builder) |
| `nginx-site.conf` | Nginx reverse proxy configuration |

## Deployment

Requires a running Nezha dashboard on `127.0.0.1:8008`.

```bash
# Install nginx config
cp nginx-site.conf /etc/nginx/sites-enabled/houdinirmm
nginx -t && systemctl reload nginx

# Start the builder
python3 app.py        # port 8091
# Or with systemd:
# systemctl start nezha-agent-builder
```

## Security

- `data/` directory contains secrets (branding.json, tg_config.json) — excluded from git
- `cache/` and `out/` are runtime artifacts — excluded from git
- Nginx handles TLS termination + gRPC proxy for agent connections

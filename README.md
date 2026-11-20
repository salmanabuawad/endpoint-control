# KEM — Kortex Endpoint Manager · School Lab Manager

Self-hosted monitoring and remote control for Windows laptops and desktops.
It is modeled on the Acronis Cyber Protect workflow (registration token → agent → central console)
but trimmed down to what a small IT team actually needs.

> **Evolving into School Lab Manager** — a multi-school platform with a tenant hierarchy
> (Municipality → School → Lab → Station), role-based access (municipality admin / school manager /
> teacher), and a **Teacher Gateway** relay so student PCs reach the server through a lab box.
> See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the design and
> [`docs/STATUS.md`](docs/STATUS.md) for an honest capability-by-capability status. The tables
> below describe the single-tenant endpoint-management core that the school platform builds on.

## Multi-school additions (new)

| Area | What it does |
|---|---|
| **Tenant hierarchy** | Municipalities, schools, labs; stations and gateways are placed in a lab |
| **Roles (RBAC)** | `superadmin`, `municipality_admin`, `school_manager`, `teacher` — scope enforced in the API, not just the UI |
| **Teacher Gateway** | One relay per lab (`gateway/relay.py`); students connect to it and it forwards to the server with its own credentials; never lets students reach the server directly |
| **Class sessions** | A teacher must start a class session before classroom commands on their lab are accepted |
| **Examination mode** | Lock a whole lab for a test in one action (internet isolation + USB block, optionally a web filter), reverted when the exam ends; one exam per lab, scope- and role-enforced, audited |
| **Users** | Admins create/disable/delete scoped users and reset passwords |
| **Incident management** | Device health alerts auto-open and auto-resolve tracked incidents (open → acknowledged → resolved) with severity, assignee and notes; operators can also raise incidents by hand. Scoped per role, with a dashboard and nav badge |
| **License compliance** | Entitlement registry + a findings engine comparing installed commercial software against licences owned (seats, expiry), scoped per school; findings: compliant / verify / potential gap / confirmed issue |

An existing single-tenant KEM database upgrades in place: the lone admin becomes a `superadmin`,
new columns/tables are added, and all devices are preserved (placed into labs by an admin afterwards).

## Endpoint-management core

The single-tenant feature set every role builds on:

| Need | Acronis feature it mirrors | KEM |
|---|---|---|
| Add machines | Registration token | Tokens with expiry / max-uses / auto-group, one-line PowerShell install |
| See every machine | RMM inventory & monitoring | Online status, CPU/RAM/disk (24h chart), OS/build, model, serial, user, IPs, MACs, battery, installed software |
| Security posture | EDR / anti-malware view, patch status | Defender on/real-time/signature age, firewall profiles, BitLocker, last hotfix, pending reboot, alert badges, on-demand Defender scan |
| **Block a station's internet** | Network isolation / URL filtering | Firewall block rules for everything except the management server (+ DNS/DHCP/NTP, optional LAN). Agent re-applies them if tampered with |
| **Install software** | Software deployment | winget catalog (Chrome, Office, Zoom, …) or any MSI/EXE URL with silent args + SHA-256 check; uninstall via winget |
| **Patch management** | Update management | Scan each device for missing Windows updates (daily, automatic), install security / all / selected updates with controlled reboot; driver updates optional |
| **Website filtering** | URL filtering | Block domains per device (hosts file, all browsers; DNS-over-HTTPS disabled by policy so it can't be bypassed in-browser). One-click presets: social, video, games, gambling, file-sharing, AI chatbots |
| **Device lockdown** | Device control | Block or make read-only USB mass storage (keeps keyboards/mice/printers); re-applied if tampered with |
| **Reset to image** | Recovery / reimage | *Restore baseline* (System Restore snapshot taken at install / on demand), or *Factory reset* via the Windows MDM RemoteWipe CSP (wipe all or keep user files) |
| Remote actions | Scripting, power management | Run PowerShell as SYSTEM with output, reboot with user message, pop a message to the signed-in user, lock the screen / sign the user out |
| Live triage | RMM remote tools | List running processes (CPU/RAM) and end one; list services and start/stop/restart or change startup type |
| Alerting | Monitoring / notifications | Webhook (Slack, Teams, Discord, Telegram, Google Chat, Mattermost, generic JSON) and/or e-mail (SMTP) on new device, new warning, long offline, failed action |
| Fleet upkeep | Agent management | Agents self-update to the version the server hosts (checksum- and parse-verified), automatically or on demand |
| Accountability | Audit log | Every sign-in, enrollment and admin action; delivered-notification log |

```
endpoint-control/
├── server/            FastAPI + SQLite + vanilla-JS dashboard (no build step)
│   ├── app.py
│   └── static/        index.html, app.js, style.css
└── agent/             Windows PowerShell 5.1 agent (nothing to install on endpoints)
    ├── install.ps1    enroll + scheduled task (SYSTEM, at startup) + baseline restore point
    ├── kem-agent.ps1  check-in loop (every 15 s), runs commands
    ├── kem-actions.ps1 telemetry, isolation, install, reset … (shared library)
    └── uninstall.ps1
```

## Run the server

```powershell
pip install -r server/requirements.txt
$env:KEM_ADMIN_PASSWORD = 'choose-a-strong-password'   # first start only; otherwise one is generated into server/data/initial_admin_password.txt
python server/app.py                                   # http://127.0.0.1:8170
```

| Env var | Default | Meaning |
|---|---|---|
| `KEM_HOST` / `KEM_PORT` | `127.0.0.1` / `8170` | Listen address |
| `KEM_DATA` | `server/data` | SQLite DB location |
| `KEM_ADMIN_USER` / `KEM_ADMIN_PASSWORD` | `admin` / random | Initial admin (only used when the DB is new) |
| `KEM_TRUST_PROXY` | off | Set `1` behind nginx so real client IPs / HTTPS are detected |
| `KEM_CHECKIN_INTERVAL` | `15` | Seconds between agent check-ins |
| `KEM_ONLINE_SECONDS` | `90` | Device is shown offline after this long without a check-in |

**Production:** put it behind nginx with HTTPS (the device secret travels with every check-in) — see `deploy/`.

## Add a device

1. Dashboard → **Add devices** → *Generate token*.
2. On the PC, open **PowerShell as Administrator** and paste the token's install command.
3. The device appears in ~15 s. Files: `C:\Program Files\KEM` (scripts), `C:\ProgramData\KEM` (config, log, state — SYSTEM/Admins only).

Remove: dashboard → device → *Remove agent*, or run `C:\Program Files\KEM\uninstall.ps1` elevated.

## How the controls work (and their limits)

- **Block internet.** Four outbound *block* rules (TCP/UDP/ICMPv4/ICMPv6, group `KEM-Isolation`) whose remote address is
  the complement of {management server IPs, loopback, link-local, multicast, [LAN]}. Block rules beat allow rules, so
  existing app exceptions can't bypass it. DNS (53), DHCP (67/547) and NTP (123) stay open so the agent can resolve and reach the server.
  The agent re-checks every 5 min and re-applies if a local admin deletes the rules or the server IP changes.
  Limits: a local administrator can always stop the agent; a 3rd-party firewall that disables Windows Firewall defeats it (the agent reports a warning); already-open connections may survive until they close.
- **Install software.** winget runs as SYSTEM (`--scope machine`, falls back to the package default). Requires *App Installer* on the PC (present on Windows 10 21H2+/11). URL installs: MSI → `msiexec /qn /norestart`; EXE needs the vendor's silent switch.
- **Restore baseline.** Uses Windows System Restore: rolls back system files, registry, programs and drivers; keeps user documents. A baseline is created at install and can be replaced from the dashboard. Windows may purge old restore points when shadow storage fills (KEM sets it to 10% of C:).
- **Factory reset.** Calls `MDM_RemoteWipe.doWipeMethod` / `doWipePersistUserDataMethod` (same mechanism as Intune "Wipe"/"Fresh start"). Needs a working Windows recovery environment. The agent is wiped too — re-enroll afterwards.
- **Website filter.** Blocked domains (and their `www.`/`m.` sub-domains) resolve to `0.0.0.0` via a managed block in the hosts file; the agent turns off browser DNS-over-HTTPS by policy and re-applies the list every 5 min. Limits: a VPN or a different DNS proxy on the device can bypass it (pair with *Block internet* for a hard lockdown); Microsoft's own domains can't be blocked (Defender restores them); it is domain-level, not per-URL.
- **USB storage.** Uses the standard RemovableStorageDevices policy plus the USBSTOR/UASPStor driver start type. Read-only and full-block both leave input devices, printers and webcams working. Re-applied every 5 min if changed locally.
- **Patch management.** Uses the Windows Update agent (COM), the same source as Settings → Windows Update. Feature *upgrades* (a new Windows version) are never installed. Needs the device's Windows Update service enabled.
- **Message / lock / processes / services.** Messages, lock and sign-out run in the signed-in user's session via a short-lived scheduled task (nothing shows if no one is signed in). Critical OS/agent services and processes are protected from being stopped.
- **Agent self-update.** The server advertises the version and SHA-256 of the scripts it hosts; the agent downloads over TLS, verifies each checksum, parses the script before swapping it in, then restarts. Redeploying the server rolls out to every device.
- **Screenshots of the user's screen were intentionally left out.** Screen-capture-to-image from a SYSTEM service is indistinguishable from spyware to Windows Defender (AMSI blocks it), and it is the most invasive capability for little gain. If a deployment genuinely needs it, add a code-signed, AV-allow-listed build — not an unsigned script.
- **Custom golden images** (deploying *your* image over the network) need PXE/WDS or bootable media and are out of scope for an in-OS agent.

## Security model

- Admin: single account, PBKDF2 password hash, HttpOnly SameSite=Strict session cookie (12 h), `X-KEM` header required on every write (CSRF), login rate-limit, full audit log.
- Agents: one-time enrollment with a registration token → per-device 256-bit secret (stored hashed on the server). Destructive commands (reset, remove agent) are single-device and require typing the hostname.
- The agent's scripts are ACL-locked so standard users can't modify code that runs as SYSTEM.

## Tested so far (Windows 10 Home 22H2)

Enrollment, telemetry/inventory/software collection (incl. Hebrew names), script execution with Hebrew output and exit codes,
command queue/cancel/validation, auth/CSRF guards, dashboard pages, firewall range calculation.
v1.1 verified on real hardware: Windows Update scan (COM), process list, service list, agent self-update checksum/version check,
settings round-trip, notification validation, and the dashboard (updates/processes/services tabs, controls card, settings).
**Not yet exercised on a real machine** (need an elevated agent): applying isolation rules, web filter, USB policy, service
start/stop, user message/lock, winget/MSI installs, Windows-update *install*, baseline restore and factory reset —
try these on a spare test PC first.

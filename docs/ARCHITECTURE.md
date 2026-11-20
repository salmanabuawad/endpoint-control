# School Lab Manager — architecture

School Lab Manager is the multi-school evolution of KEM (Kortex Endpoint Manager). It keeps
KEM's proven stack — a single-file FastAPI server, SQLite (WAL), a vanilla-JS dashboard with
no build step, and a PowerShell 5.1 agent that runs as SYSTEM — and adds the three things a
municipality-scale deployment needs: a **tenant hierarchy**, **role-based access control**, and
a **Teacher Gateway** relay between the central server and student stations.

> Migrating SQLite → PostgreSQL and the dashboard → React are later phases (see `STATUS.md`).
> The data model and API below are written so that migration is a storage swap, not a rewrite.

## Layers

```
   Central Server  (Ubuntu / nginx / FastAPI / SQLite)
        ▲  outbound HTTPS only
        │
   Teacher Gateway  (one per lab — gateway/relay.py, Python stdlib)
        ▲  LAN, students initiate
        │
   Student Stations (Windows, PowerShell agent as SYSTEM)
```

* **Central server** (`server/app.py`) — the only place that authorizes anything. Holds the
  org tree, users, devices, gateways, commands, audit, and the admin dashboard.
* **Teacher Gateway** (`gateway/relay.py`) — one per lab. Enrolls with a *gateway token*, then
  exposes the student agent endpoints (`/api/agent/enroll|checkin|report`) on the LAN and
  forwards each call to the central server, adding its own `X-Gateway-Id` / `X-Gateway-Secret`.
  Students point at the gateway URL and never reach central directly. The gateway is a
  transport only — it carries no independent authority; central still validates the device
  secret on every call and decides what each device may do.
* **Student agent** (`agent/*.ps1`) — unchanged KEM agent. It talks to whatever URL it was
  installed with (central directly, or a gateway). All of KEM's endpoint controls (internet
  isolation, USB, web filter, patching, inventory, processes/services, message/lock, reset)
  ride on top of this unchanged.

## Tenant hierarchy

```
Municipality ──< School ──< Lab ──< Station (device)
                                 └─< Teacher Gateway
```

Tables: `municipalities`, `schools`, `labs`; `devices.lab_id` and `gateways.lab_id` place a
station / gateway in a lab. A device enrolled with a lab-scoped token (or through a gateway)
is placed automatically; otherwise an admin assigns it on the device page.

## Roles (RBAC)

`users(role, scope_type, scope_id)`. Every request resolves to a user; `allowed_lab_ids()`
turns the user's scope into the set of labs — and therefore devices, commands, tokens and
gateways — they may see or act on.

| Role | Scope | Sees | Can do |
|---|---|---|---|
| `superadmin` | global | everything | everything incl. create municipalities, manage all users |
| `municipality_admin` | one municipality (or global) | its schools/labs/devices | everything within scope; create school managers & teachers |
| `school_manager` | one school | its labs/devices | all classroom + security actions; **not** reset/reimage, run-script, agent removal |
| `teacher` | one lab | its devices | lock, message, reboot, internet, USB, web filter, view processes/services — **only during a class session** |

Enforcement lives in the API (`role_can_issue`, `device_in_scope`, `has_active_class`), not
just the UI. The dashboard hides what a role can't do; the server rejects it regardless
(verified: a teacher's `run_script` and a school manager's `reset_device` both return 403).

## Teacher class sessions

A teacher must `POST /api/class/start` (on their assigned lab) before any classroom command is
accepted; `has_active_class()` gates command creation. `teacher_sessions` records start/stop for
audit. Admins and school managers need no session.

## Enrollment & authentication

* **Admin** — PBKDF2 password in `users`, HttpOnly `SameSite=Strict` session cookie, `X-KEM`
  CSRF header on writes, login rate-limit, full audit log. The legacy single admin is migrated
  to a `superadmin` user automatically on first start of the new code.
* **Device** — one-time registration token (now typed `device`/`gateway` and optionally tied to
  a lab) → per-device 256-bit secret (stored hashed). Headers `X-Device-Id` / `X-Device-Secret`.
* **Gateway** — a `gateway` token tied to a lab → per-gateway secret. Headers `X-Gateway-Id` /
  `X-Gateway-Secret`. When a gateway relays an agent call, central records the attribution and
  inherits the gateway's lab onto the device.

## Request flow (a teacher locks a screen in a gateway lab)

1. Teacher signs in → cookie; starts a class session on their lab.
2. Teacher clicks Lock → `POST /api/commands {type: lock_session}`.
3. Server checks: role may issue `lock_session`, device is in the teacher's lab, class active.
4. Command is queued for the device.
5. The station's agent (polling the **gateway**) pulls the command; the gateway forwarded the
   poll to central with its gateway credentials.
6. Agent runs it in the user session, reports back through the gateway; server stores the result
   and writes an audit row.

## Files

```
server/app.py              central server + REST API + dashboard host
server/static/             dashboard (index.html, app.js, style.css) — role-aware SPA
agent/                     Windows student agent (install/uninstall, kem-agent, kem-actions)
gateway/relay.py           Teacher Gateway relay (stdlib Python)
gateway/install-gateway.ps1  installs the relay as a boot scheduled task + firewall rule
docs/ARCHITECTURE.md       this file
docs/STATUS.md             honest capability/phase status against the v4.0 spec
```

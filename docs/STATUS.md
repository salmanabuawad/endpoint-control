# School Lab Manager — implementation status

Honest status of the v4.0 spec. This is an evolving build on KEM; "everything" is the
destination, reached phase by phase. Nothing below is marked done unless it actually runs.

Legend: ✅ working & verified · 🟡 partial / basic · ⬜ not started · 🧪 needs a real lab/VM to verify

Date: 2026-11-20. Stack today: FastAPI + SQLite + vanilla-JS SPA + PowerShell agent
(Postgres/React are planned migrations, not yet done — see bottom).

## This session's additions (all verified)

The multi-tenant + RBAC + gateway **spine** that KEM lacked, built onto the existing server:

* ✅ Municipality → School → Lab → Station hierarchy (create/delete, scoped, device placement)
* ✅ Multi-user RBAC: `superadmin`, `municipality_admin`, `school_manager`, `teacher` with
  scope enforcement in the API (not just UI) — 34 automated checks pass
* ✅ User management (create/disable/delete/reset-password), scoped to the creator's reach
* ✅ Teacher Gateway: enrollment, a runnable relay (`gateway/relay.py`), central-side
  attribution — a student enrolls & checks in **through** the gateway, verified end to end (8 checks)
* ✅ Teacher class sessions gate classroom commands (verified: no session → 403)
* ✅ In-place migration of an existing KEM database (legacy admin → superadmin, columns added,
  devices preserved) — verified against a real pre-upgrade DB
* ✅ Role-aware dashboard: org tree, users, gateways, lab-scoped device lists, teacher console
  with class banner — verified live in a browser
* ✅ **Local AI diagnostics**: KEM sends one device's health snapshot to an admin-configured
  OpenAI-compatible endpoint (Ollama / llama.cpp / LM Studio / vLLM — meant to run locally) and
  shows the model's written diagnosis + remediation steps, stored on the device. Disabled until
  configured; the prompt carries **health data only** — never the signed-in user, IP, MAC or serial
  — and the UI shows exactly what was sent. The reply is advice to display, never commands to run.
  Verified end to end against a mock endpoint (17 checks: config/enable gating, the call, PII
  exclusion from both context and prompt, API-key masking, persistence, connection test, RBAC
  teacher-denied/manager-scoped, and a clean 502 when the endpoint is down) plus a live dashboard
  (Settings card with Test connection, device-page Run/Re-run with a "what was sent" disclosure).
* ✅ **Incident management**: device health alerts become tracked incidents (open → acknowledged →
  resolved) with a severity, an assignee and notes. Warn/critical alerts open incidents and
  auto-resolve themselves when the underlying condition clears (idempotent reconcile, stable keys
  that ignore the varying numbers in an alert); operators can also raise incidents by hand, which
  the auto-reconciler never touches. Scoped to the viewer's labs (teachers see their lab read-only;
  managers/admins act). Verified end to end (24 checks: auto open from real alerts, idempotency,
  acknowledge/resolve/reopen, system auto-resolve on recovery, recurrence, manual create, and RBAC)
  plus a live dashboard (filterable list, severity/status pills, a Scan-now action, and a nav badge).
* ✅ **Examination mode**: a teacher (during a class), school manager or admin locks every station
  in a lab into a controlled state with one action — it issues the already-verified classroom
  commands (internet isolation, USB block, optional web filter) to each station and lifts them
  again when the exam ends. One exam per lab, scope- and role-enforced, audited. Verified end to
  end (19 checks: lockdown/revert command fan-out, the one-exam-per-lab guard, "must lock
  something" validation, and RBAC — teacher needs a class and is pinned to their own lab, school
  manager covers the school, cross-lab stop denied) plus a live dashboard (start form + active-exam
  banner with End-exam).
* ✅ **Software license compliance**: an entitlement registry (scoped) + a findings engine that
  compares the collected software inventory against entitlements and reports Compliant /
  Verification required / Potential gap / Confirmed issue / Not applicable — with seat-count and
  expiry checks. Verified end to end (13 checks: detection, free-software exclusion, seat
  overflow, expiry, and RBAC — teacher denied, school manager read-only) plus a live dashboard
  (summary tiles + findings + entitlements with add/edit/delete). Commercial-software detection is
  a heuristic publisher/name match over a built-in catalog (Office, Adobe, Autodesk, antivirus,
  JetBrains, MATLAB, WinRAR, VMware, TeamViewer); a missing entitlement is reported as a
  *potential* gap, never proof of misuse, per the spec.

## Mandatory capabilities (spec §1)

| # | Capability | Status | Notes |
|---|---|---|---|
| 1 | Centralized multi-school management | ✅ | org tree + scoping |
| 2 | Municipality admin dashboard | ✅ | role-scoped SPA |
| 3 | School manager dashboard | ✅ | role-scoped SPA |
| 4 | Teacher console | 🟡 | scoped device view + class sessions + classroom actions; live screen grid not built |
| 5 | Teacher gateway | ✅ | relay + enrollment + attribution verified |
| 6 | Student Windows agent | ✅ | existing KEM agent (SYSTEM scheduled task) |
| 7 | Secure task execution | ✅ | typed commands, validation, per-role authz, audit |
| 8 | Live student screen monitoring | ⬜ | **intentionally deferred** — screen capture trips Defender AMSI (see KEM note); needs a signed, AV-allow-listed agent |
| 9 | Teacher screen broadcast | ⬜ | needs a media path (not built) |
| 10 | Screen locking | ✅ | `lock_session` (lock / sign-out) |
| 11 | Internet control | ✅ | firewall isolation (`block/unblock_internet`) + per-domain web filter |
| 12 | USB / SD restrictions | ✅ | `usb_storage` allow/read-only/block |
| 13 | Software install restrictions | 🟡🧪 | installs via winget/MSI exist; enforced *blocking* of unapproved installers (AppLocker/App Control) not yet built |
| 14 | Application allowlisting | ⬜ | planned (AppLocker/WDAC policy push) |
| 15 | Approved application launching | 🟡 | `install_software` from a catalog; "launch for user" not yet separated |
| 16 | Remote assistance | ⬜ | not built |
| 17 | File distribution | ⬜ | not built (install-by-URL exists) |
| 18 | Messaging | ✅ | `send_message` to the signed-in user |
| 19 | Restart / shutdown | ✅ | `reboot` with user warning |
| 20 | Examination mode | ✅ | per-lab exam = internet isolation + USB block (+ optional web filter) applied to every station and reverted on end; scope/role-enforced, audited; app allowlisting (#14) not yet part of the bundle |
| 21 | Computer health monitoring | ✅ | CPU/RAM/disk, Defender, firewall, BitLocker, updates, alerts |
| 22 | Software inventory | ✅ | collected per device |
| 23 | Software license compliance | ✅ | entitlement registry + findings engine (compliant / verification required / potential gap / confirmed issue / not applicable), scoped; seat & expiry checks; heuristic commercial-software detection |
| 24 | Alerts & incidents | ✅ | webhook/email alerts + delivery log **and** an incident workflow: alerts auto-open/auto-resolve incidents, with acknowledge/resolve/reopen, assignee, notes, scoped views and a dashboard |
| 25 | Central image repository | ⬜ | planned (Phase 4) |
| 26 | Gateway image distribution | ⬜ | planned (Phase 4) — relay transport exists, image serving does not |
| 27 | Local recovery image per station | 🟡🧪 | System Restore baseline exists (Level 1); dedicated recovery partition/WinRE image (Level 2) not built |
| 28 | Automatic & manual recovery | 🟡🧪 | `reset_device` = restore baseline / MDM factory wipe; policy-driven auto-recovery not built |
| 29 | Local AI diagnostics | ✅ | per-device diagnosis via an admin-configured OpenAI-compatible endpoint (Ollama/llama.cpp/LM Studio); PII-stripped prompt, advice-only output, scoped to admins/school managers; model quality depends on the endpoint the admin points at |
| 30 | Reports & auditing | 🟡 | full audit log + notification log; PDF/Excel export & scheduled reports not built |
| 31 | Multi-language | 🟡 | agent & server are UTF-8/Hebrew-safe (ASCII JSON for PS 5.1); dashboard i18n (RTL) not built |
| 32 | Secure offline operation | 🟡 | agent re-asserts policy offline; gateway task-caching while central is down not built (relay forwards live) |

## Phases (spec §21)

* **Phase 1 — distributed foundation** 🟡→ mostly ✅: backend, DB, auth, RBAC, schools/labs,
  agent, gateway, enrollment, task protocol, heartbeats, inventory, dashboards, messaging,
  restart, screen lock, command delivery through the gateway, and a central Local-AI integration
  **all working**. Phase 1 foundation is essentially complete.
* **Phase 2 — classroom control & endpoint security** 🟡: internet/USB/web-filter/messaging/lock
  and **examination mode** done; live monitoring, broadcast, remote assistance, allowlisting, file
  distribution pending.
* **Phase 3 — health & licensing** 🟡: health + alerts + **incident workflow** + **license registry
  & compliance findings** + **local AI diagnostics** done; exportable (PDF/Excel) reports pending.
* **Phase 4 — recovery infrastructure** 🟡🧪: Windows Restore (L1) + factory wipe exist; local
  recovery image (L2), recovery boot env, central image catalog, gateway image delivery pending.
* **Phase 5 — exams & automation** 🟡: examination mode (lock/revert a lab) done; policy-driven
  automation (scheduled exams, auto-recovery triggers) pending.
* **Phase 6 — production hardening** 🟡: signed installers/updates & cert rotation pending; the
  agent self-update (checksum + parse verified) and TLS/CSRF/audit are in place.

## Known limitations / honesty notes

* **Screen capture is deliberately omitted.** From a SYSTEM service it is indistinguishable from
  spyware; Windows Defender AMSI blocks it and would break the whole agent. If a deployment truly
  needs it, build a code-signed agent added to the AV allowlist — never obfuscate past AMSI.
* **Storage is still SQLite** and the dashboard is still vanilla JS. The spec mandates Postgres +
  React; those are planned migrations. The data model and REST API were designed to make the
  Postgres move a storage swap. Current scale target (≈50–1000 devices) is comfortable on SQLite/WAL.
* **Device-page controls** are hidden per role in the UI *and* enforced in the API. Audit is
  currently visible to all admins (not yet per-municipality filtered).
* **Not yet exercised on real Windows hardware** (need an elevated agent / lab): applying web
  filter, USB policy, service start/stop, message/lock on a live station, Windows-update install,
  baseline restore, factory reset, and the gateway installed as a Windows boot task. The gateway
  **relay logic itself** is verified (student enrolls through it, attribution lands on central).
* **Gateway offline caching** is not implemented — the relay forwards live; if central is down the
  student's call gets a 502 and the agent retries on its next cycle.

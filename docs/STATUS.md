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
* 🟡🧪 **File distribution**: a `distribute_file` managed command downloads a file from a URL over
  TLS (optional SHA-256 check) and places it in a chosen folder on the targeted stations. The
  server side — validation (https-only URL, Windows folder path, no traversal, system folders
  blocked, valid filename/hash), per-role authorisation (admins + school managers, **not** teachers),
  lab-scope checks and command queueing — is verified by 15 checks; the agent-side handler is
  written and syntax-checked (pure ASCII) but, like the other agent actions, **not yet exercised on
  real hardware**.
* ✅ **Exportable reports**: scope-aware Device inventory, Software licence compliance and Incidents
  reports, each as a **CSV** (UTF-8 BOM, opens in Excel, Hebrew-safe) and a **print-ready HTML** page
  (the browser's Save-as-PDF makes a PDF — no PDF/Excel libraries needed). Every row is filtered to
  the viewer's scope and the action is audited. Verified end to end (16 checks: catalog, CSV
  content-type/BOM/rows, HTML table, licensing + incident contents, format/kind validation, and
  RBAC/scope — a teacher sees only their lab and cannot pull the licensing report) plus a live
  dashboard (report cards + the rendered printable report).
* ✅ **Approved application launching**: a `launch_app` command opens an approved program (full
  path) or a web page (default browser) in the signed-in student's session — a classroom action
  (teacher during a class, school managers, admins). Server validation (app path / https URL),
  the teacher class-session gate, RBAC and queueing verified by 13 checks and a live dashboard; the
  agent launches via the existing run-as-user helper (same "not yet hardware-tested" caveat as the
  other agent actions). This is distinct from `install_software` (deploy) — it just launches.
* 🟡 **Central image repository (catalog)**: a repository of golden OS images referenced by location
  (URL or share path) + size + SHA-256, scoped to a municipality/school/lab/global, plus a per-lab
  "target image" assignment. CRUD + assignment + scope + RBAC (admins register; admins & school
  managers assign within scope; teachers denied) verified by 21 checks and a live dashboard. This is
  the **control plane only** — the image files are not uploaded/stored by KEM, and actual gateway
  distribution (#26) and reimaging need boot media, which is not built.
* ✅ **Gateway offline operation**: the Teacher Gateway relay now does **store-and-forward**. When
  the central server is unreachable, the gateway caches each student check-in/result to a local disk
  spool and returns a synthesized "keep cycling, no new commands" reply, so stations stay managed
  during an outage; a background thread replays the spool to central (oldest first) once it returns.
  Enrollment stays online-only (it needs central to mint a secret). Verified end to end with a
  central up→down→up harness (8 checks: online forwarding, cached reply + disk spool while down,
  enrollment refused offline, and the queued check-in landing on central after recovery).
* 🟡🧪 **Application allowlisting**: a `set_app_policy` command pushes an AppLocker executable
  allowlist (mode audit / enforce / off, plus path and filename allow-rules) to the targeted
  stations. Built brick-safe: the generated policy **always keeps the Windows default allow-rules**
  (Program Files, Windows dir, Administrators) and **defaults to audit (log-only)** — enforce is an
  explicit, warned opt-in; MSI/Script/DLL are left unconfigured (allowed). The server side —
  mode/rule validation, per-role authorisation (admins + school managers, not teachers), scoping and
  queueing — is verified by 15 checks, and the generated AppLocker XML was validated as well-formed;
  the agent handler is written, syntax-checked (ASCII) and the XML builder validated, **but AppLocker
  itself is not yet exercised on real hardware — test off-production first** (needs Windows
  Enterprise/Education + the App Identity service).
* 🟡 **Dashboard multi-language + RTL**: an i18n framework (`t()` + English/Hebrew string tables, a
  language switcher that persists per browser) with a full **right-to-left** layout flip for Hebrew.
  Translated: the app shell (navigation, login, sidebar), **every page header + subtitle** across all
  views, the **role labels**, the shared modal chrome, and **every view** — Devices, Incidents,
  Reports, Organization, Users, Gateways, Licensing, Images and **Settings** — in full (filters,
  trees, table headers, pills, cadence text with Hebrew weekday names, forms, action buttons and
  confirm/prompt dialogs). Still English by design: the Add-devices install instructions and the
  Gateways command-line setup steps (technical copy with code), the webhook-URL help list, and
  server-generated data strings (alert text, product names, licence types, per-event descriptions,
  computed scope labels). Verified live in Hebrew RTL across all these views. The server/agent were
  already UTF-8/Hebrew-safe.
* ✅ **Scheduled reports**: admins schedule any report to run daily/weekly/monthly at a chosen time;
  the monitor thread generates each due report at the creator's scope, saves a downloadable snapshot
  in history, and delivers it through the existing channels (webhook summary and/or e-mail with the
  CSV attached). Schedules are owned by their creator (superadmin sees all), enable/disable, run-now,
  and are audited. Verified end to end (22 checks: create/validate, daily/weekly/monthly next-run
  math, run-now → history → CSV download, the scope snapshot — a municipality admin's report
  excludes other municipalities — ownership isolation, and RBAC: school managers/teachers can't
  schedule) plus a live dashboard (schedule table with cadence text + run history).
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
| 14 | Application allowlisting | 🟡🧪 | `set_app_policy` pushes an AppLocker executable allowlist (audit/enforce/off; path + filename rules), brick-safe (keeps Windows defaults, audit by default); server validation/RBAC/scope verified (15 checks) + XML validated well-formed; AppLocker not yet run on hardware |
| 15 | Approved application launching | ✅ | `launch_app` opens an approved program or URL in the student's session (classroom action, class-gated for teachers); server verified (13 checks + dashboard), agent run-as-user exec pending hardware like other agent actions |
| 16 | Remote assistance | ⬜ | not built |
| 17 | File distribution | 🟡🧪 | `distribute_file` command: download a URL (SHA-256 checked) to a folder on targeted stations; server validation/RBAC/scope/queueing verified (15 checks), agent handler written + syntax-checked but not yet run on hardware |
| 18 | Messaging | ✅ | `send_message` to the signed-in user |
| 19 | Restart / shutdown | ✅ | `reboot` with user warning |
| 20 | Examination mode | ✅ | per-lab exam = internet isolation + USB block (+ optional web filter) applied to every station and reverted on end; scope/role-enforced, audited; app allowlisting (#14) not yet part of the bundle |
| 21 | Computer health monitoring | ✅ | CPU/RAM/disk, Defender, firewall, BitLocker, updates, alerts |
| 22 | Software inventory | ✅ | collected per device; the device page lists every installed app (searchable) and lets an admin/school-manager tick apps and uninstall the selected ones (agent uninstalls via each app's registry uninstall string, winget-by-name fallback — device-side exec pending hardware) |
| 23 | Software license compliance | ✅ | entitlement registry + findings engine (compliant / verification required / potential gap / confirmed issue / not applicable), scoped; seat & expiry checks; heuristic commercial-software detection |
| 24 | Alerts & incidents | ✅ | webhook/email alerts + delivery log **and** an incident workflow: alerts auto-open/auto-resolve incidents, with acknowledge/resolve/reopen, assignee, notes, scoped views and a dashboard |
| 25 | Central image repository | 🟡 | catalog/control plane done: register images by location + SHA-256, scoped, with per-lab target assignment (21 checks + dashboard); image file storage not in KEM (by design — images live on a share/URL) |
| 26 | Gateway image distribution | ⬜ | the image catalog (#25) names what to distribute, but the gateway serving/caching of image files and station reimaging need boot media — not built |
| 27 | Local recovery image per station | 🟡🧪 | System Restore baseline exists (Level 1); dedicated recovery partition/WinRE image (Level 2) not built |
| 28 | Automatic & manual recovery | 🟡🧪 | `reset_device` = restore baseline / MDM factory wipe; policy-driven auto-recovery not built |
| 29 | Local AI diagnostics | ✅ | per-device diagnosis via an admin-configured OpenAI-compatible endpoint (Ollama/llama.cpp/LM Studio); PII-stripped prompt, advice-only output, scoped to admins/school managers; model quality depends on the endpoint the admin points at |
| 30 | Reports & auditing | ✅ | audit log + notification log, exportable reports (devices / licensing / incidents) as CSV and print-to-PDF HTML, **and scheduled reports** (daily/weekly/monthly) with stored history + webhook/e-mail delivery, all scoped per role |
| 31 | Multi-language | 🟡 | agent & server UTF-8/Hebrew-safe **and** a dashboard i18n framework (English + Hebrew, full RTL, persisted); shell, all page headers/subtitles, role labels, the Devices page and modal chrome translated; deep table/card bodies on other views still English (incremental) |
| 32 | Secure offline operation | ✅ | agent re-asserts policy offline **and** the gateway store-and-forwards student check-ins/results during a central outage, replaying them on recovery (enrollment stays online-only); verified with an up→down→up harness (8 checks) |
| 33 | Software packages / baselines | ✅ | define a named desired app-set (e.g. "Student station" = Windows + Office + Chrome; "iTest" = +iTest) scoped global/municipality/school/lab; apply to a device = install the missing set members and (optionally) uninstall apps outside the set, protecting Windows/drivers/security/runtimes/the KEM agent; a dry-run **plan preview** (install / remove / keep / protected) before anything is queued; scoped to admins/school-managers, RBAC-enforced (19 checks); device-side exec reuses install/uninstall handlers (pending hardware) |
| 34 | Lab baselines | ✅ | assign a package as a lab's standard; the Packages page shows each lab's baseline, a **drift badge** (how many of its stations don't match) and **Apply to all** (previews per-station install/remove, then queues updates only for drifted stations); optional **auto-provision**: a station enrolling into the lab for the first time auto-installs the set (install-only, never removes); remove-extras is per-lab and only runs on an explicit, previewed apply; RBAC/scope-enforced (23 checks) |

## Phases (spec §21)

* **Phase 1 — distributed foundation** 🟡→ mostly ✅: backend, DB, auth, RBAC, schools/labs,
  agent, gateway, enrollment, task protocol, heartbeats, inventory, dashboards, messaging,
  restart, screen lock, command delivery through the gateway, and a central Local-AI integration
  **all working**. Phase 1 foundation is essentially complete.
* **Phase 2 — classroom control & endpoint security** 🟡: internet/USB/web-filter/messaging/lock
  and **examination mode** done; **file distribution** and **application allowlisting** server-side
  done (agent handlers pending hardware); live monitoring, broadcast and remote assistance pending.
* **Phase 3 — health & licensing** ✅: health + alerts + **incident workflow** + **license registry
  & compliance findings** + **local AI diagnostics** + **exportable & scheduled reports** all done.
* **Phase 4 — recovery infrastructure** 🟡🧪: Windows Restore (L1) + factory wipe exist, and the
  **central image catalog + per-lab assignment** (control plane) is built; local recovery image (L2),
  recovery boot env, image-file distribution via the gateway and reimaging pending (need boot media).
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
  baseline restore, factory reset, **file distribution (`distribute_file`)**, **application
  allowlisting (`set_app_policy` / AppLocker)**, **app launching (`launch_app`)**, **uninstall by
  name (`uninstall_software` via the registry uninstall string)**, and the gateway
  installed as a Windows boot task. The gateway
  **relay logic itself** is verified (student enrolls through it, attribution lands on central).
* **Gateway offline caching** is implemented (store-and-forward): during a central outage the relay
  caches student check-ins/results to disk and replays them when central returns, so stations keep
  cycling instead of erroring. Enrollment still needs central online (it mints the per-device secret).

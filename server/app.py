"""KEM - Kortex Endpoint Manager.

Central server: admin dashboard + REST API for Windows endpoint agents.
Agents enroll with a registration token, check in every few seconds with
telemetry, and receive queued commands (block internet, install software,
reset to baseline image, ...).
"""
from __future__ import annotations

import calendar
import csv
import datetime as dtmod
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import asynccontextmanager, contextmanager
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from fastapi import Body, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

APP_VERSION = "1.1.0"
BASE = Path(__file__).resolve().parent
AGENT_DIR = BASE.parent / "agent"
DATA = Path(os.environ.get("KEM_DATA", BASE / "data"))
DATA.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA / "kem.db"

ONLINE_SECONDS = int(os.environ.get("KEM_ONLINE_SECONDS", "90"))
CHECKIN_INTERVAL = int(os.environ.get("KEM_CHECKIN_INTERVAL", "15"))
SESSION_HOURS = 12
TRUST_PROXY = os.environ.get("KEM_TRUST_PROXY") == "1"
METRIC_RETENTION = 48 * 3600
LIVE_INTERVAL = 3      # check-in interval while an admin has the device page open
_viewing: dict[str, float] = {}
AGENT_FILES = {"install.ps1", "kem-agent.ps1", "kem-actions.ps1", "uninstall.ps1"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, username TEXT, created REAL, expires REAL, ip TEXT);
CREATE TABLE IF NOT EXISTS tokens(
  id INTEGER PRIMARY KEY, token TEXT UNIQUE, label TEXT, group_name TEXT DEFAULT '',
  created REAL, expires REAL, max_uses INTEGER DEFAULT 0, uses INTEGER DEFAULT 0, revoked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS devices(
  id TEXT PRIMARY KEY, secret_hash TEXT, machine_guid TEXT, hostname TEXT,
  group_name TEXT DEFAULT '', notes TEXT DEFAULT '', enrolled REAL, last_seen REAL,
  public_ip TEXT, agent_version TEXT, telemetry TEXT DEFAULT '{}',
  inventory TEXT DEFAULT '{}', inventory_at REAL, software TEXT DEFAULT '[]', software_at REAL,
  isolated INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_devices_guid ON devices(machine_guid);
CREATE TABLE IF NOT EXISTS commands(
  id INTEGER PRIMARY KEY, device_id TEXT, type TEXT, params TEXT, status TEXT,
  created REAL, sent REAL, finished REAL, output TEXT DEFAULT '', exit_code INTEGER, created_by TEXT);
CREATE INDEX IF NOT EXISTS ix_commands_device ON commands(device_id, status);
CREATE TABLE IF NOT EXISTS metrics(device_id TEXT, ts REAL, cpu REAL, mem REAL, disk REAL);
CREATE INDEX IF NOT EXISTS ix_metrics ON metrics(device_id, ts);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts REAL, actor TEXT, ip TEXT, action TEXT, target TEXT, details TEXT);
CREATE TABLE IF NOT EXISTS notifications(
  id INTEGER PRIMARY KEY, ts REAL, event TEXT, device_id TEXT, hostname TEXT, text TEXT,
  status TEXT DEFAULT 'queued', error TEXT DEFAULT '', sent REAL);
-- School Lab Manager: organizational hierarchy, roles, gateways
CREATE TABLE IF NOT EXISTS municipalities(id TEXT PRIMARY KEY, name TEXT, created REAL);
CREATE TABLE IF NOT EXISTS schools(id TEXT PRIMARY KEY, municipality_id TEXT, name TEXT, created REAL);
CREATE TABLE IF NOT EXISTS labs(id TEXT PRIMARY KEY, school_id TEXT, name TEXT, created REAL);
CREATE INDEX IF NOT EXISTS ix_schools_muni ON schools(municipality_id);
CREATE INDEX IF NOT EXISTS ix_labs_school ON labs(school_id);
CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY, username TEXT UNIQUE, pw_hash TEXT, display_name TEXT DEFAULT '',
  role TEXT, scope_type TEXT DEFAULT 'global', scope_id TEXT,
  created REAL, last_login REAL, disabled INTEGER DEFAULT 0, created_by TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS gateways(
  id TEXT PRIMARY KEY, secret_hash TEXT, lab_id TEXT, hostname TEXT, notes TEXT DEFAULT '',
  enrolled REAL, last_seen REAL, public_ip TEXT, agent_version TEXT, telemetry TEXT DEFAULT '{}');
CREATE INDEX IF NOT EXISTS ix_gateways_lab ON gateways(lab_id);
CREATE TABLE IF NOT EXISTS teacher_sessions(
  id TEXT PRIMARY KEY, user_id TEXT, username TEXT, lab_id TEXT, started REAL, ended REAL, note TEXT DEFAULT '');
CREATE INDEX IF NOT EXISTS ix_tsession_lab ON teacher_sessions(lab_id, ended);
CREATE TABLE IF NOT EXISTS license_entitlements(
  id TEXT PRIMARY KEY, name TEXT, product TEXT DEFAULT '', publisher TEXT DEFAULT '', edition TEXT DEFAULT '',
  license_type TEXT DEFAULT 'per_device', seats INTEGER DEFAULT 0, scope_type TEXT DEFAULT 'global', scope_id TEXT,
  expires REAL, notes TEXT DEFAULT '', created REAL, created_by TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS exam_sessions(
  id TEXT PRIMARY KEY, lab_id TEXT, name TEXT DEFAULT '', started_by TEXT DEFAULT '', started REAL,
  ended REAL, ended_by TEXT DEFAULT '', lock_internet INTEGER DEFAULT 1, lock_usb INTEGER DEFAULT 1,
  allow_lan INTEGER DEFAULT 0, web_filter TEXT DEFAULT '[]', note TEXT DEFAULT '', device_ids TEXT DEFAULT '[]');
CREATE INDEX IF NOT EXISTS ix_exam_lab ON exam_sessions(lab_id, ended);
CREATE TABLE IF NOT EXISTS incidents(
  id TEXT PRIMARY KEY, device_id TEXT, lab_id TEXT, title TEXT, detail TEXT DEFAULT '',
  severity TEXT DEFAULT 'warning', status TEXT DEFAULT 'open', source TEXT DEFAULT 'manual',
  source_key TEXT DEFAULT '', assignee TEXT DEFAULT '', note TEXT DEFAULT '',
  created REAL, created_by TEXT DEFAULT '', updated REAL,
  ack_at REAL, ack_by TEXT DEFAULT '', resolved_at REAL, resolved_by TEXT DEFAULT '', auto_resolved INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_incidents_status ON incidents(status, created);
CREATE INDEX IF NOT EXISTS ix_incidents_device ON incidents(device_id, status);
CREATE TABLE IF NOT EXISTS report_schedules(
  id TEXT PRIMARY KEY, kind TEXT, fmt TEXT DEFAULT 'csv', cadence TEXT DEFAULT 'weekly',
  hour INTEGER DEFAULT 7, weekday INTEGER DEFAULT 0, monthday INTEGER DEFAULT 1,
  recipients TEXT DEFAULT '', to_webhook INTEGER DEFAULT 0,
  role TEXT DEFAULT 'superadmin', scope_type TEXT DEFAULT 'global', scope_id TEXT,
  enabled INTEGER DEFAULT 1, created REAL, created_by TEXT DEFAULT '', last_run REAL, next_run REAL);
CREATE TABLE IF NOT EXISTS report_runs(
  id TEXT PRIMARY KEY, schedule_id TEXT, kind TEXT, fmt TEXT, scope_label TEXT, rows INTEGER DEFAULT 0,
  bytes INTEGER DEFAULT 0, content TEXT, generated REAL, status TEXT DEFAULT 'generated', note TEXT DEFAULT '');
CREATE INDEX IF NOT EXISTS ix_runs_sched ON report_runs(schedule_id, generated);
CREATE TABLE IF NOT EXISTS images(
  id TEXT PRIMARY KEY, name TEXT, os TEXT DEFAULT '', version TEXT DEFAULT '', size_bytes INTEGER DEFAULT 0,
  sha256 TEXT DEFAULT '', source_url TEXT DEFAULT '', notes TEXT DEFAULT '',
  scope_type TEXT DEFAULT 'global', scope_id TEXT, created REAL, created_by TEXT DEFAULT '');
CREATE INDEX IF NOT EXISTS ix_images_scope ON images(scope_type, scope_id);
"""
# Columns added after v1.0 (ALTER TABLE on existing databases).
MIGRATIONS = [
    ("devices", "updates", "TEXT DEFAULT '{}'"),
    ("devices", "updates_at", "REAL"),
    ("devices", "alert_state", "TEXT"),
    ("devices", "offline_notified", "INTEGER DEFAULT 0"),
    ("commands", "data", "TEXT"),
    # School Lab Manager
    ("devices", "lab_id", "TEXT"),
    ("devices", "gateway_id", "TEXT"),
    ("tokens", "kind", "TEXT DEFAULT 'device'"),
    ("tokens", "lab_id", "TEXT"),
    ("commands", "via_role", "TEXT DEFAULT ''"),
    ("devices", "ai_diagnosis", "TEXT"),
    ("devices", "ai_diagnosis_at", "REAL"),
    ("labs", "image_id", "TEXT"),
]

COMMAND_TYPES = {
    "block_internet", "unblock_internet", "install_software", "uninstall_software",
    "run_script", "reboot", "defender_scan", "refresh_inventory", "create_baseline",
    "reset_device", "uninstall_agent",
    # v1.1
    "scan_updates", "install_updates", "set_web_filter", "usb_storage", "list_processes",
    "kill_process", "list_services", "service_action", "send_message", "lock_session",
    "update_agent",
    # file distribution
    "distribute_file",
    # application allowlisting (AppLocker)
    "set_app_policy",
    # launch an approved app / URL in the student's session
    "launch_app",
}
# Destructive commands: one device at a time, admin must type the hostname.
CONFIRM_TYPES = {"reset_device", "uninstall_agent"}
# Commands whose result payload is kept on the command row (latest few per device).
DATA_TYPES = {"list_processes", "list_services"}
UPDATE_TYPES = {"scan_updates", "install_updates"}
RESET_MODES = {"restore_baseline", "factory_reset", "factory_reset_keep_data"}
WINGET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{1,127}$")
DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
SERVICE_NAME = re.compile(r"^[A-Za-z0-9_.$@ -]{1,100}$")
PROCESS_NAME = re.compile(r"^[A-Za-z0-9_.() -]{1,100}$")
TOKEN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
UPDATE_SCAN_HOURS = 24

NOTIFY_EVENTS = {
    "enrolled": "A new device enrolls",
    "alert": "A device gets a new warning (low disk, antivirus off, missing security updates, ...)",
    "offline": "A device stays offline longer than the threshold (and when it comes back)",
    "command_failed": "An action you sent fails",
}
DEFAULT_SETTINGS = {
    "notify_webhook": "", "notify_email": "", "smtp_host": "", "smtp_port": "587", "smtp_user": "",
    "smtp_pass": "", "smtp_from": "", "smtp_security": "starttls",
    "notify_events": json.dumps(["enrolled", "alert", "offline", "command_failed"]),
    "notify_offline_hours": "0", "auto_update_scan": "1", "auto_update_agent": "1", "public_url": "",
    # Local AI diagnostics (OpenAI-compatible endpoint: Ollama, llama.cpp, LM Studio, ...).
    "ai_enabled": "0", "ai_base_url": "", "ai_model": "", "ai_api_key": "",
}

# ---------------------------------------------------------------- roles & RBAC
# Hierarchy: Municipality -> School -> Lab -> Station (device).
# superadmin         : platform owner, sees/controls everything, manages municipalities.
# municipality_admin : full control within one municipality (scope_id) or global.
# school_manager     : controls all labs in one school (scope_id = school id).
# teacher            : controls one assigned lab (scope_id = lab id) during a class session.
ROLES = ("superadmin", "municipality_admin", "school_manager", "teacher")
ADMIN_ROLES = ("superadmin", "municipality_admin")          # may manage org, users, settings, tokens
SCOPE_FOR_ROLE = {"superadmin": "global", "municipality_admin": "municipality",
                  "school_manager": "school", "teacher": "lab"}

# Classroom commands a teacher may issue (needs an active class session). A teacher cannot
# run scripts, reset/reimage, change the security baseline, or touch the agent.
TEACHER_COMMANDS = {
    "lock_session", "send_message", "reboot", "block_internet", "unblock_internet",
    "usb_storage", "set_web_filter", "list_processes", "list_services", "launch_app",
}
# A school manager may do everything except destructive recovery and raw script execution,
# which stay with municipality admins (or require explicit delegation - a later phase).
SCHOOL_MANAGER_BLOCKED = {"reset_device", "uninstall_agent", "run_script"}


def role_can_issue(role: str, ctype: str) -> bool:
    if role in ("superadmin", "municipality_admin"):
        return True
    if role == "school_manager":
        return ctype not in SCHOOL_MANAGER_BLOCKED
    if role == "teacher":
        return ctype in TEACHER_COMMANDS
    return False


def role_capabilities(role: str) -> dict:
    """What the dashboard should let this role do (coarse UI gating; the API re-checks)."""
    admin = role in ADMIN_ROLES
    return {
        "manage_org": admin, "manage_users": admin, "manage_gateways": admin,
        "manage_tokens": admin, "server_settings": role == "superadmin",
        "view_audit": admin, "destructive": role in ("superadmin", "municipality_admin"),
        "run_script": role in ("superadmin", "municipality_admin"),
        "class_session": role == "teacher",
        "manage_exams": role in ROLES,  # teacher (during class), school_manager, admins; API re-checks scope
        "view_incidents": role in ROLES, "manage_incidents": admin or role == "school_manager",
        "run_diagnostics": admin or role == "school_manager", "view_reports": role in ROLES,
        "view_images": admin or role == "school_manager", "manage_images": admin,
        "view_licensing": admin or role == "school_manager", "manage_licensing": admin,
        "commands": sorted(COMMAND_TYPES) if admin else
                    sorted(COMMAND_TYPES - SCHOOL_MANAGER_BLOCKED) if role == "school_manager" else
                    sorted(TEACHER_COMMANDS),
    }


# ---------------------------------------------------------------- software license compliance
LICENSE_TYPES = ("per_device", "per_user", "concurrent", "site", "educational",
                 "subscription", "perpetual", "municipality")
# Unlimited-coverage types: an entitlement of this kind needs no per-seat count.
SITE_TYPES = {"site", "municipality", "educational"}

# Commercial products worth tracking. A detected product with no recorded entitlement becomes a
# "potential gap" finding (never "confirmed" - a missing record is not proof of misuse, per spec).
# Free editions (Acrobat Reader, TeamViewer Host, VS Code, ...) are deliberately excluded.
COMMERCIAL_SOFTWARE = [
    {"key": "ms_office", "label": "Microsoft Office / 365", "type": "subscription",
     "pub": r"microsoft", "name": r"microsoft (365|office)|office (365|professional|standard|home|plus|19|20)",
     "exclude": r"runtime|tools|web components|language pack"},
    {"key": "windows_server", "label": "Windows Server", "type": "per_device",
     "pub": r"microsoft", "name": r"windows server", "exclude": r""},
    {"key": "adobe_cc", "label": "Adobe Creative Cloud", "type": "subscription",
     "pub": r"adobe", "name": r"photoshop|illustrator|premiere|after effects|indesign|lightroom|creative cloud|acrobat (pro|dc)",
     "exclude": r"acrobat reader|reader|acrobat \(64|air"},
    {"key": "autodesk", "label": "Autodesk (AutoCAD / Revit / ...)", "type": "educational",
     "pub": r"autodesk", "name": r"autocad|revit|inventor|maya|3ds max|fusion|civil 3d", "exclude": r"viewer|player"},
    {"key": "antivirus", "label": "Endpoint antivirus (paid)", "type": "per_device",
     "pub": r"eset|kaspersky|bitdefender|symantec|norton|mcafee|trend micro|sophos|webroot", "name": r".", "exclude": r"free"},
    {"key": "jetbrains", "label": "JetBrains IDEs", "type": "subscription",
     "pub": r"jetbrains", "name": r"intellij idea ultimate|pycharm professional|webstorm|rider|clion|datagrip|phpstorm", "exclude": r"community"},
    {"key": "matlab", "label": "MATLAB", "type": "educational", "pub": r"mathworks", "name": r"matlab|simulink", "exclude": r""},
    {"key": "winrar", "label": "WinRAR", "type": "perpetual", "pub": r"win\.?rar|rarlab", "name": r"winrar", "exclude": r""},
    {"key": "vmware", "label": "VMware Workstation", "type": "perpetual", "pub": r"vmware", "name": r"workstation (pro|player)?", "exclude": r""},
    {"key": "teamviewer", "label": "TeamViewer", "type": "subscription", "pub": r"teamviewer", "name": r"teamviewer", "exclude": r"host"},
]
FINDING_ORDER = {"confirmed_issue": 0, "potential_gap": 1, "verification_required": 2, "compliant": 3, "not_applicable": 4}


def detect_product(name: str | None, publisher: str | None) -> dict | None:
    """Classify an installed program as a known commercial product, or None (free/untracked)."""
    n = (name or "").strip().lower()
    p = (publisher or "").strip().lower()
    if not n:
        return None
    for c in COMMERCIAL_SOFTWARE:
        if c.get("exclude") and re.search(c["exclude"], n):
            continue
        pub_ok = bool(c["pub"]) and bool(re.search(c["pub"], p))
        name_ok = c.get("name") not in (None, "", ".") and bool(re.search(c["name"], n))
        if (pub_ok and (c.get("name") in (None, "", ".") or name_ok)) or name_ok:
            return c
    return None


def entitlement_in_scope(con, user: dict, e: dict) -> bool:
    st, sid = e["scope_type"], e["scope_id"]
    if user["role"] == "superadmin" or st == "global":
        return True
    if st == "municipality":
        return muni_in_scope(user, sid)
    if st == "school":
        return school_in_scope(con, user, sid)
    if st == "lab":
        return device_in_scope(con, user, sid)
    return False


def compute_findings(con, user: dict) -> list[dict]:
    allowed = allowed_lab_ids(con, user)
    products: dict[str, dict] = {}
    for r in con.execute("SELECT id, hostname, lab_id, software FROM devices").fetchall():
        if allowed is not None and (r["lab_id"] is None or r["lab_id"] not in allowed):
            continue
        for s in jload(r["software"], []):
            if not isinstance(s, dict):
                continue
            c = detect_product(s.get("name"), s.get("publisher"))
            if not c:
                continue
            pr = products.setdefault(c["key"], {"key": c["key"], "label": c["label"], "type": c["type"],
                                                "devices": set(), "samples": []})
            pr["devices"].add(r["id"])
            if len(pr["samples"]) < 25:
                pr["samples"].append({"host": r["hostname"], "name": s.get("name"), "version": s.get("version")})
    ents = [dict(e) for e in con.execute("SELECT * FROM license_entitlements").fetchall()]
    ents = [e for e in ents if entitlement_in_scope(con, user, e)]
    by_product: dict[str, list] = {}
    for e in ents:
        by_product.setdefault(e["product"] or "", []).append(e)
    t = now()
    findings = []
    for key, pr in products.items():
        installs = len(pr["devices"])
        matched = by_product.get(key, [])
        seats = sum((e["seats"] or 0) for e in matched)
        site = any(e["license_type"] in SITE_TYPES or (e["seats"] or 0) == 0 for e in matched)
        expiries = [e["expires"] for e in matched if e["expires"]]
        soonest = min(expiries) if expiries else None
        if not matched:
            cat, msg = "potential_gap", f"{installs} install(s) found, no recorded entitlement"
        elif soonest and soonest < t:
            cat, msg = "confirmed_issue", "Entitlement expired " + time.strftime('%Y-%m-%d', time.localtime(soonest))
        elif soonest and soonest < t + 30 * 86400:
            cat, msg = "verification_required", "Entitlement expires " + time.strftime('%Y-%m-%d', time.localtime(soonest))
        elif not site and seats and installs > seats:
            cat, msg = "confirmed_issue", f"{installs} installs exceed {seats} licensed seat(s)"
        elif not site and not seats:
            cat, msg = "verification_required", "Entitlement has no seat count"
        else:
            cat, msg = "compliant", f"{installs} install(s)" + (" / site licence" if site else f" / {seats} seats")
        findings.append({"product": key, "label": pr["label"], "type": pr["type"], "installs": installs,
                         "seats": seats, "site": site, "category": cat, "message": msg,
                         "entitlements": len(matched), "expires": soonest, "samples": pr["samples"][:10]})
    for e in ents:
        if (e["product"] or "") not in products and e["product"]:
            c = next((x for x in COMMERCIAL_SOFTWARE if x["key"] == e["product"]), None)
            findings.append({"product": e["product"], "label": c["label"] if c else e["name"], "type": e["license_type"],
                             "installs": 0, "seats": e["seats"] or 0, "site": e["license_type"] in SITE_TYPES,
                             "category": "not_applicable", "message": "Entitlement on record, no installs detected",
                             "entitlements": 1, "expires": e["expires"], "samples": []})
    findings.sort(key=lambda f: (FINDING_ORDER.get(f["category"], 9), -f["installs"]))
    return findings


def now() -> float:
    return time.time()


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


@contextmanager
def db():
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def hash_password(pw: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 240_000)
    return f"pbkdf2${salt}${dk.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, salt, digest = stored.split("$")
    except ValueError:
        return False
    return hmac.compare_digest(hash_password(pw, salt).split("$")[2], digest)


def get_setting(con, key: str) -> str | None:
    row = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None


def set_setting(con, key: str, value: str) -> None:
    con.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def setting(con, key: str) -> str:
    v = get_setting(con, key)
    return DEFAULT_SETTINGS.get(key, "") if v is None else v


def vtuple(v: str | None) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:3]) or (0,)


def _agent_release() -> dict:
    """Version + SHA-256 of the agent scripts this server hands out (used for agent self-update)."""
    text = (AGENT_DIR / "kem-actions.ps1").read_text(encoding="ascii", errors="replace")
    m = re.search(r"\$script:KemVersion\s*=\s*'([^']+)'", text)
    files = {n: hashlib.sha256((AGENT_DIR / n).read_bytes()).hexdigest()
             for n in ("kem-agent.ps1", "kem-actions.ps1", "uninstall.ps1")}
    return {"version": m.group(1) if m else "0", "files": files}


AGENT_RELEASE = _agent_release()


def init_db() -> None:
    generated = False
    user = pw = None
    with db() as con:
        con.execute("PRAGMA journal_mode=WAL")
        con.executescript(SCHEMA)
        for table, col, decl in MIGRATIONS:
            cols = {r["name"] for r in con.execute(f"PRAGMA table_info({table})")}
            if col not in cols:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
        con.execute("CREATE INDEX IF NOT EXISTS ix_devices_lab ON devices(lab_id)")
        # Seed the first administrator into the users table (or migrate a legacy single admin).
        if not con.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            legacy_hash = get_setting(con, "admin_hash")
            if legacy_hash:  # existing KEM install -> promote the single admin to global superadmin
                user = get_setting(con, "admin_user") or "admin"
                pw_hash = legacy_hash
            else:
                user = os.environ.get("KEM_ADMIN_USER", "admin")
                pw = os.environ.get("KEM_ADMIN_PASSWORD")
                generated = not pw
                pw = pw or secrets.token_urlsafe(12)
                pw_hash = hash_password(pw)
                set_setting(con, "admin_user", user)
                set_setting(con, "admin_hash", pw_hash)
            con.execute(
                "INSERT INTO users(id,username,pw_hash,display_name,role,scope_type,scope_id,created,created_by)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (uuid.uuid4().hex, user, pw_hash, "Administrator", "superadmin", "global", None, now(),
                 "migration" if legacy_hash else "bootstrap"))
    if generated:
        note = DATA / "initial_admin_password.txt"
        note.write_text(f"user: {user}\npassword: {pw}\n(delete this file after first login and change the password)\n")
        try:
            note.chmod(0o600)
        except OSError:
            pass
        print(f"[KEM] Created admin user '{user}'. Initial password written to {note}")


init_db()


# ---------------------------------------------------------------- notifications (webhook / e-mail)

_wake = threading.Event()


def channels_configured(con) -> bool:
    return bool(setting(con, "notify_webhook") or (setting(con, "notify_email") and setting(con, "smtp_host")))


def notify(con, event: str, device_id: str, hostname: str, text: str) -> None:
    """Queue a notification; the monitor thread delivers it."""
    if event not in jload(setting(con, "notify_events"), []) or not channels_configured(con):
        return
    con.execute("INSERT INTO notifications(ts,event,device_id,hostname,text) VALUES(?,?,?,?,?)",
                (now(), event, device_id, hostname, text[:1000]))
    _wake.set()


def _http_post(url: str, payload: dict) -> None:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": f"KEM/{APP_VERSION}"})
    with urllib.request.urlopen(req, timeout=15) as r:
        r.read(2048)


def send_webhook(url: str, title: str, text: str, link: str) -> None:
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    full = f"{title}\n{text}" + (f"\n{link}" if link else "")
    if host == "api.telegram.org":
        # https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<CHAT>
        parts = urllib.parse.urlsplit(url)
        chat = urllib.parse.parse_qs(parts.query).get("chat_id", [""])[0]
        _http_post(urllib.parse.urlunsplit(parts._replace(query="")), {"chat_id": chat, "text": full})
    elif host.endswith("discord.com") or host.endswith("discordapp.com"):
        _http_post(url, {"content": full[:1900]})
    elif host.endswith("logic.azure.com") or host.endswith("powerplatform.com"):
        # Microsoft Teams "Workflows" webhook expects an Adaptive Card.
        body = [{"type": "TextBlock", "text": title, "weight": "Bolder", "wrap": True},
                {"type": "TextBlock", "text": text, "wrap": True}]
        card = {"type": "AdaptiveCard", "version": "1.4", "body": body,
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json"}
        if link:
            card["actions"] = [{"type": "Action.OpenUrl", "title": "Open in KEM", "url": link}]
        _http_post(url, {"type": "message", "attachments": [
            {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]})
    else:  # Slack, Teams (Office connector), Mattermost, Google Chat, generic
        _http_post(url, {"text": full})


def send_email(cfg: dict, subject: str, text: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["smtp_from"] or cfg["smtp_user"]
    msg["To"] = cfg["notify_email"]
    msg.set_content(text)
    port = int(cfg["smtp_port"] or 587)
    ctx = ssl.create_default_context()
    if cfg["smtp_security"] == "ssl":
        smtp = smtplib.SMTP_SSL(cfg["smtp_host"], port, timeout=20, context=ctx)
    else:
        smtp = smtplib.SMTP(cfg["smtp_host"], port, timeout=20)
    with smtp:
        if cfg["smtp_security"] == "starttls":
            smtp.starttls(context=ctx)
        if cfg["smtp_user"]:
            smtp.login(cfg["smtp_user"], cfg["smtp_pass"])
        smtp.send_message(msg)


def deliver(cfg: dict, title: str, text: str, link: str = "") -> list[str]:
    """Send to every configured channel. Returns a list of error strings (empty = all sent)."""
    errors = []
    if cfg["notify_webhook"]:
        try:
            send_webhook(cfg["notify_webhook"], title, text, link)
        except Exception as e:  # noqa: BLE001 - report any delivery failure
            errors.append(f"webhook: {e}")
    if cfg["notify_email"] and cfg["smtp_host"]:
        try:
            send_email(cfg, title, text + (f"\n\n{link}" if link else ""))
        except Exception as e:  # noqa: BLE001
            errors.append(f"email: {e}")
    return errors


def notify_config(con) -> dict:
    return {k: setting(con, k) for k in DEFAULT_SETTINGS}


INCIDENT_SEVERITY = {"warn": "warning", "crit": "critical"}


def alert_key(text: str) -> str:
    """Stable identity for an alert, ignoring the varying numbers inside it (day counts, sizes)."""
    return re.sub(r"\s+", " ", re.sub(r"\d+", "", text or "")).strip().lower()


def sync_incidents(con, device_id: str, hostname: str, lab_id, alerts: list) -> None:
    """Reconcile a device's open incidents with its current alerts: open new ones, auto-resolve cleared ones.
    Idempotent — safe to run every monitor tick. Human-created incidents (source='manual') are never touched."""
    active: dict[str, tuple] = {}
    for a in alerts:
        if a["level"] in ("warn", "crit"):
            active.setdefault(alert_key(a["text"]), (INCIDENT_SEVERITY[a["level"]], a["text"]))
    open_rows = con.execute(
        "SELECT id, source_key FROM incidents WHERE device_id=? AND source='auto' AND status!='resolved'",
        (device_id,)).fetchall()
    open_keys = {r["source_key"] for r in open_rows}
    t = now()
    for key, (sev, text) in active.items():
        if key not in open_keys:
            con.execute(
                "INSERT INTO incidents(id,device_id,lab_id,title,detail,severity,status,source,source_key,created,created_by,updated)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (uuid.uuid4().hex, device_id, lab_id, text, f"Auto-detected on {hostname}", sev, "open", "auto", key, t, "system", t))
    for r in open_rows:
        if r["source_key"] not in active:
            con.execute("UPDATE incidents SET status='resolved', resolved_at=?, resolved_by=?, auto_resolved=1, updated=? "
                        "WHERE id=?", (t, "system", t, r["id"]))


def evaluate_devices(con) -> None:
    """Detect new alerts and long offline periods, queue notifications for them, and reconcile incidents."""
    t = now()
    offline_hours = float(setting(con, "notify_offline_hours") or 0)
    for row in con.execute("SELECT * FROM devices").fetchall():
        online = bool(row["last_seen"] and t - row["last_seen"] < ONLINE_SECONDS)
        alerts = device_alerts(row, jload(row["telemetry"], {}), jload(row["inventory"], {}), online,
                               jload(row["updates"], {}))
        sync_incidents(con, row["id"], row["hostname"], row["lab_id"], alerts)
        current = sorted({a["text"] for a in alerts if a["level"] in ("warn", "crit")})
        if row["alert_state"] is None:  # first look at this device: remember silently
            con.execute("UPDATE devices SET alert_state=? WHERE id=?", (json.dumps(current), row["id"]))
        else:
            before = set(jload(row["alert_state"], []))
            new = [a for a in current if a not in before]
            if current != sorted(before):
                con.execute("UPDATE devices SET alert_state=? WHERE id=?", (json.dumps(current), row["id"]))
            if new:
                notify(con, "alert", row["id"], row["hostname"], "New warning: " + "; ".join(new))
        if (offline_hours > 0 and not row["offline_notified"] and row["last_seen"]
                and t - row["last_seen"] > offline_hours * 3600):
            con.execute("UPDATE devices SET offline_notified=1 WHERE id=?", (row["id"],))
            notify(con, "offline", row["id"], row["hostname"],
                   f"Offline since {time.strftime('%Y-%m-%d %H:%M', time.localtime(row['last_seen']))}")


def send_queued(con) -> None:
    rows = con.execute("SELECT * FROM notifications WHERE status='queued' ORDER BY id LIMIT 50").fetchall()
    if not rows:
        return
    cfg = notify_config(con)
    con.commit()  # don't hold the write lock while talking to the network
    for n in rows:
        link = f"{cfg['public_url']}/#/device/{n['device_id']}" if cfg["public_url"] and n["device_id"] else ""
        errors = deliver(cfg, f"[KEM] {n['hostname'] or 'KEM'}: {n['event'].replace('_', ' ')}", n["text"], link)
        con.execute("UPDATE notifications SET status=?, error=?, sent=? WHERE id=?",
                    ("failed" if errors else "sent", "; ".join(errors)[:1000], now(), n["id"]))
        con.commit()
    con.execute("DELETE FROM notifications WHERE id NOT IN (SELECT id FROM notifications ORDER BY id DESC LIMIT 500)")


def monitor_loop() -> None:
    while True:
        try:
            with db() as con:
                evaluate_devices(con)
            with db() as con:
                send_queued(con)
            with db() as con:
                run_due_reports(con)
        except Exception as e:  # noqa: BLE001 - keep the monitor alive
            print(f"[KEM] monitor error: {e}")
        _wake.wait(60)
        _wake.clear()


@asynccontextmanager
async def lifespan(_app):
    threading.Thread(target=monitor_loop, name="kem-monitor", daemon=True).start()
    yield


app = FastAPI(title="KEM Endpoint Manager", version=APP_VERSION, docs_url=None, redoc_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache"  # revalidate via ETag so upgrades show up at once
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


class AgentJSON(JSONResponse):
    """ASCII-only JSON so Windows PowerShell 5.1 never mis-decodes Hebrew etc."""
    media_type = "application/json; charset=utf-8"

    def render(self, content: Any) -> bytes:
        return json.dumps(content, ensure_ascii=True, separators=(",", ":")).encode("ascii")


# ---------------------------------------------------------------- helpers

def client_ip(request: Request) -> str:
    if TRUST_PROXY:
        fwd = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if fwd:
            return fwd
    return request.client.host if request.client else ""


def is_https(request: Request) -> bool:
    if TRUST_PROXY and request.headers.get("x-forwarded-proto") == "https":
        return True
    return request.url.scheme == "https"


def clean(value: Any, limit: int) -> str:
    return str(value or "").strip()[:limit]


def audit(con, actor: str, ip: str, action: str, target: str = "", details: Any = "") -> None:
    if not isinstance(details, str):
        details = json.dumps(details, ensure_ascii=False)
    con.execute("INSERT INTO audit(ts,actor,ip,action,target,details) VALUES(?,?,?,?,?,?)",
                (now(), actor, ip, action, target, details[:4000]))


_attempts: dict[str, list[float]] = {}


def rate_limit(key: str, limit: int = 8, window: int = 300) -> None:
    t = now()
    hits = [x for x in _attempts.get(key, []) if t - x < window]
    if len(hits) >= limit:
        raise HTTPException(429, "Too many attempts, try again in a few minutes")
    hits.append(t)
    _attempts[key] = hits


def _authenticate(request: Request) -> dict:
    """Resolve the session cookie to a user row (dict) and enforce the CSRF header on writes."""
    tok = request.cookies.get("kem_session")
    if not tok:
        raise HTTPException(401, "Not signed in")
    with db() as con:
        sess = con.execute("SELECT username, expires FROM sessions WHERE token_hash=?", (sha256(tok),)).fetchone()
        if not sess or sess["expires"] < now():
            raise HTTPException(401, "Session expired")
        urow = con.execute("SELECT * FROM users WHERE username=? AND disabled=0", (sess["username"],)).fetchone()
    if not urow:
        raise HTTPException(401, "Account disabled")
    # CSRF guard: a custom header cannot be sent cross-site without a CORS preflight (which we never allow).
    if request.method not in ("GET", "HEAD") and request.headers.get("x-kem") != "1":
        raise HTTPException(403, "Missing X-KEM header")
    return dict(urow)


def current_user(request: Request) -> dict:
    """Any authenticated user (teacher, school manager, admin...)."""
    return _authenticate(request)


def require_admin(request: Request) -> str:
    """Administrator-only endpoints (org, users, gateways, tokens, settings, audit)."""
    u = _authenticate(request)
    if u["role"] not in ADMIN_ROLES:
        raise HTTPException(403, "Administrator access required")
    return u["username"]


def require_admin_user(request: Request) -> dict:
    """Like require_admin but returns the full user dict (for scope-aware admin endpoints)."""
    u = _authenticate(request)
    if u["role"] not in ADMIN_ROLES:
        raise HTTPException(403, "Administrator access required")
    return u


def require_superadmin(request: Request) -> dict:
    u = _authenticate(request)
    if u["role"] != "superadmin":
        raise HTTPException(403, "This action requires the platform owner (superadmin)")
    return u


# ---- scoping: which labs (and thus devices) a user may see / act on --------------------

def allowed_lab_ids(con, user: dict):
    """Return a set of lab ids the user is scoped to, or None meaning 'all labs' (global)."""
    role, st, sid = user["role"], user["scope_type"], user["scope_id"]
    if role == "superadmin" or (role == "municipality_admin" and st == "global"):
        return None
    if role == "municipality_admin":
        return {r["id"] for r in con.execute(
            "SELECT l.id FROM labs l JOIN schools s ON s.id=l.school_id WHERE s.municipality_id=?", (sid,))}
    if role == "school_manager":
        return {r["id"] for r in con.execute("SELECT id FROM labs WHERE school_id=?", (sid,))}
    if role == "teacher":
        return {sid} if sid else set()
    return set()


def sees_unassigned(user: dict) -> bool:
    """Only global admins see devices/gateways not yet placed in a lab (so they can place them)."""
    return user["role"] == "superadmin" or (user["role"] == "municipality_admin" and user["scope_type"] == "global")


def device_in_scope(con, user: dict, lab_id) -> bool:
    allowed = allowed_lab_ids(con, user)
    if allowed is None:
        return True
    return bool(lab_id) and lab_id in allowed


def has_active_class(con, user: dict, lab_id) -> bool:
    if user["role"] != "teacher":
        return True
    return bool(con.execute(
        "SELECT 1 FROM teacher_sessions WHERE user_id=? AND lab_id=? AND ended IS NULL",
        (user["id"], lab_id)).fetchone())


def scope_label(con, user: dict) -> str:
    st, sid = user["scope_type"], user["scope_id"]
    if st == "global" or not sid:
        return "All municipalities" if user["role"] == "superadmin" else "Unscoped"
    table = {"municipality": "municipalities", "school": "schools", "lab": "labs"}.get(st)
    if not table:
        return ""
    row = con.execute(f"SELECT name FROM {table} WHERE id=?", (sid,)).fetchone()
    return row["name"] if row else "(deleted)"


def agent_device(request: Request) -> dict:
    did = request.headers.get("x-device-id", "")
    secret = request.headers.get("x-device-secret", "")
    with db() as con:
        row = con.execute("SELECT id, hostname, secret_hash FROM devices WHERE id=?", (did,)).fetchone()
    if not row or not secret or not hmac.compare_digest(row["secret_hash"], sha256(secret)):
        raise HTTPException(401, "Unknown device or bad secret")
    return dict(row)


def gateway_identity(con, request: Request) -> dict | None:
    """Optional gateway attribution on an agent request relayed through a Teacher Gateway.

    The student agent still presents its own device secret; the gateway adds its own
    credentials so the server learns which gateway (and therefore which lab) relayed it.
    An invalid gateway header is ignored (the request is treated as direct)."""
    gid = request.headers.get("x-gateway-id", "")
    secret = request.headers.get("x-gateway-secret", "")
    if not gid or not secret:
        return None
    row = con.execute("SELECT id, lab_id, secret_hash FROM gateways WHERE id=?", (gid,)).fetchone()
    if not row or not hmac.compare_digest(row["secret_hash"], sha256(secret)):
        return None
    con.execute("UPDATE gateways SET last_seen=? WHERE id=?", (now(), gid))
    return dict(row)


def gateway_auth(request: Request) -> dict:
    """Gateway-only endpoints (the gateway's own heartbeat / task pull)."""
    gid = request.headers.get("x-gateway-id", "")
    secret = request.headers.get("x-gateway-secret", "")
    with db() as con:
        row = con.execute("SELECT * FROM gateways WHERE id=?", (gid,)).fetchone()
    if not row or not secret or not hmac.compare_digest(row["secret_hash"], sha256(secret)):
        raise HTTPException(401, "Unknown gateway or bad secret")
    return dict(row)


def jload(s: str | None, default: Any) -> Any:
    try:
        return json.loads(s) if s else default
    except (TypeError, ValueError):
        return default


def pct(used: float | None, total: float | None) -> float | None:
    if not total:
        return None
    return round(100.0 * (used or 0) / total, 1)


def device_metrics(tel: dict) -> tuple[float | None, float | None, float | None]:
    cpu = tel.get("cpu_pct")
    mem_total, mem_free = tel.get("mem_total_mb"), tel.get("mem_free_mb")
    mem = pct((mem_total or 0) - (mem_free or 0), mem_total) if mem_total else None
    disk = None
    for d in tel.get("disks") or []:
        if not isinstance(d, dict) or not d.get("size_gb"):
            continue
        p = pct(d["size_gb"] - (d.get("free_gb") or 0), d["size_gb"])
        if str(d.get("drive", "")).upper().startswith(str(tel.get("system_drive", "C:")).upper()) or disk is None:
            disk = p
    return cpu, mem, disk


def update_summary(upd: dict, at: float | None) -> dict:
    items = upd.get("updates") if isinstance(upd.get("updates"), list) else []
    return {"total": len(items), "security": sum(1 for u in items if isinstance(u, dict) and u.get("security")),
            "reboot_required": bool(upd.get("reboot_required")), "at": at, "error": upd.get("error") or ""}


def device_alerts(row, tel: dict, inv: dict, online: bool, upd: dict | None = None) -> list[dict]:
    # Each alert keeps a stable English `text` (its identity for alert_state / incidents / notifications)
    # plus a `code` and `params` the dashboard uses to show the message in the viewer's language.
    alerts = []
    t = now()
    if row["last_seen"] and not online and t - row["last_seen"] > 3 * 86400:
        alerts.append({"level": "warn", "text": "Offline for more than 3 days", "code": "offline_3d", "params": {}})
    for d in tel.get("disks") or []:
        if isinstance(d, dict) and d.get("size_gb") and (d.get("free_gb") or 0) / d["size_gb"] < 0.10:
            alerts.append({"level": "crit", "text": f"Low disk space on {d.get('drive')}", "code": "low_disk", "params": {"drive": d.get("drive")}})
    av = inv.get("defender") or {}
    if av:
        if av.get("realtime") is False:
            alerts.append({"level": "crit", "text": "Defender real-time protection off", "code": "defender_off", "params": {}})
        age = av.get("signature_age_days")
        if isinstance(age, (int, float)) and age > 7:
            alerts.append({"level": "warn", "text": f"AV signatures {int(age)} days old", "code": "av_sig", "params": {"days": int(age)}})
    for prof in inv.get("firewall") or []:
        if isinstance(prof, dict) and prof.get("enabled") is False:
            alerts.append({"level": "warn", "text": f"Firewall off ({prof.get('name')})", "code": "fw_off", "params": {"name": prof.get("name")}})
            break
    sec = update_summary(upd or {}, None)["security"]
    if sec:
        alerts.append({"level": "warn", "text": f"{sec} security update{'s' if sec > 1 else ''} missing", "code": "sec_updates", "params": {"n": sec}})
    if inv.get("pending_reboot"):
        alerts.append({"level": "info", "text": "Reboot pending", "code": "reboot_pending", "params": {}})
    return alerts


def serialize_device(row, full: bool = False) -> dict:
    tel = jload(row["telemetry"], {})
    inv = jload(row["inventory"], {})
    upd = jload(row["updates"], {})
    online = bool(row["last_seen"] and now() - row["last_seen"] < ONLINE_SECONDS)
    cpu, mem, disk = device_metrics(tel)
    out = {
        "id": row["id"], "hostname": row["hostname"], "group": row["group_name"] or "",
        "notes": row["notes"] or "", "enrolled": row["enrolled"], "last_seen": row["last_seen"],
        "online": online, "public_ip": row["public_ip"], "agent_version": row["agent_version"],
        "isolated": bool(row["isolated"]), "user": tel.get("user") or "",
        "ips": tel.get("ips") or [], "os": inv.get("os_name") or "", "os_version": inv.get("display_version") or "",
        "model": " ".join(x for x in [inv.get("manufacturer"), inv.get("model")] if x),
        "chassis": inv.get("chassis") or "", "cpu": cpu, "mem": mem, "disk": disk,
        "busy": tel.get("busy"), "alerts": device_alerts(row, tel, inv, online, upd),
        "updates": update_summary(upd, row["updates_at"]),
        "web_filter": tel.get("web_filter") or 0, "usb": tel.get("usb_mode") or "",
        "agent_outdated": vtuple(row["agent_version"]) < vtuple(AGENT_RELEASE["version"]),
        "lab_id": row["lab_id"], "gateway_id": row["gateway_id"],
    }
    if full:
        out.update({"telemetry": tel, "inventory": inv, "inventory_at": row["inventory_at"],
                    "software": jload(row["software"], []), "software_at": row["software_at"],
                    "update_list": upd.get("updates") or [],
                    "ai_diagnosis": row["ai_diagnosis"], "ai_diagnosis_at": row["ai_diagnosis_at"]})
    return out


def serialize_command(row) -> dict:
    d = dict(row)
    d["params"] = jload(d.get("params"), {})
    if "data" in d:
        d["has_data"] = bool(d.pop("data"))
    return d


def place_map(con) -> dict:
    """lab_id -> {lab, school_id, school, municipality_id, municipality} for labelling devices."""
    out: dict[str, dict] = {}
    for r in con.execute(
            "SELECT l.id lab_id, l.name lab, s.id school_id, s.name school, "
            "m.id municipality_id, m.name municipality "
            "FROM labs l LEFT JOIN schools s ON s.id=l.school_id "
            "LEFT JOIN municipalities m ON m.id=s.municipality_id").fetchall():
        out[r["lab_id"]] = dict(r)
    return out


def attach_place(d: dict, pmap: dict, gw_names: dict | None = None) -> dict:
    p = pmap.get(d.get("lab_id")) if d.get("lab_id") else None
    d["place"] = p or {"lab": "", "school": "", "municipality": ""}
    if gw_names is not None:
        d["gateway"] = gw_names.get(d.get("gateway_id"), "")
    return d


# ---------------------------------------------------------------- command validation

def _int(p: dict, key: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(p.get(key, default))
    except (TypeError, ValueError):
        raise HTTPException(400, f"'{key}' must be a number")
    if not lo <= v <= hi:
        raise HTTPException(400, f"'{key}' must be between {lo} and {hi}")
    return v


def _winget_id(p: dict) -> str:
    pid = clean(p.get("package_id"), 128)
    if not WINGET_ID.match(pid):
        raise HTTPException(400, "Invalid winget package id (example: Google.Chrome)")
    return pid


def validate_params(ctype: str, p: Any) -> dict:
    if ctype not in COMMAND_TYPES:
        raise HTTPException(400, f"Unknown command type '{ctype}'")
    if not isinstance(p, dict):
        raise HTTPException(400, "params must be an object")
    if ctype == "block_internet":
        return {"allow_lan": bool(p.get("allow_lan"))}
    if ctype in ("unblock_internet", "refresh_inventory", "create_baseline", "uninstall_agent"):
        return {}
    if ctype == "install_software":
        method = p.get("method")
        if method == "winget":
            return {"method": "winget", "package_id": _winget_id(p)}
        if method == "url":
            url = clean(p.get("url"), 2000)
            if not re.match(r"^https?://[^\s]+$", url):
                raise HTTPException(400, "Installer URL must start with https:// (or http://)")
            args = clean(p.get("args"), 1000)
            if "\n" in args or "\r" in args:
                raise HTTPException(400, "Installer arguments must be a single line")
            sha = clean(p.get("sha256"), 64).lower()
            if sha and not re.fullmatch(r"[0-9a-f]{64}", sha):
                raise HTTPException(400, "SHA-256 must be 64 hex characters")
            return {"method": "url", "url": url, "args": args, "sha256": sha}
        raise HTTPException(400, "method must be 'winget' or 'url'")
    if ctype == "uninstall_software":
        if p.get("package_id") not in (None, ""):
            return {"package_id": _winget_id(p)}
        name = clean(p.get("name"), 200)
        if not name:
            raise HTTPException(400, "Give a winget package id or a program name to uninstall")
        return {"name": name}
    if ctype == "run_script":
        script = str(p.get("script") or "")
        if not script.strip() or len(script) > 50_000:
            raise HTTPException(400, "Script must be 1-50,000 characters")
        return {"script": script, "timeout": _int(p, "timeout", 600, 10, 7200)}
    if ctype == "reboot":
        return {"delay": _int(p, "delay", 60, 0, 3600), "message": clean(p.get("message"), 200)}
    if ctype == "defender_scan":
        scan = p.get("scan_type", "quick")
        if scan not in ("quick", "full"):
            raise HTTPException(400, "scan_type must be quick or full")
        return {"scan_type": scan}
    if ctype == "reset_device":
        mode = p.get("mode")
        if mode not in RESET_MODES:
            raise HTTPException(400, f"mode must be one of {sorted(RESET_MODES)}")
        return {"mode": mode}
    if ctype in ("scan_updates", "list_processes", "list_services", "update_agent"):
        return {}
    if ctype == "install_updates":
        scope = p.get("scope", "security")
        if scope not in ("security", "all", "selected"):
            raise HTTPException(400, "scope must be security, all or selected")
        ids = p.get("update_ids") or []
        if scope == "selected":
            if not isinstance(ids, list) or not 1 <= len(ids) <= 200 or not all(isinstance(i, str) and GUID.match(i) for i in ids):
                raise HTTPException(400, "Select at least one update")
        reboot = p.get("reboot", "if_needed")
        if reboot not in ("never", "if_needed"):
            raise HTTPException(400, "reboot must be never or if_needed")
        return {"scope": scope, "update_ids": ids if scope == "selected" else [],
                "include_drivers": bool(p.get("include_drivers")), "reboot": reboot,
                "reboot_delay": _int(p, "reboot_delay", 600, 60, 7200)}
    if ctype == "set_web_filter":
        raw = p.get("domains") or []
        if not isinstance(raw, list) or len(raw) > 2000:
            raise HTTPException(400, "domains must be a list (max 2000)")
        domains: list[str] = []
        for d in raw:
            d = re.sub(r"^[a-z]+://", "", str(d).strip().lower()).split("/")[0].split(":")[0].lstrip("*.").rstrip(".")
            if not d:
                continue
            if not DOMAIN.match(d):
                raise HTTPException(400, f"'{d}' is not a valid domain name")
            if d not in domains:
                domains.append(d)
        return {"domains": domains}
    if ctype == "usb_storage":
        mode = p.get("mode")
        if mode not in ("allow", "read_only", "block"):
            raise HTTPException(400, "mode must be allow, read_only or block")
        return {"mode": mode}
    if ctype == "distribute_file":
        url = clean(p.get("url"), 2000)
        if not re.match(r"^https?://[^\s]+$", url):
            raise HTTPException(400, "File URL must start with https:// (or http://)")
        dest = clean(p.get("dest"), 400)
        if not re.match(r"^[A-Za-z]:\\", dest) or "\n" in dest or "\r" in dest:
            raise HTTPException(400, "Destination must be a full Windows folder path, e.g. C:\\Lab\\Handouts")
        if ".." in dest:
            raise HTTPException(400, "Destination path may not contain '..'")
        if re.match(r"(?i)^[A-Za-z]:\\(windows|program files)", dest):
            raise HTTPException(400, "Choose a non-system folder (not Windows or Program Files)")
        filename = clean(p.get("filename"), 200)
        if filename and not re.fullmatch(r'[^<>:"/\\|?*\x00]{1,200}', filename):
            raise HTTPException(400, "Invalid file name")
        sha = clean(p.get("sha256"), 64).lower()
        if sha and not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise HTTPException(400, "SHA-256 must be 64 hex characters")
        return {"url": url, "dest": dest, "filename": filename, "sha256": sha, "overwrite": bool(p.get("overwrite"))}
    if ctype == "set_app_policy":
        mode = p.get("mode")
        if mode not in ("audit", "enforce", "off"):
            raise HTTPException(400, "mode must be audit, enforce or off")
        raw = p.get("rules") or []
        if not isinstance(raw, list) or len(raw) > 500:
            raise HTTPException(400, "rules must be a list (max 500)")
        rules = []
        for r in raw:
            if not isinstance(r, dict):
                raise HTTPException(400, "each rule must be an object")
            rt = r.get("type")
            if rt not in ("path", "filename"):
                raise HTTPException(400, "rule type must be 'path' or 'filename'")
            val = clean(r.get("value"), 400)
            if not val or "\n" in val or "\r" in val:
                raise HTTPException(400, "each rule needs a one-line value")
            if rt == "filename" and not re.fullmatch(r'[^<>:"/\\|?*\x00]{1,200}', val):
                raise HTTPException(400, f"'{val}' is not a valid file name")
            if rt == "path" and not re.match(r"^([A-Za-z]:\\|%[A-Za-z0-9_()]+%|\*)", val):
                raise HTTPException(400, f"path rule must start with a drive, %VAR% or * ('{val}')")
            rules.append({"type": rt, "value": val})
        if mode != "off" and not rules:
            raise HTTPException(400, "Add at least one allow rule, or choose 'off' to remove the policy")
        return {"mode": mode, "rules": rules}
    if ctype == "launch_app":
        target = p.get("target")
        if target not in ("app", "url"):
            raise HTTPException(400, "target must be 'app' or 'url'")
        val = clean(p.get("value"), 2000)
        if not val:
            raise HTTPException(400, "A program path or URL is required")
        if target == "url":
            if not re.match(r"^https?://[^\s]+$", val):
                raise HTTPException(400, "url must start with https:// or http://")
            return {"target": "url", "value": val, "args": ""}
        if not re.match(r"^([A-Za-z]:\\|%[A-Za-z0-9_()]+%)", val) or "\n" in val or "\r" in val:
            raise HTTPException(400, "app must be a full Windows path, e.g. C:\\Program Files\\App\\app.exe")
        args = clean(p.get("args"), 1000)
        if "\n" in args or "\r" in args:
            raise HTTPException(400, "args must be a single line")
        return {"target": "app", "value": val, "args": args}
    if ctype == "kill_process":
        if p.get("pid") not in (None, ""):
            return {"pid": _int(p, "pid", 0, 5, 2**31 - 1)}
        name = clean(p.get("name"), 100)
        if name.lower().endswith(".exe"):
            name = name[:-4]
        if not PROCESS_NAME.match(name):
            raise HTTPException(400, "Give a process id or a process name (e.g. chrome)")
        if name.lower() in ("csrss", "wininit", "winlogon", "lsass", "smss", "services", "system", "svchost", "powershell"):
            raise HTTPException(400, f"Refusing to kill critical process '{name}'")
        return {"name": name}
    if ctype == "service_action":
        name = clean(p.get("name"), 100)
        if not SERVICE_NAME.match(name):
            raise HTTPException(400, "Invalid service name")
        action = p.get("action")
        if action not in ("start", "stop", "restart", "none"):
            raise HTTPException(400, "action must be start, stop or restart")
        startup = p.get("startup") or ""
        if startup not in ("", "automatic", "manual", "disabled"):
            raise HTTPException(400, "startup must be automatic, manual or disabled")
        if action == "none" and not startup:
            raise HTTPException(400, "Nothing to do")
        return {"name": name, "action": action, "startup": startup}
    if ctype == "send_message":
        text = str(p.get("text") or "").strip()
        if not 1 <= len(text) <= 1000:
            raise HTTPException(400, "Message must be 1-1000 characters")
        return {"title": clean(p.get("title"), 80) or "Message from IT", "text": text}
    if ctype == "lock_session":
        action = p.get("action", "lock")
        if action not in ("lock", "logoff"):
            raise HTTPException(400, "action must be lock or logoff")
        return {"action": action}
    raise HTTPException(400, "Unsupported command")


# ---------------------------------------------------------------- pages & agent files

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(BASE / "static" / "index.html", headers={"Cache-Control": "no-store"})


@app.get("/agent/{name}", include_in_schema=False)
def agent_file(name: str):
    if name not in AGENT_FILES:
        raise HTTPException(404)
    return FileResponse(AGENT_DIR / name, media_type="text/plain; charset=utf-8",
                        headers={"Cache-Control": "no-store"})


@app.get("/healthz")
def healthz():
    return {"ok": True, "version": APP_VERSION}


# ---------------------------------------------------------------- admin auth

@app.post("/api/login")
def login(request: Request, response: Response, body: dict = Body(...)):
    ip = client_ip(request)
    rate_limit(f"login:{ip}")
    user, pw = clean(body.get("username"), 64), str(body.get("password") or "")
    with db() as con:
        urow = con.execute("SELECT * FROM users WHERE username=? AND disabled=0", (user,)).fetchone()
        ok = bool(urow) and verify_password(pw, urow["pw_hash"])
        audit(con, user or "?", ip, "login" if ok else "login_failed")
        if not ok:
            raise HTTPException(401, "Wrong username or password")
        tok = secrets.token_urlsafe(32)
        con.execute("DELETE FROM sessions WHERE expires<?", (now(),))
        con.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", (sha256(tok), user, now(), now() + SESSION_HOURS * 3600, ip))
        con.execute("UPDATE users SET last_login=? WHERE id=?", (now(), urow["id"]))
    _attempts.pop(f"login:{ip}", None)
    response.set_cookie("kem_session", tok, max_age=SESSION_HOURS * 3600, httponly=True,
                        samesite="strict", secure=is_https(request))
    return {"ok": True}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    tok = request.cookies.get("kem_session")
    if tok:
        with db() as con:
            con.execute("DELETE FROM sessions WHERE token_hash=?", (sha256(tok),))
    response.delete_cookie("kem_session")
    return {"ok": True}


@app.get("/api/me")
def me(user: dict = Depends(current_user)):
    with db() as con:
        label = scope_label(con, user)
    return {"user": user["username"], "display_name": user["display_name"] or user["username"],
            "role": user["role"], "scope_type": user["scope_type"], "scope_id": user["scope_id"],
            "scope_label": label, "capabilities": role_capabilities(user["role"]),
            "version": APP_VERSION, "interval": CHECKIN_INTERVAL, "online_seconds": ONLINE_SECONDS}


@app.post("/api/password")
def change_password(request: Request, body: dict = Body(...), user: dict = Depends(current_user)):
    new = str(body.get("new") or "")
    if len(new) < 10:
        raise HTTPException(400, "New password must be at least 10 characters")
    with db() as con:
        urow = con.execute("SELECT pw_hash FROM users WHERE id=?", (user["id"],)).fetchone()
        if not verify_password(str(body.get("current") or ""), urow["pw_hash"]):
            raise HTTPException(400, "Current password is wrong")
        h = hash_password(new)
        con.execute("UPDATE users SET pw_hash=? WHERE id=?", (h, user["id"]))
        if user["role"] == "superadmin":
            set_setting(con, "admin_hash", h)  # keep the legacy setting in sync for the bootstrap admin
        con.execute("DELETE FROM sessions WHERE username=? AND token_hash<>?",
                    (user["username"], sha256(request.cookies.get("kem_session", ""))))
        audit(con, user["username"], client_ip(request), "password_changed")
    (DATA / "initial_admin_password.txt").unlink(missing_ok=True)
    return {"ok": True}


# ---------------------------------------------------------------- devices

@app.get("/api/devices")
def list_devices(user: dict = Depends(current_user)):
    with db() as con:
        rows = con.execute("SELECT * FROM devices ORDER BY hostname COLLATE NOCASE").fetchall()
        allowed = allowed_lab_ids(con, user)
        show_unassigned = sees_unassigned(user)
        pmap = place_map(con)
        gw = {r["id"]: r["hostname"] for r in con.execute("SELECT id, hostname FROM gateways")}
    out = []
    for r in rows:
        if allowed is not None:
            if r["lab_id"] is None and not show_unassigned:
                continue
            if r["lab_id"] is not None and r["lab_id"] not in allowed:
                continue
        out.append(attach_place(serialize_device(r), pmap, gw))
    return out


@app.get("/api/devices/{device_id}")
def get_device(device_id: str, user: dict = Depends(current_user)):
    with db() as con:
        row = con.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if not row or not device_in_scope(con, user, row["lab_id"]):
            raise HTTPException(404, "Device not found")
        cmds = con.execute("SELECT c.id,c.device_id,c.type,c.params,c.status,c.created,c.sent,c.finished,c.output,c.exit_code,c.created_by,(c.data IS NOT NULL) AS data FROM commands c WHERE c.device_id=? ORDER BY c.id DESC LIMIT 100", (device_id,)).fetchall()
        mets = con.execute("SELECT ts,cpu,mem,disk FROM metrics WHERE device_id=? AND ts>? ORDER BY ts",
                           (device_id, now() - 24 * 3600)).fetchall()
        pmap = place_map(con)
        gw = {r["id"]: r["hostname"] for r in con.execute("SELECT id, hostname FROM gateways")}
    _viewing[device_id] = now()
    d = attach_place(serialize_device(row, full=True), pmap, gw)
    d["commands"] = [serialize_command(c) for c in cmds]
    d["metrics"] = [dict(m) for m in mets]
    return d


@app.patch("/api/devices/{device_id}")
def update_device(device_id: str, request: Request, body: dict = Body(...), user: dict = Depends(current_user)):
    with db() as con:
        row = con.execute("SELECT lab_id FROM devices WHERE id=?", (device_id,)).fetchone()
        if not row or not device_in_scope(con, user, row["lab_id"]):
            raise HTTPException(404, "Device not found")
        con.execute("UPDATE devices SET group_name=?, notes=? WHERE id=?",
                    (clean(body.get("group"), 64), clean(body.get("notes"), 2000), device_id))
        # Assigning a device to a lab (placing a station) is an administrator action.
        if "lab_id" in body:
            if user["role"] not in ADMIN_ROLES:
                raise HTTPException(403, "Only administrators can move a device to a lab")
            new_lab = clean(body.get("lab_id"), 32) or None
            if new_lab:
                lab = con.execute("SELECT id FROM labs WHERE id=?", (new_lab,)).fetchone()
                if not lab or not device_in_scope(con, user, new_lab):
                    raise HTTPException(400, "Unknown lab or outside your scope")
            elif not sees_unassigned(user):
                raise HTTPException(403, "You cannot unassign a device")
            con.execute("UPDATE devices SET lab_id=? WHERE id=?", (new_lab, device_id))
            audit(con, user["username"], client_ip(request), "device_placed", device_id, {"lab_id": new_lab})
        audit(con, user["username"], client_ip(request), "device_updated", device_id, {"group": body.get("group")})
    return {"ok": True}


@app.delete("/api/devices/{device_id}")
def forget_device(device_id: str, request: Request, user: dict = Depends(require_admin_user)):
    with db() as con:
        row = con.execute("SELECT hostname, lab_id FROM devices WHERE id=?", (device_id,)).fetchone()
        if not row or not device_in_scope(con, user, row["lab_id"]):
            raise HTTPException(404, "Device not found")
        for table in ("devices", "commands", "metrics"):
            col = "id" if table == "devices" else "device_id"
            con.execute(f"DELETE FROM {table} WHERE {col}=?", (device_id,))
        audit(con, user["username"], client_ip(request), "device_forgotten", row["hostname"])
    return {"ok": True}


# ---------------------------------------------------------------- commands

@app.post("/api/commands")
def create_commands(request: Request, body: dict = Body(...), user: dict = Depends(current_user)):
    ids = body.get("device_ids")
    if not isinstance(ids, list) or not ids or len(ids) > 1000:
        raise HTTPException(400, "device_ids must be a non-empty list")
    ids = list(dict.fromkeys(str(i) for i in ids))
    ctype = str(body.get("type") or "")
    if ctype in COMMAND_TYPES and not role_can_issue(user["role"], ctype):
        raise HTTPException(403, f"Your role is not allowed to issue '{ctype}'")
    params = validate_params(ctype, body.get("params") or {})
    with db() as con:
        marks = ",".join("?" * len(ids))
        devices = con.execute(f"SELECT id, hostname, lab_id FROM devices WHERE id IN ({marks})", ids).fetchall()
        if len(devices) != len(ids):
            raise HTTPException(404, "One or more devices not found")
        for d in devices:
            if not device_in_scope(con, user, d["lab_id"]):
                raise HTTPException(403, "One or more devices are outside your scope")
            if not has_active_class(con, user, d["lab_id"]):
                raise HTTPException(403, "Start a class session on this lab before sending classroom commands")
        if ctype in CONFIRM_TYPES:
            if len(devices) != 1:
                raise HTTPException(400, "This action can only target one device at a time")
            if clean(body.get("confirm"), 64).lower() != (devices[0]["hostname"] or "").lower():
                raise HTTPException(400, "Type the device hostname exactly to confirm")
        created = []
        for d in devices:
            cur = con.execute(
                "INSERT INTO commands(device_id,type,params,status,created,created_by,via_role) VALUES(?,?,?,?,?,?,?)",
                (d["id"], ctype, json.dumps(params, ensure_ascii=False), "queued", now(), user["username"], user["role"]))
            created.append(cur.lastrowid)
            logged = {k: (v if k != "script" else f"<{len(v)} chars>") for k, v in params.items()}
            audit(con, user["username"], client_ip(request), f"command:{ctype}", d["hostname"], logged)
    return {"created": created}


_CMD_COLS = ("SELECT c.id,c.device_id,c.type,c.params,c.status,c.created,c.sent,c.finished,"
             "c.output,c.exit_code,c.created_by,c.via_role,(c.data IS NOT NULL) AS data, d.hostname, d.lab_id "
             "FROM commands c LEFT JOIN devices d ON d.id=c.device_id ")


@app.get("/api/commands")
def list_commands(device_id: str = "", limit: int = 200, user: dict = Depends(current_user)):
    limit = max(1, min(limit, 1000))
    with db() as con:
        allowed = allowed_lab_ids(con, user)
        if device_id:
            drow = con.execute("SELECT lab_id FROM devices WHERE id=?", (device_id,)).fetchone()
            if not drow or not device_in_scope(con, user, drow["lab_id"]):
                raise HTTPException(404, "Device not found")
            rows = con.execute(_CMD_COLS + "WHERE c.device_id=? ORDER BY c.id DESC LIMIT ?",
                               (device_id, limit)).fetchall()
        else:
            rows = con.execute(_CMD_COLS + "ORDER BY c.id DESC LIMIT ?",
                               (limit if allowed is None else 2000,)).fetchall()
    out = []
    for r in rows:
        if allowed is not None and (r["lab_id"] is None or r["lab_id"] not in allowed):
            continue
        rr = serialize_command(r)
        rr.pop("lab_id", None)
        out.append(rr)
        if len(out) >= limit:
            break
    return out


def _command_with_data(cmd_id: int) -> tuple[dict, Any]:
    with db() as con:
        row = con.execute("SELECT c.*, d.hostname FROM commands c LEFT JOIN devices d ON d.id=c.device_id WHERE c.id=?",
                          (cmd_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Command not found")
    d = dict(row)
    data = jload(d.pop("data", None), None)
    d["params"] = jload(d.get("params"), {})
    d["has_data"] = data is not None
    return d, data


@app.get("/api/commands/{cmd_id}")
def get_command(cmd_id: int, user: dict = Depends(current_user)):
    d, data = _command_with_data(cmd_id)
    with db() as con:
        drow = con.execute("SELECT lab_id FROM devices WHERE id=?", (d["device_id"],)).fetchone()
        if not drow or not device_in_scope(con, user, drow["lab_id"]):
            raise HTTPException(404, "Command not found")
    d["data"] = data
    return d


@app.post("/api/commands/{cmd_id}/cancel")
def cancel_command(cmd_id: int, request: Request, user: dict = Depends(current_user)):
    with db() as con:
        crow = con.execute("SELECT c.device_id, d.lab_id FROM commands c LEFT JOIN devices d ON d.id=c.device_id "
                           "WHERE c.id=?", (cmd_id,)).fetchone()
        if not crow or not device_in_scope(con, user, crow["lab_id"]):
            raise HTTPException(404, "Command not found")
        cur = con.execute("UPDATE commands SET status='cancelled', finished=? WHERE id=? AND status='queued'", (now(), cmd_id))
        if not cur.rowcount:
            raise HTTPException(400, "Only queued commands can be cancelled")
        audit(con, user["username"], client_ip(request), "command_cancelled", str(cmd_id))
    return {"ok": True}


# ---------------------------------------------------------------- registration tokens

def new_token() -> str:
    return "-".join("".join(secrets.choice(TOKEN_ALPHABET) for _ in range(4)) for _ in range(3))


@app.get("/api/tokens")
def list_tokens(user: dict = Depends(require_admin_user)):
    with db() as con:
        rows = con.execute("SELECT * FROM tokens ORDER BY id DESC").fetchall()
        allowed = allowed_lab_ids(con, user)
        pmap = place_map(con)
    t = now()
    out = []
    for r in rows:
        if allowed is not None and (r["lab_id"] is None or r["lab_id"] not in allowed):
            continue
        d = dict(r)
        d["active"] = not r["revoked"] and (not r["expires"] or r["expires"] > t) and (not r["max_uses"] or r["uses"] < r["max_uses"])
        d["lab_name"] = pmap.get(r["lab_id"], {}).get("lab", "") if r["lab_id"] else ""
        out.append(d)
    return out


@app.post("/api/tokens")
def create_token(request: Request, body: dict = Body(...), user: dict = Depends(require_admin_user)):
    hours = _int(body, "hours", 72, 0, 24 * 365)
    max_uses = _int(body, "max_uses", 0, 0, 100_000)
    kind = body.get("kind", "device")
    if kind not in ("device", "gateway"):
        raise HTTPException(400, "kind must be device or gateway")
    lab_id = clean(body.get("lab_id"), 32) or None
    with db() as con:
        if lab_id:
            if not con.execute("SELECT 1 FROM labs WHERE id=?", (lab_id,)).fetchone() or not device_in_scope(con, user, lab_id):
                raise HTTPException(400, "Unknown lab or outside your scope")
        elif kind == "gateway":
            raise HTTPException(400, "A gateway token must be tied to a lab")
        elif not sees_unassigned(user):
            raise HTTPException(400, "Choose a lab for this enrollment token")
        tok = new_token()
        con.execute("INSERT INTO tokens(token,label,group_name,created,expires,max_uses,kind,lab_id) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (tok, clean(body.get("label"), 80), clean(body.get("group"), 64), now(),
                     now() + hours * 3600 if hours else None, max_uses, kind, lab_id))
        audit(con, user["username"], client_ip(request), "token_created", tok,
              {"hours": hours, "max_uses": max_uses, "kind": kind, "lab_id": lab_id})
    return {"token": tok, "kind": kind}


@app.delete("/api/tokens/{token_id}")
def revoke_token(token_id: int, request: Request, user: dict = Depends(require_admin_user)):
    with db() as con:
        row = con.execute("SELECT lab_id FROM tokens WHERE id=?", (token_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Token not found")
        if not sees_unassigned(user) and (row["lab_id"] is None or not device_in_scope(con, user, row["lab_id"])):
            raise HTTPException(403, "Outside your scope")
        con.execute("UPDATE tokens SET revoked=1 WHERE id=?", (token_id,))
        audit(con, user["username"], client_ip(request), "token_revoked", str(token_id))
    return {"ok": True}


@app.get("/api/audit")
def list_audit(limit: int = 300, admin: str = Depends(require_admin)):
    with db() as con:
        rows = con.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (max(1, min(limit, 2000)),)).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------- server settings & notifications

def public_settings(con) -> dict:
    cfg = notify_config(con)
    out = {k: v for k, v in cfg.items() if k not in ("smtp_pass", "ai_api_key")}
    out["smtp_pass_set"] = bool(cfg["smtp_pass"])
    out["ai_api_key_set"] = bool(cfg["ai_api_key"])
    out["ai_enabled"] = cfg["ai_enabled"] == "1"
    out["notify_events"] = jload(cfg["notify_events"], [])
    out["event_names"] = NOTIFY_EVENTS
    out["agent_version"] = AGENT_RELEASE["version"]
    return out


@app.get("/api/settings")
def get_settings(admin: str = Depends(require_admin)):
    with db() as con:
        return public_settings(con)


@app.put("/api/settings")
def put_settings(request: Request, body: dict = Body(...), admin: str = Depends(require_admin)):
    vals: dict[str, str] = {}
    hook = clean(body.get("notify_webhook"), 1000)
    if hook and not re.match(r"^https://[^\s]+$", hook):
        raise HTTPException(400, "Webhook URL must start with https://")
    vals["notify_webhook"] = hook
    emails = [e.strip() for e in re.split(r"[,;\s]+", clean(body.get("notify_email"), 500)) if e.strip()]
    if any(not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", e) for e in emails):
        raise HTTPException(400, "Notification e-mail: enter one or more valid addresses, comma separated")
    vals["notify_email"] = ", ".join(emails)
    vals["smtp_host"] = clean(body.get("smtp_host"), 200)
    vals["smtp_port"] = str(_int(body, "smtp_port", 587, 1, 65535))
    vals["smtp_user"] = clean(body.get("smtp_user"), 200)
    vals["smtp_from"] = clean(body.get("smtp_from"), 200)
    sec = body.get("smtp_security", "starttls")
    if sec not in ("starttls", "ssl", "none"):
        raise HTTPException(400, "smtp_security must be starttls, ssl or none")
    vals["smtp_security"] = sec
    if emails and not vals["smtp_host"]:
        raise HTTPException(400, "Enter the SMTP server to send e-mail")
    events = body.get("notify_events") or []
    if not isinstance(events, list) or any(e not in NOTIFY_EVENTS for e in events):
        raise HTTPException(400, "Unknown notification event")
    vals["notify_events"] = json.dumps(events)
    vals["notify_offline_hours"] = str(_int(body, "notify_offline_hours", 0, 0, 720))
    vals["auto_update_scan"] = "1" if body.get("auto_update_scan") else "0"
    vals["auto_update_agent"] = "1" if body.get("auto_update_agent") else "0"
    ai_url = clean(body.get("ai_base_url"), 500)
    if ai_url and not re.match(r"^https?://[^\s]+$", ai_url):
        raise HTTPException(400, "AI endpoint URL must start with http:// or https://")
    vals["ai_base_url"] = ai_url.rstrip("/")
    vals["ai_model"] = clean(body.get("ai_model"), 100)
    ai_on = bool(body.get("ai_enabled"))
    if ai_on and not (vals["ai_base_url"] and vals["ai_model"]):
        raise HTTPException(400, "Set the AI endpoint URL and model before enabling AI diagnostics")
    vals["ai_enabled"] = "1" if ai_on else "0"
    # Remember how admins reach the dashboard so notifications can link to devices.
    vals["public_url"] = f"{'https' if is_https(request) else 'http'}://{request.headers.get('host', '')}".rstrip("/")
    with db() as con:
        for k, v in vals.items():
            set_setting(con, k, v)
        if body.get("smtp_pass"):  # blank = keep the stored password
            set_setting(con, "smtp_pass", str(body["smtp_pass"])[:200])
        if body.get("clear_smtp_pass"):
            set_setting(con, "smtp_pass", "")
        if body.get("ai_api_key"):  # blank = keep the stored key
            set_setting(con, "ai_api_key", str(body["ai_api_key"])[:400])
        if body.get("clear_ai_api_key"):
            set_setting(con, "ai_api_key", "")
        audit(con, admin, client_ip(request), "settings_updated", "",
              {k: v for k, v in vals.items() if k not in ("notify_webhook",)})
        return public_settings(con)


@app.post("/api/settings/test-notification")
def test_notification(request: Request, admin: str = Depends(require_admin)):
    with db() as con:
        cfg = notify_config(con)
    if not (cfg["notify_webhook"] or (cfg["notify_email"] and cfg["smtp_host"])):
        raise HTTPException(400, "Save a webhook URL or e-mail settings first")
    errors = deliver(cfg, "[KEM] Test notification", f"Notifications from KEM work. Sent by {admin}.", cfg["public_url"])
    if errors:
        raise HTTPException(502, "; ".join(errors))
    return {"ok": True}


@app.get("/api/notifications")
def list_notifications(admin: str = Depends(require_admin)):
    with db() as con:
        return [dict(r) for r in con.execute("SELECT * FROM notifications ORDER BY id DESC LIMIT 100").fetchall()]


# ---------------------------------------------------------------- local AI diagnostics
# Sends a privacy-safe health snapshot of one device to an admin-configured OpenAI-compatible
# endpoint (Ollama / llama.cpp / LM Studio / vLLM, meant to run locally or on the LAN) and returns
# the model's written diagnosis. The reply is advice to show a technician, never commands to run.

AI_SYSTEM_PROMPT = (
    "You are an IT support assistant for a school computer lab. You receive one Windows endpoint's "
    "health and inventory data as JSON. Identify the most likely problems and give concise, concrete "
    "remediation steps a technician can follow, most important first. Prioritise security and "
    "data-loss risks. If the data looks healthy, say so plainly. Use only the data provided - do not "
    "invent details. Reply in short plain-text sections."
)


def ai_config(con) -> dict:
    return {"enabled": setting(con, "ai_enabled") == "1", "base_url": setting(con, "ai_base_url"),
            "model": setting(con, "ai_model"), "api_key": setting(con, "ai_api_key")}


def ai_chat(cfg: dict, system: str, user: str, max_tokens: int = 700) -> str:
    """Call an OpenAI-compatible /chat/completions endpoint. Raises HTTPException(502) on any failure."""
    url = cfg["base_url"].rstrip("/") + "/chat/completions"
    payload = {"model": cfg["model"], "temperature": 0.2, "stream": False, "max_tokens": max_tokens,
               "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    headers = {"Content-Type": "application/json", "User-Agent": f"KEM/{APP_VERSION}"}
    if cfg["api_key"]:
        headers["Authorization"] = "Bearer " + cfg["api_key"]
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        body = e.read(2000).decode("utf-8", "replace")
        raise HTTPException(502, f"AI endpoint returned HTTP {e.code}: {body[:300]}")
    except Exception as e:  # noqa: BLE001 - connection refused / timeout / DNS / bad JSON
        raise HTTPException(502, f"Could not reach the AI endpoint: {e}")
    try:
        text = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise HTTPException(502, "AI endpoint returned an unexpected response shape")
    if not isinstance(text, str) or not text.strip():
        raise HTTPException(502, "AI endpoint returned an empty response")
    return text.strip()


def ai_device_context(d: dict) -> dict:
    """A health snapshot for the model - deliberately no signed-in user, no IP/MAC/serial (privacy)."""
    tel = d.get("telemetry") or {}
    inv = d.get("inventory") or {}
    return {
        "hostname": d.get("hostname"), "os": d.get("os"), "os_version": d.get("os_version"),
        "model": d.get("model"), "online": d.get("online"), "agent_version": d.get("agent_version"),
        "cpu_percent": d.get("cpu"), "memory_percent": d.get("mem"), "disk_percent": d.get("disk"),
        "disks": [{"drive": x.get("drive"), "size_gb": x.get("size_gb"), "free_gb": x.get("free_gb")}
                  for x in (tel.get("disks") or []) if isinstance(x, dict)],
        "defender": inv.get("defender"), "firewall": inv.get("firewall"), "bitlocker": inv.get("bitlocker"),
        "pending_reboot": inv.get("pending_reboot"), "missing_updates": d.get("updates"),
        "alerts": [a.get("text") for a in (d.get("alerts") or [])],
    }


def require_diagnostics(request: Request) -> dict:
    u = _authenticate(request)
    if u["role"] not in ADMIN_ROLES and u["role"] != "school_manager":
        raise HTTPException(403, "Not allowed to run diagnostics")
    return u


@app.get("/api/ai/status")
def ai_status(user: dict = Depends(current_user)):
    with db() as con:
        cfg = ai_config(con)
    return {"enabled": cfg["enabled"], "configured": bool(cfg["base_url"] and cfg["model"]), "model": cfg["model"]}


@app.post("/api/ai/test")
def ai_test(admin: str = Depends(require_admin)):
    with db() as con:
        cfg = ai_config(con)
    if not (cfg["base_url"] and cfg["model"]):
        raise HTTPException(400, "Set the AI endpoint URL and model first")
    reply = ai_chat(cfg, "You are a connectivity check.", "Reply with the single word READY.", max_tokens=20)
    return {"ok": True, "model": cfg["model"], "reply": reply[:200]}


@app.post("/api/devices/{device_id}/diagnose")
def diagnose_device(device_id: str, request: Request, user: dict = Depends(require_diagnostics)):
    with db() as con:
        row = con.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if not row or not device_in_scope(con, user, row["lab_id"]):
            raise HTTPException(404, "Device not found")
        cfg = ai_config(con)
        if not cfg["enabled"]:
            raise HTTPException(400, "AI diagnostics are not enabled - configure them in Settings")
        d = serialize_device(row, full=True)
        incidents = [r["title"] for r in con.execute(
            "SELECT title FROM incidents WHERE device_id=? AND status!='resolved' ORDER BY created DESC LIMIT 20",
            (device_id,)).fetchall()]
    ctx = ai_device_context(d)
    ctx["open_incidents"] = incidents
    user_msg = "Diagnose this Windows endpoint and recommend fixes.\n\n" + json.dumps(ctx, ensure_ascii=False, indent=2)
    text = ai_chat(cfg, AI_SYSTEM_PROMPT, user_msg)
    t = now()
    with db() as con:
        con.execute("UPDATE devices SET ai_diagnosis=?, ai_diagnosis_at=? WHERE id=?", (text, t, device_id))
        audit(con, user["username"], client_ip(request), "ai_diagnose", row["hostname"],
              {"model": cfg["model"], "chars": len(text)})
    return {"diagnosis": text, "at": t, "model": cfg["model"], "context_sent": ctx}


# ---------------------------------------------------------------- reports (CSV / printable HTML)
# Exportable reports, scoped to the signed-in user. CSV opens in Excel (UTF-8 BOM, Hebrew-safe);
# the HTML version is print-ready, so the browser's "Save as PDF" produces a PDF without extra deps.

REPORTS = {"devices": "Device inventory", "licensing": "Software licence compliance", "incidents": "Incidents"}


def _report_date(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else ""


def _can_licensing(user: dict) -> bool:
    return user["role"] in ADMIN_ROLES or user["role"] == "school_manager"


def report_data(con, user: dict, kind: str) -> tuple[list[str], list[list], str]:
    """Return (columns, rows, title) for a report, already filtered to the user's scope."""
    if kind == "devices":
        allowed = allowed_lab_ids(con, user)
        pmap = place_map(con)
        cols = ["Hostname", "Municipality", "School", "Lab", "OS", "Model", "Last seen", "Online",
                "CPU %", "RAM %", "Disk %", "Internet", "USB", "Web filter sites", "Alerts"]
        rows = []
        for r in con.execute("SELECT * FROM devices ORDER BY hostname").fetchall():
            if allowed is not None and not (r["lab_id"] in allowed or (r["lab_id"] is None and sees_unassigned(user))):
                continue
            d = serialize_device(r)
            p = pmap.get(r["lab_id"], {}) if r["lab_id"] else {}
            alerts = "; ".join(a["text"] for a in d["alerts"] if a["level"] != "info")
            rows.append([d["hostname"], p.get("municipality", ""), p.get("school", ""), p.get("lab", ""),
                         d["os"], d["model"], _report_date(d["last_seen"]), "yes" if d["online"] else "no",
                         d["cpu"], d["mem"], d["disk"], "blocked" if d["isolated"] else "allowed",
                         d["usb"] or "allow", d["web_filter"] or 0, alerts])
        return cols, rows, "Device inventory"
    if kind == "licensing":
        if not _can_licensing(user):
            raise HTTPException(403, "Not allowed to view licensing")
        cols = ["Product", "Status", "Installs", "Seats", "Entitlements", "Expires", "Notes"]
        rows = [[f["label"], f["category"].replace("_", " "), f["installs"],
                 "site" if f["site"] else (f["seats"] or 0), f["entitlements"],
                 _report_date(f["expires"]) if f["expires"] else "", f["message"]]
                for f in compute_findings(con, user)]
        return cols, rows, "Software licence compliance"
    if kind == "incidents":
        allowed = allowed_lab_ids(con, user)
        cols = ["Severity", "Title", "Device", "Lab", "Status", "Assignee", "Source", "Opened", "Resolved"]
        rows = []
        for r in con.execute(_INC_COLS + "ORDER BY i.created DESC LIMIT 5000").fetchall():
            if not _incident_visible(user, allowed, r["lab_id"]):
                continue
            rows.append([r["severity"], r["title"], r["device_hostname"] or "",
                         scope_name(con, "lab", r["lab_id"]) if r["lab_id"] else "", r["status"],
                         r["assignee"] or "", r["source"], _report_date(r["created"]),
                         _report_date(r["resolved_at"]) if r["resolved_at"] else ""])
        return cols, rows, "Incidents"
    raise HTTPException(404, "Unknown report")


def report_csv_text(cols: list[str], rows: list[list]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for row in rows:
        w.writerow(["" if v is None else v for v in row])
    return buf.getvalue()


def report_csv(cols: list[str], rows: list[list], filename: str) -> Response:
    return Response(content="﻿" + report_csv_text(cols, rows), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{filename}.csv"'})


def report_html(title: str, cols: list[str], rows: list[list], scope: str) -> Response:
    import html
    e = html.escape
    thead = "".join(f"<th>{e(c)}</th>" for c in cols)
    tbody = "".join("<tr>" + "".join(f"<td>{e(str('' if v is None else v))}</td>" for v in row) + "</tr>"
                    for row in rows) or f'<tr><td colspan="{len(cols)}" class="empty">No data in scope.</td></tr>'
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{e(title)} — KEM report</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{ font: 14px/1.5 system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 32px; color: #111; background: #fff; }}
  header {{ display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; border-bottom: 2px solid #111; padding-bottom: 12px; margin-bottom: 20px; flex-wrap: wrap; }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  .meta {{ color: #555; font-size: 13px; }}
  .btn {{ border: 1px solid #2563eb; background: #2563eb; color: #fff; padding: 8px 14px; border-radius: 8px; font: inherit; cursor: pointer; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 12.5px; }}
  th, td {{ text-align: left; padding: 7px 10px; border-bottom: 1px solid #e3e3e3; vertical-align: top; }}
  th {{ background: #f3f4f6; font-weight: 700; border-bottom: 2px solid #ccc; }}
  tr:nth-child(even) td {{ background: #fafafa; }}
  .empty {{ text-align: center; color: #777; padding: 24px; }}
  footer {{ margin-top: 20px; color: #888; font-size: 12px; }}
  @media print {{ body {{ padding: 0; }} .btn {{ display: none; }} th {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }} }}
</style></head><body>
<header><div><h1>{e(title)}</h1>
  <div class="meta">KEM · School Lab Manager — scope: {e(scope)} · {len(rows)} row(s)<br>Generated {e(time.strftime('%Y-%m-%d %H:%M'))}</div></div>
  <button class="btn" onclick="window.print()">Print / Save as PDF</button></header>
<table><thead><tr>{thead}</tr></thead><tbody>{tbody}</tbody></table>
<footer>Generated by KEM. Figures reflect the most recent check-in from each device in scope.</footer>
</body></html>"""
    return Response(content=page, media_type="text/html; charset=utf-8")


@app.get("/api/reports")
def list_reports(user: dict = Depends(current_user)):
    return [{"kind": k, "label": v} for k, v in REPORTS.items()
            if not (k == "licensing" and not _can_licensing(user))]


@app.get("/api/reports/{kind}")
def get_report(kind: str, request: Request, format: str = "html", user: dict = Depends(current_user)):
    if kind not in REPORTS:
        raise HTTPException(404, "Unknown report")
    if format not in ("html", "csv"):
        raise HTTPException(400, "format must be html or csv")
    with db() as con:
        cols, rows, title = report_data(con, user, kind)
        scope = scope_label(con, user)
        audit(con, user["username"], client_ip(request), "report", kind, {"format": format, "rows": len(rows)})
    fname = f"kem-{kind}-{time.strftime('%Y%m%d')}"
    return report_csv(cols, rows, fname) if format == "csv" else report_html(title, cols, rows, scope)


# ---------------------------------------------------------------- scheduled reports
# A schedule generates a report on a cadence, stores the snapshot in history (downloadable later),
# and optionally delivers it through the existing notification channels (webhook summary + e-mail
# with the CSV attached). It runs at the scope of whoever created it.

CADENCES = ("daily", "weekly", "monthly")


def next_report_run(cadence: str, hour: int, weekday: int, monthday: int, frm: float) -> float:
    base = dtmod.datetime.fromtimestamp(frm)
    cand = base.replace(hour=hour, minute=0, second=0, microsecond=0)
    if cadence == "daily":
        if cand <= base:
            cand += dtmod.timedelta(days=1)
    elif cadence == "weekly":
        cand += dtmod.timedelta(days=(weekday - cand.weekday()) % 7)
        if cand <= base:
            cand += dtmod.timedelta(days=7)
    else:  # monthly
        def at(y: int, m: int):
            return cand.replace(year=y, month=m, day=min(monthday, calendar.monthrange(y, m)[1]))
        cand = at(cand.year, cand.month)
        if cand <= base:
            y, m = (cand.year + 1, 1) if cand.month == 12 else (cand.year, cand.month + 1)
            cand = at(y, m)
    return cand.timestamp()


def send_report_email(cfg: dict, recipients: list[str], subject: str, text: str, filename: str, csv_text: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["smtp_from"] or cfg["smtp_user"]
    msg["To"] = ", ".join(recipients)
    msg.set_content(text)
    msg.add_attachment(csv_text.encode("utf-8"), maintype="text", subtype="csv", filename=filename)
    port = int(cfg["smtp_port"] or 587)
    ctx = ssl.create_default_context()
    smtp = (smtplib.SMTP_SSL(cfg["smtp_host"], port, timeout=20, context=ctx)
            if cfg["smtp_security"] == "ssl" else smtplib.SMTP(cfg["smtp_host"], port, timeout=20))
    with smtp:
        if cfg["smtp_security"] == "starttls":
            smtp.starttls(context=ctx)
        if cfg["smtp_user"]:
            smtp.login(cfg["smtp_user"], cfg["smtp_pass"])
        smtp.send_message(msg)


def _schedule_user(s) -> dict:
    return {"username": "scheduler", "role": s["role"], "scope_type": s["scope_type"], "scope_id": s["scope_id"]}


def generate_report_run(con, s) -> dict:
    """Generate one report for a schedule, store it in history, and try to deliver it."""
    user = _schedule_user(s)
    cols, rows, title = report_data(con, user, s["kind"])
    scope = scope_label(con, user)
    content = report_csv_text(cols, rows)
    cfg = notify_config(con)
    sent = []
    if s["to_webhook"] and cfg["notify_webhook"]:
        link = cfg.get("public_url", "") and f"{cfg['public_url']}/#/reports"
        errs = deliver(cfg, f"[KEM] Scheduled report: {title}", f"{len(rows)} row(s) · scope: {scope}", link or "")
        sent.append("webhook: " + ("sent" if not errs else "; ".join(errs)))
    recips = [e.strip() for e in re.split(r"[,;\s]+", s["recipients"] or "") if e.strip()]
    if recips and cfg["smtp_host"]:
        try:
            send_report_email(cfg, recips, f"[KEM] {title}",
                              f"Attached: {title} — {len(rows)} row(s), scope {scope}.",
                              f"kem-{s['kind']}-{time.strftime('%Y%m%d')}.csv", content)
            sent.append("email: sent")
        except Exception as e:  # noqa: BLE001 - record delivery failure, keep the stored copy
            sent.append(f"email: {e}")
    note = "; ".join(sent) or "stored (no delivery channel configured)"
    rid = uuid.uuid4().hex
    con.execute("INSERT INTO report_runs(id,schedule_id,kind,fmt,scope_label,rows,bytes,content,generated,status,note)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (rid, s["id"], s["kind"], "csv", scope, len(rows), len(content.encode("utf-8")), content, now(),
                 "generated", note[:500]))
    # keep history bounded per schedule
    con.execute("DELETE FROM report_runs WHERE schedule_id=? AND id NOT IN "
                "(SELECT id FROM report_runs WHERE schedule_id=? ORDER BY generated DESC LIMIT 50)",
                (s["id"], s["id"]))
    return {"id": rid, "rows": len(rows), "note": note, "scope": scope, "title": title}


def run_due_reports(con) -> None:
    t = now()
    due = con.execute("SELECT * FROM report_schedules WHERE enabled=1 AND next_run IS NOT NULL AND next_run<=?",
                      (t,)).fetchall()
    for s in due:
        try:
            generate_report_run(con, s)
        except Exception as e:  # noqa: BLE001 - one bad schedule must not stop the others
            print(f"[KEM] report schedule {s['id']} failed: {e}")
        con.execute("UPDATE report_schedules SET last_run=?, next_run=? WHERE id=?",
                    (t, next_report_run(s["cadence"], s["hour"], s["weekday"], s["monthday"], now()), s["id"]))


def serialize_schedule(s) -> dict:
    d = dict(s)
    d["to_webhook"] = bool(d["to_webhook"])
    d["enabled"] = bool(d["enabled"])
    d["label"] = REPORTS.get(d["kind"], d["kind"])
    return d


def _owns_schedule(user: dict, s) -> bool:
    return user["role"] == "superadmin" or s["created_by"] == user["username"]


@app.get("/api/report-schedules")
def list_schedules(user: dict = Depends(require_admin_user)):
    with db() as con:
        rows = con.execute("SELECT * FROM report_schedules ORDER BY created DESC").fetchall()
        runs = {r["schedule_id"]: dict(r) for r in con.execute(
            "SELECT schedule_id, MAX(generated) AS generated, rows, note FROM report_runs GROUP BY schedule_id")}
    out = []
    for s in rows:
        if not _owns_schedule(user, s):
            continue
        d = serialize_schedule(s)
        d["last"] = runs.get(s["id"])
        out.append(d)
    return out


@app.post("/api/report-schedules")
def create_schedule(request: Request, body: dict = Body(...), user: dict = Depends(require_admin_user)):
    kind = clean(body.get("kind"), 32)
    if kind not in REPORTS:
        raise HTTPException(400, "Unknown report kind")
    if kind == "licensing" and not _can_licensing(user):
        raise HTTPException(403, "Not allowed to schedule the licensing report")
    cadence = body.get("cadence", "weekly")
    if cadence not in CADENCES:
        raise HTTPException(400, f"cadence must be one of {list(CADENCES)}")
    hour = _int(body, "hour", 7, 0, 23)
    weekday = _int(body, "weekday", 0, 0, 6)
    monthday = _int(body, "monthday", 1, 1, 28)
    recips = [e.strip() for e in re.split(r"[,;\s]+", clean(body.get("recipients"), 500)) if e.strip()]
    if any(not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", e) for e in recips):
        raise HTTPException(400, "Recipients must be valid e-mail addresses")
    sid = uuid.uuid4().hex
    t = now()
    nxt = next_report_run(cadence, hour, weekday, monthday, t)
    with db() as con:
        con.execute(
            "INSERT INTO report_schedules(id,kind,fmt,cadence,hour,weekday,monthday,recipients,to_webhook,"
            "role,scope_type,scope_id,enabled,created,created_by,next_run) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sid, kind, "csv", cadence, hour, weekday, monthday, ", ".join(recips), 1 if body.get("to_webhook") else 0,
             user["role"], user["scope_type"], user["scope_id"], 1, t, user["username"], nxt))
        audit(con, user["username"], client_ip(request), "report_schedule_created", kind, {"cadence": cadence})
        row = con.execute("SELECT * FROM report_schedules WHERE id=?", (sid,)).fetchone()
    return serialize_schedule(row)


@app.patch("/api/report-schedules/{sid}")
def update_schedule(sid: str, request: Request, body: dict = Body(...), user: dict = Depends(require_admin_user)):
    with db() as con:
        s = con.execute("SELECT * FROM report_schedules WHERE id=?", (sid,)).fetchone()
        if not s or not _owns_schedule(user, s):
            raise HTTPException(404, "Schedule not found")
        sets: dict[str, Any] = {}
        if "enabled" in body:
            sets["enabled"] = 1 if body.get("enabled") else 0
        if "to_webhook" in body:
            sets["to_webhook"] = 1 if body.get("to_webhook") else 0
        if "recipients" in body:
            recips = [e.strip() for e in re.split(r"[,;\s]+", clean(body.get("recipients"), 500)) if e.strip()]
            if any(not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", e) for e in recips):
                raise HTTPException(400, "Recipients must be valid e-mail addresses")
            sets["recipients"] = ", ".join(recips)
        if not sets:
            raise HTTPException(400, "Nothing to update")
        con.execute(f"UPDATE report_schedules SET {', '.join(k + '=?' for k in sets)} WHERE id=?",
                    (*sets.values(), sid))
        audit(con, user["username"], client_ip(request), "report_schedule_updated", sid, sets)
        row = con.execute("SELECT * FROM report_schedules WHERE id=?", (sid,)).fetchone()
    return serialize_schedule(row)


@app.delete("/api/report-schedules/{sid}")
def delete_schedule(sid: str, request: Request, user: dict = Depends(require_admin_user)):
    with db() as con:
        s = con.execute("SELECT * FROM report_schedules WHERE id=?", (sid,)).fetchone()
        if not s or not _owns_schedule(user, s):
            raise HTTPException(404, "Schedule not found")
        con.execute("DELETE FROM report_schedules WHERE id=?", (sid,))
        con.execute("DELETE FROM report_runs WHERE schedule_id=?", (sid,))
        audit(con, user["username"], client_ip(request), "report_schedule_deleted", sid)
    return {"ok": True}


@app.post("/api/report-schedules/{sid}/run")
def run_schedule_now(sid: str, request: Request, user: dict = Depends(require_admin_user)):
    with db() as con:
        s = con.execute("SELECT * FROM report_schedules WHERE id=?", (sid,)).fetchone()
        if not s or not _owns_schedule(user, s):
            raise HTTPException(404, "Schedule not found")
        result = generate_report_run(con, s)
        con.execute("UPDATE report_schedules SET last_run=? WHERE id=?", (now(), sid))
        audit(con, user["username"], client_ip(request), "report_schedule_run", s["kind"], {"rows": result["rows"]})
    return result


@app.get("/api/report-runs")
def list_report_runs(schedule_id: str = "", limit: int = 100, user: dict = Depends(require_admin_user)):
    with db() as con:
        owned = {s["id"] for s in con.execute("SELECT id, created_by, role FROM report_schedules").fetchall()
                 if _owns_schedule(user, s)}
        q = "SELECT id,schedule_id,kind,fmt,scope_label,rows,bytes,generated,status,note FROM report_runs "
        args: list = []
        if schedule_id:
            q += "WHERE schedule_id=? "
            args.append(schedule_id)
        q += "ORDER BY generated DESC LIMIT ?"
        args.append(max(1, min(limit, 500)))
        rows = [dict(r) for r in con.execute(q, args).fetchall()]
    return [r for r in rows if r["schedule_id"] in owned]


@app.get("/api/report-runs/{rid}/download")
def download_report_run(rid: str, user: dict = Depends(require_admin_user)):
    with db() as con:
        r = con.execute("SELECT r.*, s.created_by, s.role FROM report_runs r "
                        "LEFT JOIN report_schedules s ON s.id=r.schedule_id WHERE r.id=?", (rid,)).fetchone()
        if not r or (r["created_by"] is not None and not _owns_schedule(user, r)):
            raise HTTPException(404, "Report not found")
    fname = f"kem-{r['kind']}-{time.strftime('%Y%m%d%H%M', time.localtime(r['generated']))}"
    return Response(content="﻿" + (r["content"] or ""), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{fname}.csv"'})


# ---------------------------------------------------------------- central image repository (catalog)
# The repository is a catalog of OS images referenced by location + checksum (images are multi-GB
# and live on a share/URL, not in the DB) plus a per-lab "target image" assignment. Actually storing,
# distributing (via the gateway) and applying an image needs boot media / imaging infrastructure and
# is NOT built here - this is the control plane that such distribution would consume.


def serialize_image(con, row) -> dict:
    d = dict(row)
    d["scope_name"] = scope_name(con, d["scope_type"], d["scope_id"])
    return d


def require_images(request: Request) -> dict:
    u = _authenticate(request)
    if u["role"] not in ADMIN_ROLES:
        raise HTTPException(403, "Only administrators manage the image repository")
    return u


def _image_scope(con, user: dict, body: dict) -> tuple[str, str | None]:
    st = body.get("scope_type", "global")
    if st not in ("global", "municipality", "school", "lab"):
        raise HTTPException(400, "scope_type must be global, municipality, school or lab")
    if st == "global":
        if user["role"] != "superadmin":
            raise HTTPException(403, "Only a superadmin can register a global image")
        return st, None
    sid = clean(body.get("scope_id"), 64) or None
    if not sid:
        raise HTTPException(400, "scope_id is required for this scope")
    table = {"municipality": "municipalities", "school": "schools", "lab": "labs"}[st]
    if not con.execute(f"SELECT 1 FROM {table} WHERE id=?", (sid,)).fetchone():
        raise HTTPException(404, f"{st} not found")
    if not entitlement_in_scope(con, user, {"scope_type": st, "scope_id": sid}):
        raise HTTPException(403, "That scope is outside your reach")
    return st, sid


@app.get("/api/images")
def list_images(user: dict = Depends(current_user)):
    if not (user["role"] in ADMIN_ROLES or user["role"] == "school_manager"):
        raise HTTPException(403, "Not allowed")
    with db() as con:
        rows = con.execute("SELECT * FROM images ORDER BY created DESC").fetchall()
        out = [serialize_image(con, r) for r in rows if entitlement_in_scope(con, user, r)]
    return out


@app.post("/api/images")
def create_image(request: Request, body: dict = Body(...), user: dict = Depends(require_images)):
    name = clean(body.get("name"), 120)
    if not name:
        raise HTTPException(400, "A name is required")
    url = clean(body.get("source_url"), 500)
    if url and not re.match(r"^(https?://|[A-Za-z]:\\|\\\\)", url):
        raise HTTPException(400, "source_url must be an http(s) URL or a Windows/UNC path")
    sha = clean(body.get("sha256"), 64).lower()
    if sha and not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise HTTPException(400, "SHA-256 must be 64 hex characters")
    try:
        size = max(0, int(body.get("size_bytes") or 0))
    except (TypeError, ValueError):
        raise HTTPException(400, "size_bytes must be a number")
    with db() as con:
        st, sid = _image_scope(con, user, body)
        iid = uuid.uuid4().hex
        con.execute(
            "INSERT INTO images(id,name,os,version,size_bytes,sha256,source_url,notes,scope_type,scope_id,created,created_by)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (iid, name, clean(body.get("os"), 100), clean(body.get("version"), 60), size, sha, url,
             clean(body.get("notes"), 1000), st, sid, now(), user["username"]))
        audit(con, user["username"], client_ip(request), "image_created", name, {"scope": st})
        out = serialize_image(con, con.execute("SELECT * FROM images WHERE id=?", (iid,)).fetchone())
    return out


@app.delete("/api/images/{iid}")
def delete_image(iid: str, request: Request, user: dict = Depends(require_images)):
    with db() as con:
        row = con.execute("SELECT * FROM images WHERE id=?", (iid,)).fetchone()
        if not row or not entitlement_in_scope(con, user, row):
            raise HTTPException(404, "Image not found")
        con.execute("DELETE FROM images WHERE id=?", (iid,))
        con.execute("UPDATE labs SET image_id=NULL WHERE image_id=?", (iid,))
        audit(con, user["username"], client_ip(request), "image_deleted", row["name"])
    return {"ok": True}


@app.get("/api/lab-images")
def lab_images(user: dict = Depends(current_user)):
    if not (user["role"] in ADMIN_ROLES or user["role"] == "school_manager"):
        raise HTTPException(403, "Not allowed")
    with db() as con:
        allowed = allowed_lab_ids(con, user)
        rows = con.execute(
            "SELECT l.id, l.name, l.image_id, s.name AS school, i.name AS image_name "
            "FROM labs l JOIN schools s ON s.id=l.school_id LEFT JOIN images i ON i.id=l.image_id "
            "ORDER BY s.name, l.name").fetchall()
        out = [{"lab_id": r["id"], "lab": r["name"], "school": r["school"],
                "image_id": r["image_id"], "image_name": r["image_name"]}
               for r in rows if allowed is None or r["id"] in allowed]
    return out


@app.post("/api/labs/{lab_id}/image")
def assign_lab_image(lab_id: str, request: Request, body: dict = Body(...), user: dict = Depends(current_user)):
    if not (user["role"] in ADMIN_ROLES or user["role"] == "school_manager"):
        raise HTTPException(403, "Not allowed")
    image_id = clean(body.get("image_id"), 64) or None
    with db() as con:
        if not con.execute("SELECT 1 FROM labs WHERE id=?", (lab_id,)).fetchone() or not device_in_scope(con, user, lab_id):
            raise HTTPException(404, "Lab not found")
        if image_id:
            img = con.execute("SELECT * FROM images WHERE id=?", (image_id,)).fetchone()
            if not img or not entitlement_in_scope(con, user, img):
                raise HTTPException(404, "Image not found")
        con.execute("UPDATE labs SET image_id=? WHERE id=?", (image_id, lab_id))
        audit(con, user["username"], client_ip(request), "lab_image_set", lab_id, {"image_id": image_id or ""})
    return {"ok": True, "lab_id": lab_id, "image_id": image_id}


# ---------------------------------------------------------------- organization (municipality/school/lab)

def _req_name(body: dict, key: str = "name", limit: int = 120) -> str:
    v = clean(body.get(key), limit)
    if not v:
        raise HTTPException(400, "A name is required")
    return v


def muni_in_scope(user: dict, mid: str) -> bool:
    if user["role"] == "superadmin":
        return True
    if user["role"] == "municipality_admin":
        return user["scope_type"] == "global" or user["scope_id"] == mid
    return False


def school_in_scope(con, user: dict, sid: str) -> bool:
    if user["role"] == "superadmin":
        return True
    row = con.execute("SELECT municipality_id FROM schools WHERE id=?", (sid,)).fetchone()
    if not row:
        return False
    if user["role"] == "municipality_admin":
        return user["scope_type"] == "global" or row["municipality_id"] == user["scope_id"]
    if user["role"] == "school_manager":
        return user["scope_id"] == sid
    return False


@app.get("/api/org")
def get_org(user: dict = Depends(current_user)):
    """Scoped Municipality -> School -> Lab tree with device/gateway counts (drives the UI)."""
    with db() as con:
        allowed = allowed_lab_ids(con, user)
        munis = con.execute("SELECT * FROM municipalities ORDER BY name COLLATE NOCASE").fetchall()
        schools = con.execute("SELECT * FROM schools ORDER BY name COLLATE NOCASE").fetchall()
        labs = con.execute("SELECT * FROM labs ORDER BY name COLLATE NOCASE").fetchall()
        dcount = {r["lab_id"]: r["n"] for r in con.execute(
            "SELECT lab_id, COUNT(*) n FROM devices WHERE lab_id IS NOT NULL GROUP BY lab_id")}
        gcount = {r["lab_id"]: r["n"] for r in con.execute(
            "SELECT lab_id, COUNT(*) n FROM gateways WHERE lab_id IS NOT NULL GROUP BY lab_id")}
        unassigned = con.execute("SELECT COUNT(*) n FROM devices WHERE lab_id IS NULL").fetchone()["n"]
    labs_by_school: dict[str, list] = {}
    for l in labs:
        if allowed is not None and l["id"] not in allowed:
            continue
        labs_by_school.setdefault(l["school_id"], []).append(
            {"id": l["id"], "name": l["name"], "devices": dcount.get(l["id"], 0), "gateways": gcount.get(l["id"], 0)})
    schools_by_muni: dict[str, list] = {}
    for s in schools:
        ls = labs_by_school.get(s["id"], [])
        keep = allowed is None or ls or (user["role"] == "school_manager" and user["scope_id"] == s["id"]) \
            or (user["role"] == "municipality_admin" and (user["scope_type"] == "global" or user["scope_id"] == s["municipality_id"]))
        if keep:
            schools_by_muni.setdefault(s["municipality_id"], []).append({"id": s["id"], "name": s["name"], "labs": ls})
    out = []
    for m in munis:
        ss = schools_by_muni.get(m["id"], [])
        keep = allowed is None or ss or muni_in_scope(user, m["id"])
        if keep:
            out.append({"id": m["id"], "name": m["name"], "schools": ss})
    return {"municipalities": out, "unassigned_devices": unassigned if sees_unassigned(user) else 0,
            "can_edit": user["role"] in ADMIN_ROLES}


@app.post("/api/municipalities")
def create_municipality(request: Request, body: dict = Body(...), user: dict = Depends(require_superadmin)):
    name = _req_name(body)
    mid = uuid.uuid4().hex
    with db() as con:
        con.execute("INSERT INTO municipalities(id,name,created) VALUES(?,?,?)", (mid, name, now()))
        audit(con, user["username"], client_ip(request), "municipality_created", name)
    return {"id": mid, "name": name}


@app.post("/api/schools")
def create_school(request: Request, body: dict = Body(...), user: dict = Depends(require_admin_user)):
    name = _req_name(body)
    mid = clean(body.get("municipality_id"), 32)
    with db() as con:
        if not con.execute("SELECT 1 FROM municipalities WHERE id=?", (mid,)).fetchone():
            raise HTTPException(404, "Municipality not found")
        if not muni_in_scope(user, mid):
            raise HTTPException(403, "That municipality is outside your scope")
        sid = uuid.uuid4().hex
        con.execute("INSERT INTO schools(id,municipality_id,name,created) VALUES(?,?,?,?)", (sid, mid, name, now()))
        audit(con, user["username"], client_ip(request), "school_created", name, {"municipality_id": mid})
    return {"id": sid, "name": name}


@app.post("/api/labs")
def create_lab(request: Request, body: dict = Body(...), user: dict = Depends(require_admin_user)):
    name = _req_name(body)
    sid = clean(body.get("school_id"), 32)
    with db() as con:
        if not con.execute("SELECT 1 FROM schools WHERE id=?", (sid,)).fetchone():
            raise HTTPException(404, "School not found")
        if not school_in_scope(con, user, sid):
            raise HTTPException(403, "That school is outside your scope")
        lid = uuid.uuid4().hex
        con.execute("INSERT INTO labs(id,school_id,name,created) VALUES(?,?,?,?)", (lid, sid, name, now()))
        audit(con, user["username"], client_ip(request), "lab_created", name, {"school_id": sid})
    return {"id": lid, "name": name}


@app.delete("/api/municipalities/{mid}")
def delete_municipality(mid: str, request: Request, user: dict = Depends(require_superadmin)):
    with db() as con:
        if con.execute("SELECT 1 FROM schools WHERE municipality_id=?", (mid,)).fetchone():
            raise HTTPException(400, "Remove the schools in this municipality first")
        con.execute("DELETE FROM municipalities WHERE id=?", (mid,))
        audit(con, user["username"], client_ip(request), "municipality_deleted", mid)
    return {"ok": True}


@app.delete("/api/schools/{sid}")
def delete_school(sid: str, request: Request, user: dict = Depends(require_admin_user)):
    with db() as con:
        if not school_in_scope(con, user, sid):
            raise HTTPException(404, "School not found")
        if con.execute("SELECT 1 FROM labs WHERE school_id=?", (sid,)).fetchone():
            raise HTTPException(400, "Remove the labs in this school first")
        con.execute("DELETE FROM schools WHERE id=?", (sid,))
        audit(con, user["username"], client_ip(request), "school_deleted", sid)
    return {"ok": True}


@app.delete("/api/labs/{lid}")
def delete_lab(lid: str, request: Request, user: dict = Depends(require_admin_user)):
    with db() as con:
        if not device_in_scope(con, user, lid) or not con.execute("SELECT 1 FROM labs WHERE id=?", (lid,)).fetchone():
            raise HTTPException(404, "Lab not found")
        if con.execute("SELECT 1 FROM devices WHERE lab_id=?", (lid,)).fetchone() or \
           con.execute("SELECT 1 FROM gateways WHERE lab_id=?", (lid,)).fetchone():
            raise HTTPException(400, "Move the devices and gateway out of this lab first")
        con.execute("DELETE FROM labs WHERE id=?", (lid,))
        audit(con, user["username"], client_ip(request), "lab_deleted", lid)
    return {"ok": True}


# ---------------------------------------------------------------- users & roles

def serialize_user(con, r) -> dict:
    return {"id": r["id"], "username": r["username"], "display_name": r["display_name"] or "",
            "role": r["role"], "scope_type": r["scope_type"], "scope_id": r["scope_id"],
            "scope_label": scope_label(con, dict(r)), "disabled": bool(r["disabled"]),
            "last_login": r["last_login"], "created": r["created"]}


def _user_visible(con, admin: dict, target: dict) -> bool:
    """Can `admin` see/manage `target`? Based on the target's scope falling inside admin's scope."""
    if admin["role"] == "superadmin":
        return True
    role, st, sid = target["role"], target["scope_type"], target["scope_id"]
    if role == "superadmin":
        return False
    if st == "municipality":
        return muni_in_scope(admin, sid)
    if st == "school":
        return school_in_scope(con, admin, sid) if sid else False
    if st == "lab":
        return device_in_scope(con, admin, sid)
    return False


@app.get("/api/users")
def list_users(user: dict = Depends(require_admin_user)):
    with db() as con:
        rows = con.execute("SELECT * FROM users ORDER BY role, username COLLATE NOCASE").fetchall()
        return [serialize_user(con, r) for r in rows if _user_visible(con, user, dict(r))]


@app.post("/api/users")
def create_user(request: Request, body: dict = Body(...), user: dict = Depends(require_admin_user)):
    username = clean(body.get("username"), 64)
    if not re.fullmatch(r"[A-Za-z0-9._@-]{3,64}", username):
        raise HTTPException(400, "Username must be 3-64 chars (letters, digits, . _ - @)")
    pw = str(body.get("password") or "")
    if len(pw) < 10:
        raise HTTPException(400, "Password must be at least 10 characters")
    role = body.get("role")
    if role not in ("municipality_admin", "school_manager", "teacher"):
        raise HTTPException(400, "role must be municipality_admin, school_manager or teacher")
    if role == "municipality_admin" and user["role"] != "superadmin":
        raise HTTPException(403, "Only the platform owner can create municipality administrators")
    scope_id = clean(body.get("scope_id"), 32) or None
    scope_type = SCOPE_FOR_ROLE[role]
    with db() as con:
        # Validate the scope target exists and is inside the creator's own scope.
        if role == "municipality_admin":
            if not scope_id or not con.execute("SELECT 1 FROM municipalities WHERE id=?", (scope_id,)).fetchone() \
                    or not muni_in_scope(user, scope_id):
                raise HTTPException(400, "Choose a municipality within your scope")
        elif role == "school_manager":
            if not scope_id or not school_in_scope(con, user, scope_id):
                raise HTTPException(400, "Choose a school within your scope")
        elif role == "teacher":
            if not scope_id or not con.execute("SELECT 1 FROM labs WHERE id=?", (scope_id,)).fetchone() \
                    or not device_in_scope(con, user, scope_id):
                raise HTTPException(400, "Choose a lab within your scope")
        if con.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            raise HTTPException(400, "That username is taken")
        uid = uuid.uuid4().hex
        con.execute("INSERT INTO users(id,username,pw_hash,display_name,role,scope_type,scope_id,created,created_by)"
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (uid, username, hash_password(pw), clean(body.get("display_name"), 120), role,
                     scope_type, scope_id, now(), user["username"]))
        audit(con, user["username"], client_ip(request), "user_created", username, {"role": role, "scope_id": scope_id})
    return {"id": uid, "username": username}


@app.patch("/api/users/{uid}")
def update_user(uid: str, request: Request, body: dict = Body(...), user: dict = Depends(require_admin_user)):
    with db() as con:
        row = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not row or not _user_visible(con, user, dict(row)):
            raise HTTPException(404, "User not found")
        if row["role"] == "superadmin" and user["role"] != "superadmin":
            raise HTTPException(403, "You cannot change this account")
        if "display_name" in body:
            con.execute("UPDATE users SET display_name=? WHERE id=?", (clean(body.get("display_name"), 120), uid))
        if "disabled" in body:
            if row["id"] == user["id"]:
                raise HTTPException(400, "You cannot disable your own account")
            con.execute("UPDATE users SET disabled=? WHERE id=?", (1 if body.get("disabled") else 0, uid))
            if body.get("disabled"):
                con.execute("DELETE FROM sessions WHERE username=?", (row["username"],))
        if body.get("password"):
            if len(str(body["password"])) < 10:
                raise HTTPException(400, "Password must be at least 10 characters")
            con.execute("UPDATE users SET pw_hash=? WHERE id=?", (hash_password(str(body["password"])), uid))
            con.execute("DELETE FROM sessions WHERE username=?", (row["username"],))
        audit(con, user["username"], client_ip(request), "user_updated", row["username"],
              {k: ("***" if k == "password" else v) for k, v in body.items()})
    return {"ok": True}


@app.delete("/api/users/{uid}")
def delete_user(uid: str, request: Request, user: dict = Depends(require_admin_user)):
    with db() as con:
        row = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not row or not _user_visible(con, user, dict(row)):
            raise HTTPException(404, "User not found")
        if row["id"] == user["id"]:
            raise HTTPException(400, "You cannot delete your own account")
        if row["role"] == "superadmin":
            raise HTTPException(403, "The platform owner account cannot be deleted")
        con.execute("DELETE FROM users WHERE id=?", (uid,))
        con.execute("DELETE FROM sessions WHERE username=?", (row["username"],))
        audit(con, user["username"], client_ip(request), "user_deleted", row["username"])
    return {"ok": True}


@app.get("/api/roles")
def list_roles(user: dict = Depends(current_user)):
    return {"roles": ROLES, "scope_for_role": SCOPE_FOR_ROLE}


# ---------------------------------------------------------------- Teacher Gateways

def serialize_gateway(row, pmap: dict) -> dict:
    online = bool(row["last_seen"] and now() - row["last_seen"] < ONLINE_SECONDS)
    return {"id": row["id"], "hostname": row["hostname"], "lab_id": row["lab_id"],
            "place": pmap.get(row["lab_id"], {"lab": "", "school": "", "municipality": ""}),
            "online": online, "last_seen": row["last_seen"], "enrolled": row["enrolled"],
            "public_ip": row["public_ip"], "agent_version": row["agent_version"], "notes": row["notes"] or ""}


@app.get("/api/gateways")
def list_gateways(user: dict = Depends(require_admin_user)):
    with db() as con:
        rows = con.execute("SELECT * FROM gateways ORDER BY hostname COLLATE NOCASE").fetchall()
        allowed = allowed_lab_ids(con, user)
        pmap = place_map(con)
        counts = {r["gateway_id"]: r["n"] for r in con.execute(
            "SELECT gateway_id, COUNT(*) n FROM devices WHERE gateway_id IS NOT NULL GROUP BY gateway_id")}
    out = []
    for r in rows:
        if allowed is not None and (r["lab_id"] is None or r["lab_id"] not in allowed):
            continue
        g = serialize_gateway(r, pmap)
        g["devices"] = counts.get(r["id"], 0)
        out.append(g)
    return out


@app.delete("/api/gateways/{gid}")
def delete_gateway(gid: str, request: Request, user: dict = Depends(require_admin_user)):
    with db() as con:
        row = con.execute("SELECT * FROM gateways WHERE id=?", (gid,)).fetchone()
        if not row or not device_in_scope(con, user, row["lab_id"]):
            raise HTTPException(404, "Gateway not found")
        con.execute("DELETE FROM gateways WHERE id=?", (gid,))
        con.execute("UPDATE devices SET gateway_id=NULL WHERE gateway_id=?", (gid,))
        audit(con, user["username"], client_ip(request), "gateway_deleted", row["hostname"])
    return {"ok": True}


@app.post("/api/gateway/enroll")
def gateway_enroll(request: Request, body: dict = Body(...)):
    ip = client_ip(request)
    rate_limit(f"genroll:{ip}", limit=20)
    token = clean(body.get("token"), 32).upper()
    hostname = clean(body.get("hostname"), 64) or "GATEWAY"
    t = now()
    with db() as con:
        tk = con.execute("SELECT * FROM tokens WHERE token=?", (token,)).fetchone()
        if (not tk or tk["revoked"] or (tk["expires"] and tk["expires"] < t)
                or (tk["max_uses"] and tk["uses"] >= tk["max_uses"])):
            audit(con, "gateway", ip, "gateway_enroll_rejected", hostname, {"token": token[:4] + "-****"})
            con.commit()
            raise HTTPException(403, "Registration token is invalid, expired or used up")
        if (tk["kind"] or "device") != "gateway":
            con.commit()
            raise HTTPException(403, "This is a device token; a gateway needs a gateway token")
        if not tk["lab_id"]:
            con.commit()
            raise HTTPException(400, "This gateway token is not tied to a lab")
        secret = secrets.token_urlsafe(32)
        gid = uuid.uuid4().hex
        con.execute("INSERT INTO gateways(id,secret_hash,lab_id,hostname,enrolled,last_seen,public_ip) "
                    "VALUES(?,?,?,?,?,?,?)", (gid, sha256(secret), tk["lab_id"], hostname, t, t, ip))
        con.execute("UPDATE tokens SET uses=uses+1 WHERE id=?", (tk["id"],))
        audit(con, "gateway", ip, "gateway_enrolled", hostname, {"token": token, "lab_id": tk["lab_id"]})
    return AgentJSON({"gateway_id": gid, "secret": secret, "interval": CHECKIN_INTERVAL, "lab_id": tk["lab_id"]})


@app.post("/api/gateway/checkin")
def gateway_checkin(request: Request, body: dict = Body(...), gw: dict = Depends(gateway_auth)):
    t = now()
    with db() as con:
        con.execute("UPDATE gateways SET last_seen=?, public_ip=?, agent_version=?, telemetry=? WHERE id=?",
                    (t, client_ip(request), clean(body.get("agent_version"), 20),
                     json.dumps(body.get("telemetry") or {}, ensure_ascii=False)[:100_000], gw["id"]))
        ndev = con.execute("SELECT COUNT(*) n FROM devices WHERE gateway_id=?", (gw["id"],)).fetchone()["n"]
    return AgentJSON({"ok": True, "interval": CHECKIN_INTERVAL, "server_time": t, "devices": ndev})


# ---------------------------------------------------------------- teacher class sessions

@app.get("/api/class/active")
def class_active(user: dict = Depends(current_user)):
    if user["role"] != "teacher":
        return {"active": None}
    with db() as con:
        row = con.execute("SELECT * FROM teacher_sessions WHERE user_id=? AND ended IS NULL ORDER BY started DESC LIMIT 1",
                          (user["id"],)).fetchone()
    return {"active": dict(row) if row else None, "lab_id": user["scope_id"]}


@app.post("/api/class/start")
def class_start(request: Request, body: dict = Body(...), user: dict = Depends(current_user)):
    if user["role"] != "teacher":
        raise HTTPException(403, "Only teachers run class sessions")
    lab_id = user["scope_id"]
    if not lab_id:
        raise HTTPException(400, "You are not assigned to a lab")
    with db() as con:
        if not con.execute("SELECT 1 FROM labs WHERE id=?", (lab_id,)).fetchone():
            raise HTTPException(404, "Your lab no longer exists")
        con.execute("UPDATE teacher_sessions SET ended=? WHERE user_id=? AND ended IS NULL", (now(), user["id"]))
        sid = uuid.uuid4().hex
        con.execute("INSERT INTO teacher_sessions(id,user_id,username,lab_id,started,note) VALUES(?,?,?,?,?,?)",
                    (sid, user["id"], user["username"], lab_id, now(), clean(body.get("note"), 200)))
        audit(con, user["username"], client_ip(request), "class_started", lab_id)
    return {"id": sid, "lab_id": lab_id}


@app.post("/api/class/stop")
def class_stop(request: Request, user: dict = Depends(current_user)):
    if user["role"] != "teacher":
        raise HTTPException(403, "Only teachers run class sessions")
    with db() as con:
        cur = con.execute("UPDATE teacher_sessions SET ended=? WHERE user_id=? AND ended IS NULL", (now(), user["id"]))
        audit(con, user["username"], client_ip(request), "class_stopped", user["scope_id"] or "")
    return {"ok": True, "ended": cur.rowcount}


# ---------------------------------------------------------------- examination mode
# An exam locks every station in a lab into a controlled state by issuing the already-verified
# classroom commands (internet isolation, USB block, optional web filter) to each device, and
# lifts them again when the exam ends. The exam record is the orchestration layer; the agent does
# the enforcement with the same commands an operator could send by hand.

def _enqueue(con, user: dict, devices, ctype: str, params: dict) -> list[int]:
    """Queue one server-initiated command for several devices (params are generated, not user input)."""
    pj = json.dumps(validate_params(ctype, params), ensure_ascii=False)
    created = []
    for d in devices:
        cur = con.execute(
            "INSERT INTO commands(device_id,type,params,status,created,created_by,via_role) VALUES(?,?,?,?,?,?,?)",
            (d["id"], ctype, pj, "queued", now(), user["username"], user["role"]))
        created.append(cur.lastrowid)
    return created


def serialize_exam(con, row) -> dict:
    d = dict(row)
    d["web_filter"] = jload(d.get("web_filter"), [])
    d["stations"] = len(jload(d.pop("device_ids", "[]"), []))
    d["active"] = d["ended"] is None
    d["lock_internet"] = bool(d["lock_internet"])
    d["lock_usb"] = bool(d["lock_usb"])
    d["allow_lan"] = bool(d["allow_lan"])
    d["lab_name"] = scope_name(con, "lab", d["lab_id"])
    return d


def _exam_lab(con, user: dict, body: dict, require_class: bool) -> str:
    """Resolve and authorize the lab an exam acts on for this user."""
    if user["role"] == "teacher":
        lab_id = user["scope_id"]
        if not lab_id:
            raise HTTPException(400, "You are not assigned to a lab")
        if require_class and not has_active_class(con, user, lab_id):
            raise HTTPException(403, "Start a class session before managing an exam")
        return lab_id
    lab_id = clean(body.get("lab_id"), 64)
    if not lab_id:
        raise HTTPException(400, "lab_id is required")
    if not con.execute("SELECT 1 FROM labs WHERE id=?", (lab_id,)).fetchone():
        raise HTTPException(404, "Lab not found")
    if not device_in_scope(con, user, lab_id):
        raise HTTPException(403, "That lab is outside your scope")
    return lab_id


@app.get("/api/exams")
def list_exams(user: dict = Depends(current_user)):
    with db() as con:
        allowed = allowed_lab_ids(con, user)
        rows = con.execute("SELECT * FROM exam_sessions ORDER BY (ended IS NULL) DESC, started DESC LIMIT 200").fetchall()
        out = [serialize_exam(con, r) for r in rows
               if allowed is None or r["lab_id"] in allowed]
    return out


@app.post("/api/exams/start")
def exam_start(request: Request, body: dict = Body(...), user: dict = Depends(current_user)):
    if not role_can_issue(user["role"], "block_internet"):
        raise HTTPException(403, "Your role cannot start an exam")
    name = clean(body.get("name"), 120) or "Exam"
    note = clean(body.get("note"), 300)
    lock_internet = bool(body.get("lock_internet", True))
    lock_usb = bool(body.get("lock_usb", True))
    allow_lan = bool(body.get("allow_lan"))
    wf = validate_params("set_web_filter", {"domains": body.get("web_filter") or []})["domains"]
    if not (lock_internet or lock_usb or wf):
        raise HTTPException(400, "An exam must lock at least one of internet, USB or web filter")
    with db() as con:
        lab_id = _exam_lab(con, user, body, require_class=True)
        if con.execute("SELECT 1 FROM exam_sessions WHERE lab_id=? AND ended IS NULL", (lab_id,)).fetchone():
            raise HTTPException(409, "An exam is already running in this lab — end it first")
        devices = con.execute("SELECT id, hostname FROM devices WHERE lab_id=?", (lab_id,)).fetchall()
        created: list[int] = []
        if lock_internet:
            created += _enqueue(con, user, devices, "block_internet", {"allow_lan": allow_lan})
        elif wf:
            created += _enqueue(con, user, devices, "set_web_filter", {"domains": wf})
        if lock_usb:
            created += _enqueue(con, user, devices, "usb_storage", {"mode": "block"})
        eid = uuid.uuid4().hex
        dids = [d["id"] for d in devices]
        con.execute(
            "INSERT INTO exam_sessions(id,lab_id,name,started_by,started,lock_internet,lock_usb,allow_lan,web_filter,note,device_ids)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (eid, lab_id, name, user["username"], now(), int(lock_internet), int(lock_usb), int(allow_lan),
             json.dumps(wf), note, json.dumps(dids)))
        audit(con, user["username"], client_ip(request), "exam_started", lab_id,
              {"name": name, "stations": len(dids), "commands": len(created)})
        row = con.execute("SELECT * FROM exam_sessions WHERE id=?", (eid,)).fetchone()
        exam = serialize_exam(con, row)
    return {"exam": exam, "stations": len(dids), "commands": len(created)}


@app.post("/api/exams/{eid}/stop")
def exam_stop(eid: str, request: Request, user: dict = Depends(current_user)):
    with db() as con:
        row = con.execute("SELECT * FROM exam_sessions WHERE id=?", (eid,)).fetchone()
        if not row:
            raise HTTPException(404, "Exam not found")
        if not device_in_scope(con, user, row["lab_id"]):
            raise HTTPException(403, "That exam is outside your scope")
        if user["role"] == "teacher" and not has_active_class(con, user, row["lab_id"]):
            raise HTTPException(403, "Start a class session on this lab to manage its exam")
        if row["ended"] is not None:
            raise HTTPException(400, "This exam already ended")
        devices = con.execute("SELECT id, hostname FROM devices WHERE lab_id=?", (row["lab_id"],)).fetchall()
        created: list[int] = []
        if row["lock_internet"]:
            created += _enqueue(con, user, devices, "unblock_internet", {})
        elif jload(row["web_filter"], []):
            created += _enqueue(con, user, devices, "set_web_filter", {"domains": []})
        if row["lock_usb"]:
            created += _enqueue(con, user, devices, "usb_storage", {"mode": "allow"})
        con.execute("UPDATE exam_sessions SET ended=?, ended_by=? WHERE id=?", (now(), user["username"], eid))
        audit(con, user["username"], client_ip(request), "exam_ended", row["lab_id"], {"commands": len(created)})
    return {"ok": True, "commands": len(created)}


# ---------------------------------------------------------------- incidents
# Incidents turn raw device alerts into tracked work: open -> acknowledged -> resolved, with an
# assignee and notes. Health alerts open and auto-resolve themselves (source='auto'); operators can
# also raise incidents by hand (source='manual'), which the auto-reconciler never touches.

INCIDENT_STATUS = ("open", "acknowledged", "resolved")
INCIDENT_SEV = ("info", "warning", "critical")


def require_incidents(request: Request) -> dict:
    u = _authenticate(request)
    if u["role"] not in ADMIN_ROLES and u["role"] != "school_manager":
        raise HTTPException(403, "Not allowed to manage incidents")
    return u


def _incident_visible(user: dict, allowed, lab_id) -> bool:
    if allowed is None:
        return True
    if lab_id is None:
        return sees_unassigned(user)
    return lab_id in allowed


def serialize_incident(con, row) -> dict:
    d = dict(row)
    d["device_hostname"] = d.pop("device_hostname", None) or ""
    d["auto_resolved"] = bool(d.get("auto_resolved"))
    d["lab_name"] = scope_name(con, "lab", d["lab_id"]) if d["lab_id"] else ""
    return d


_INC_COLS = ("SELECT i.*, d.hostname AS device_hostname FROM incidents i "
             "LEFT JOIN devices d ON d.id=i.device_id ")


@app.get("/api/incidents")
def list_incidents(status: str = "", device_id: str = "", limit: int = 300, user: dict = Depends(current_user)):
    limit = max(1, min(limit, 1000))
    where, args = [], []
    if status in INCIDENT_STATUS:
        where.append("i.status=?"); args.append(status)
    elif status == "unresolved":
        where.append("i.status!='resolved'")
    if device_id:
        where.append("i.device_id=?"); args.append(device_id)
    sql = _INC_COLS + ("WHERE " + " AND ".join(where) + " " if where else "") + "ORDER BY i.created DESC LIMIT 2000"
    with db() as con:
        allowed = allowed_lab_ids(con, user)
        rows = con.execute(sql, args).fetchall()
        out = []
        for r in rows:
            if not _incident_visible(user, allowed, r["lab_id"]):
                continue
            out.append(serialize_incident(con, r))
            if len(out) >= limit:
                break
    return out


@app.get("/api/incidents/summary")
def incidents_summary(user: dict = Depends(current_user)):
    with db() as con:
        allowed = allowed_lab_ids(con, user)
        rows = con.execute("SELECT status, severity, lab_id FROM incidents WHERE status!='resolved'").fetchall()
    s = {"open": 0, "acknowledged": 0, "critical": 0, "total": 0}
    for r in rows:
        if not _incident_visible(user, allowed, r["lab_id"]):
            continue
        s["total"] += 1
        s[r["status"]] = s.get(r["status"], 0) + 1
        if r["severity"] == "critical":
            s["critical"] += 1
    return s


@app.post("/api/incidents/scan")
def incidents_scan(user: dict = Depends(require_incidents)):
    """Re-evaluate every device's alerts now and reconcile incidents (instead of waiting for the monitor)."""
    with db() as con:
        evaluate_devices(con)
    return incidents_summary(user)


@app.post("/api/incidents")
def create_incident(request: Request, body: dict = Body(...), user: dict = Depends(require_incidents)):
    title = clean(body.get("title"), 200)
    if not title:
        raise HTTPException(400, "A title is required")
    severity = body.get("severity", "warning")
    if severity not in INCIDENT_SEV:
        raise HTTPException(400, f"severity must be one of {list(INCIDENT_SEV)}")
    detail = clean(body.get("detail"), 1000)
    assignee = clean(body.get("assignee"), 64)
    device_id = clean(body.get("device_id"), 64)
    t = now()
    with db() as con:
        lab_id = None
        if device_id:
            drow = con.execute("SELECT id, lab_id FROM devices WHERE id=?", (device_id,)).fetchone()
            if not drow:
                raise HTTPException(404, "Device not found")
            if not device_in_scope(con, user, drow["lab_id"]):
                raise HTTPException(403, "That device is outside your scope")
            lab_id = drow["lab_id"]
        elif user["role"] == "school_manager":
            raise HTTPException(400, "Attach the incident to a device in your school")
        iid = uuid.uuid4().hex
        con.execute(
            "INSERT INTO incidents(id,device_id,lab_id,title,detail,severity,status,source,assignee,created,created_by,updated)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (iid, device_id or None, lab_id, title, detail, severity, "open", "manual", assignee, t, user["username"], t))
        audit(con, user["username"], client_ip(request), "incident_created", title)
        row = con.execute(_INC_COLS + "WHERE i.id=?", (iid,)).fetchone()
        out = serialize_incident(con, row)
    return out


@app.patch("/api/incidents/{iid}")
def update_incident(iid: str, request: Request, body: dict = Body(...), user: dict = Depends(require_incidents)):
    action = body.get("action", "")
    if action not in ("acknowledge", "resolve", "reopen", "assign", "note"):
        raise HTTPException(400, "action must be acknowledge, resolve, reopen, assign or note")
    t = now()
    with db() as con:
        allowed = allowed_lab_ids(con, user)
        row = con.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
        if not row or not _incident_visible(user, allowed, row["lab_id"]):
            raise HTTPException(404, "Incident not found")
        sets: dict[str, Any] = {"updated": t}
        if action == "acknowledge":
            if row["status"] != "open":
                raise HTTPException(400, "Only open incidents can be acknowledged")
            sets.update(status="acknowledged", ack_at=t, ack_by=user["username"])
        elif action == "resolve":
            if row["status"] == "resolved":
                raise HTTPException(400, "Already resolved")
            sets.update(status="resolved", resolved_at=t, resolved_by=user["username"], auto_resolved=0)
        elif action == "reopen":
            if row["status"] != "resolved":
                raise HTTPException(400, "Only resolved incidents can be reopened")
            sets.update(status="open", resolved_at=None, resolved_by="", auto_resolved=0)
        elif action == "assign":
            sets["assignee"] = clean(body.get("assignee"), 64)
        if "note" in body:
            sets["note"] = clean(body.get("note"), 1000)
        con.execute(f"UPDATE incidents SET {', '.join(k + '=?' for k in sets)} WHERE id=?", (*sets.values(), iid))
        audit(con, user["username"], client_ip(request), f"incident_{action}", row["title"])
        out = serialize_incident(con, con.execute(_INC_COLS + "WHERE i.id=?", (iid,)).fetchone())
    return out


# ---------------------------------------------------------------- license compliance API

def require_licensing(request: Request) -> dict:
    u = _authenticate(request)
    if u["role"] not in ADMIN_ROLES and u["role"] != "school_manager":
        raise HTTPException(403, "Not allowed")
    return u


def scope_name(con, st: str, sid) -> str:
    if st == "global" or not sid:
        return "All (global)"
    table = {"municipality": "municipalities", "school": "schools", "lab": "labs"}.get(st)
    row = con.execute(f"SELECT name FROM {table} WHERE id=?", (sid,)).fetchone() if table else None
    return row["name"] if row else "(deleted)"


def parse_date(s) -> float | None:
    s = clean(s, 20)
    if not s:
        return None
    try:
        return time.mktime(time.strptime(s, "%Y-%m-%d"))
    except ValueError:
        raise HTTPException(400, "Date must be YYYY-MM-DD")


def serialize_entitlement(con, e: dict) -> dict:
    cat = next((c for c in COMMERCIAL_SOFTWARE if c["key"] == e["product"]), None)
    return {**e, "product_label": cat["label"] if cat else "", "scope_name": scope_name(con, e["scope_type"], e["scope_id"])}


@app.get("/api/license/catalog")
def license_catalog(user: dict = Depends(require_licensing)):
    return {"products": [{"key": c["key"], "label": c["label"], "type": c["type"]} for c in COMMERCIAL_SOFTWARE],
            "license_types": list(LICENSE_TYPES)}


@app.get("/api/entitlements")
def list_entitlements(user: dict = Depends(require_licensing)):
    with db() as con:
        rows = [dict(e) for e in con.execute("SELECT * FROM license_entitlements ORDER BY name COLLATE NOCASE")]
        return [serialize_entitlement(con, e) for e in rows if entitlement_in_scope(con, user, e)]


@app.post("/api/entitlements")
def create_entitlement(request: Request, body: dict = Body(...), user: dict = Depends(require_admin_user)):
    name = _req_name(body)
    product = clean(body.get("product"), 40)
    if product and product not in {c["key"] for c in COMMERCIAL_SOFTWARE}:
        raise HTTPException(400, "Unknown product")
    ltype = body.get("license_type", "per_device")
    if ltype not in LICENSE_TYPES:
        raise HTTPException(400, f"license_type must be one of {list(LICENSE_TYPES)}")
    seats = _int(body, "seats", 0, 0, 1_000_000)
    scope_type = body.get("scope_type", "global")
    if scope_type not in ("global", "municipality", "school", "lab"):
        raise HTTPException(400, "scope_type must be global, municipality, school or lab")
    scope_id = clean(body.get("scope_id"), 32) or None
    expires = parse_date(body.get("expires"))
    with db() as con:
        if scope_type == "global":
            if not (user["role"] == "superadmin" or (user["role"] == "municipality_admin" and user["scope_type"] == "global")):
                raise HTTPException(403, "Only a global administrator can add a global entitlement")
        elif scope_type == "municipality":
            if not scope_id or not con.execute("SELECT 1 FROM municipalities WHERE id=?", (scope_id,)).fetchone() or not muni_in_scope(user, scope_id):
                raise HTTPException(400, "Choose a municipality within your scope")
        elif scope_type == "school":
            if not scope_id or not school_in_scope(con, user, scope_id):
                raise HTTPException(400, "Choose a school within your scope")
        elif scope_type == "lab":
            if not scope_id or not device_in_scope(con, user, scope_id):
                raise HTTPException(400, "Choose a lab within your scope")
        eid = uuid.uuid4().hex
        con.execute("INSERT INTO license_entitlements(id,name,product,publisher,edition,license_type,seats,scope_type,scope_id,expires,notes,created,created_by)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (eid, name, product, clean(body.get("publisher"), 120), clean(body.get("edition"), 80), ltype,
                     seats, scope_type, scope_id, expires, clean(body.get("notes"), 500), now(), user["username"]))
        audit(con, user["username"], client_ip(request), "entitlement_created", name, {"product": product, "seats": seats})
    return {"id": eid}


@app.patch("/api/entitlements/{eid}")
def update_entitlement(eid: str, request: Request, body: dict = Body(...), user: dict = Depends(require_admin_user)):
    with db() as con:
        e = con.execute("SELECT * FROM license_entitlements WHERE id=?", (eid,)).fetchone()
        if not e or not entitlement_in_scope(con, user, dict(e)):
            raise HTTPException(404, "Entitlement not found")
        fields, vals = [], []
        if "seats" in body:
            fields.append("seats=?"); vals.append(_int(body, "seats", 0, 0, 1_000_000))
        if "license_type" in body:
            if body["license_type"] not in LICENSE_TYPES:
                raise HTTPException(400, "Bad license_type")
            fields.append("license_type=?"); vals.append(body["license_type"])
        if "expires" in body:
            fields.append("expires=?"); vals.append(parse_date(body.get("expires")))
        if "notes" in body:
            fields.append("notes=?"); vals.append(clean(body.get("notes"), 500))
        if "name" in body:
            fields.append("name=?"); vals.append(_req_name(body))
        if fields:
            con.execute(f"UPDATE license_entitlements SET {', '.join(fields)} WHERE id=?", (*vals, eid))
        audit(con, user["username"], client_ip(request), "entitlement_updated", e["name"])
    return {"ok": True}


@app.delete("/api/entitlements/{eid}")
def delete_entitlement(eid: str, request: Request, user: dict = Depends(require_admin_user)):
    with db() as con:
        e = con.execute("SELECT * FROM license_entitlements WHERE id=?", (eid,)).fetchone()
        if not e or not entitlement_in_scope(con, user, dict(e)):
            raise HTTPException(404, "Entitlement not found")
        con.execute("DELETE FROM license_entitlements WHERE id=?", (eid,))
        audit(con, user["username"], client_ip(request), "entitlement_deleted", e["name"])
    return {"ok": True}


@app.get("/api/license/findings")
def license_findings(user: dict = Depends(require_licensing)):
    with db() as con:
        findings = compute_findings(con, user)
    summary: dict[str, int] = {}
    for f in findings:
        summary[f["category"]] = summary.get(f["category"], 0) + 1
    return {"findings": findings, "summary": summary}


# ---------------------------------------------------------------- agent API

@app.post("/api/agent/enroll")
def agent_enroll(request: Request, body: dict = Body(...)):
    ip = client_ip(request)
    rate_limit(f"enroll:{ip}", limit=20)
    token = clean(body.get("token"), 32).upper()
    hostname = clean(body.get("hostname"), 64) or "UNKNOWN"
    guid = clean(body.get("machine_guid"), 64)
    t = now()
    with db() as con:
        tk = con.execute("SELECT * FROM tokens WHERE token=?", (token,)).fetchone()
        if (not tk or tk["revoked"] or (tk["expires"] and tk["expires"] < t)
                or (tk["max_uses"] and tk["uses"] >= tk["max_uses"])):
            audit(con, "agent", ip, "enroll_rejected", hostname, {"token": token[:4] + "-****"})
            con.commit()
            raise HTTPException(403, "Registration token is invalid, expired or used up")
        if (tk["kind"] or "device") != "device":
            con.commit()
            raise HTTPException(403, "This is a gateway token; use it to enroll a Teacher Gateway")
        # If a Teacher Gateway relayed this enrollment, the station inherits the gateway's lab.
        gw = gateway_identity(con, request)
        lab_id = gw["lab_id"] if gw else tk["lab_id"]
        gateway_id = gw["id"] if gw else None
        secret = secrets.token_urlsafe(32)
        existing = None
        if guid:
            existing = con.execute("SELECT id FROM devices WHERE machine_guid=? AND hostname=? COLLATE NOCASE",
                                   (guid, hostname)).fetchone()
        if existing:
            device_id = existing["id"]
            con.execute("UPDATE devices SET secret_hash=?, last_seen=?, lab_id=COALESCE(?,lab_id), "
                        "gateway_id=COALESCE(?,gateway_id) WHERE id=?",
                        (sha256(secret), t, lab_id, gateway_id, device_id))
        else:
            device_id = uuid.uuid4().hex
            con.execute("INSERT INTO devices(id,secret_hash,machine_guid,hostname,group_name,enrolled,last_seen,"
                        "public_ip,lab_id,gateway_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (device_id, sha256(secret), guid, hostname, tk["group_name"] or "", t, t, ip, lab_id, gateway_id))
        con.execute("UPDATE tokens SET uses=uses+1 WHERE id=?", (tk["id"],))
        audit(con, "agent", ip, "device_reenrolled" if existing else "device_enrolled", hostname, {"token": token})
        notify(con, "enrolled", device_id, hostname,
               f"{'Re-enrolled' if existing else 'Enrolled'} with token {token} from {ip}")
    return AgentJSON({"device_id": device_id, "secret": secret, "interval": CHECKIN_INTERVAL})


def apply_result(con, device_id: str, r: Any, t: float) -> None:
    if not isinstance(r, dict):
        return
    try:
        cid = int(r.get("id"))
    except (TypeError, ValueError):
        return
    status = r.get("status")
    if status not in ("running", "success", "failed"):
        return
    exit_code = r.get("exit_code")
    exit_code = exit_code if isinstance(exit_code, int) else None
    output = str(r.get("output") or "")[-65536:]
    cmd = con.execute("SELECT type, created_by FROM commands WHERE id=? AND device_id=?", (cid, device_id)).fetchone()
    if not cmd:
        return
    cur = con.execute(
        "UPDATE commands SET status=?, output=CASE WHEN ?='' THEN output ELSE ? END, exit_code=?, finished=? "
        "WHERE id=? AND device_id=? AND status NOT IN ('success','failed','cancelled')",
        (status, output, output, exit_code, None if status == "running" else t, cid, device_id))
    if not cur.rowcount or status == "running":
        return
    data = r.get("data")
    if cmd["type"] in UPDATE_TYPES and isinstance(data, dict) and isinstance(data.get("updates"), list):
        upd = {"updates": [u for u in data["updates"][:500] if isinstance(u, dict)],
               "reboot_required": bool(data.get("reboot_required")), "error": ""}
        con.execute("UPDATE devices SET updates=?, updates_at=? WHERE id=?",
                    (json.dumps(upd, ensure_ascii=False), t, device_id))
    elif cmd["type"] in DATA_TYPES and data is not None:
        blob = json.dumps(data, ensure_ascii=False)
        if len(blob) <= 12_000_000:
            con.execute("UPDATE commands SET data=? WHERE id=?", (blob, cid))
            # keep only the latest 5 payloads of this kind per device
            con.execute("UPDATE commands SET data=NULL WHERE device_id=? AND type=? AND data IS NOT NULL AND id NOT IN "
                        "(SELECT id FROM commands WHERE device_id=? AND type=? AND data IS NOT NULL ORDER BY id DESC LIMIT 5)",
                        (device_id, cmd["type"], device_id, cmd["type"]))
    if status == "failed" and cmd["created_by"] != "auto":
        host = con.execute("SELECT hostname FROM devices WHERE id=?", (device_id,)).fetchone()
        first = next((ln for ln in output.splitlines() if ln.strip()), "no output")[:300]
        notify(con, "command_failed", device_id, host["hostname"] if host else "",
               f"{cmd['type'].replace('_', ' ')} failed: {first}")


@app.post("/api/agent/checkin")
def agent_checkin(request: Request, body: dict = Body(...), dev: dict = Depends(agent_device)):
    t = now()
    tel = body.get("telemetry") if isinstance(body.get("telemetry"), dict) else {}
    sets: dict[str, Any] = {
        "last_seen": t, "public_ip": client_ip(request),
        "agent_version": clean(body.get("agent_version"), 20),
        "telemetry": json.dumps(tel, ensure_ascii=False)[:200_000],
        "isolated": 1 if tel.get("isolated") else 0,
    }
    if tel.get("hostname"):
        sets["hostname"] = clean(tel["hostname"], 64)
    if isinstance(body.get("inventory"), dict):
        sets["inventory"] = json.dumps(body["inventory"], ensure_ascii=False)[:500_000]
        sets["inventory_at"] = t
    if isinstance(body.get("software"), list):
        sets["software"] = json.dumps(body["software"][:5000], ensure_ascii=False)
        sets["software_at"] = t
    with db() as con:
        gw = gateway_identity(con, request)
        if gw:
            sets["gateway_id"] = gw["id"]
            con.execute("UPDATE devices SET lab_id=COALESCE(lab_id,?) WHERE id=?", (gw["lab_id"], dev["id"]))
        prev = con.execute("SELECT updates_at, offline_notified, hostname FROM devices WHERE id=?", (dev["id"],)).fetchone()
        if prev["offline_notified"]:
            sets["offline_notified"] = 0
            notify(con, "offline", dev["id"], prev["hostname"], "Back online")
        con.execute(f"UPDATE devices SET {', '.join(k + '=?' for k in sets)} WHERE id=?", (*sets.values(), dev["id"]))
        for r in body.get("results") or []:
            apply_result(con, dev["id"], r, t)
        # Windows Update scan once a day (agents >= 1.1). Skip while a scan/install is pending or one ran recently.
        if (setting(con, "auto_update_scan") == "1" and vtuple(sets["agent_version"]) >= (1, 1)
                and (not prev["updates_at"] or t - prev["updates_at"] > UPDATE_SCAN_HOURS * 3600)
                and not con.execute("SELECT 1 FROM commands WHERE device_id=? AND type IN ('scan_updates','install_updates') "
                                    "AND (status IN ('queued','sent','running') OR created>?)",
                                    (dev["id"], t - 6 * 3600)).fetchone()):
            con.execute("INSERT INTO commands(device_id,type,params,status,created,created_by) VALUES(?,?,?,?,?,?)",
                        (dev["id"], "scan_updates", "{}", "queued", t, "auto"))
        # A reboot / baseline restore can't report its own result: the device coming back
        # with a newer boot time is the proof it happened.
        boot = tel.get("boot_time")
        if isinstance(boot, (int, float)):
            for c in con.execute("SELECT id, sent FROM commands WHERE device_id=? AND status IN ('sent','running') "
                                 "AND type IN ('reboot','reset_device')", (dev["id"],)).fetchall():
                if c["sent"] and boot > c["sent"]:
                    con.execute("UPDATE commands SET status='success', finished=?, "
                                "output=output || ? WHERE id=?",
                                (t, "\nDevice restarted and checked in again.", c["id"]))
        last = con.execute("SELECT MAX(ts) FROM metrics WHERE device_id=?", (dev["id"],)).fetchone()[0]
        if not last or t - last >= 60:
            cpu, mem, disk = device_metrics(tel)
            con.execute("INSERT INTO metrics VALUES(?,?,?,?,?)", (dev["id"], t, cpu, mem, disk))
            con.execute("DELETE FROM metrics WHERE device_id=? AND ts<?", (dev["id"], t - METRIC_RETENTION))
        rows = con.execute("SELECT id, type, params FROM commands WHERE device_id=? AND status='queued' ORDER BY id",
                           (dev["id"],)).fetchall()
        for c in rows:
            con.execute("UPDATE commands SET status='sent', sent=? WHERE id=?", (t, c["id"]))
        auto_upgrade = setting(con, "auto_update_agent") == "1"
    cmds = [{"id": c["id"], "type": c["type"], "params": jload(c["params"], {})} for c in rows]
    live = t - _viewing.get(dev["id"], 0) < 45
    resp = {"commands": cmds, "interval": LIVE_INTERVAL if live else CHECKIN_INTERVAL, "server_time": t}
    if auto_upgrade or any(c["type"] == "update_agent" for c in cmds):
        resp["agent"] = AGENT_RELEASE  # agent self-updates when its version differs
    return AgentJSON(resp)


@app.post("/api/agent/report")
def agent_report(body: dict = Body(...), dev: dict = Depends(agent_device)):
    """Immediate result push (used right before a reboot / reset / uninstall)."""
    with db() as con:
        for r in body.get("results") or []:
            apply_result(con, dev["id"], r, now())
    return AgentJSON({"ok": True})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=os.environ.get("KEM_HOST", "127.0.0.1"), port=int(os.environ.get("KEM_PORT", "8170")),
                proxy_headers=TRUST_PROXY)

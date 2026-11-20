"""KEM Teacher Gateway relay.

The School Lab Manager architecture is Central Server <- Teacher Gateway <- Student Stations.
Student agents never talk to the central server directly: they talk to the gateway running
on the teacher PC (or a dedicated lab box). This relay:

  * exposes the same agent endpoints students already use (/api/agent/enroll, /checkin, /report)
    on the local network, and forwards each call to the central server;
  * adds its own gateway credentials (X-Gateway-Id / X-Gateway-Secret) to every forwarded call,
    so the server learns which gateway - and therefore which lab - the station belongs to;
  * sends its own heartbeat to the server so the gateway shows online in the dashboard.

It uses only the Python standard library so a lab box needs nothing but Python 3.8+.

    python relay.py enroll --server https://kem.example.com --token ABCD-EFGH-JKLM
    python relay.py run                 # serves on 0.0.0.0:8171 by default

Config is stored next to this file as gateway.json (override with KEM_GATEWAY_CONFIG).
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CONFIG_PATH = Path(os.environ.get("KEM_GATEWAY_CONFIG", Path(__file__).resolve().parent / "gateway.json"))
RELAY_VERSION = "1.1.0"
# Only these paths are relayed to the central server. Everything else is refused so the
# gateway can never be used as an open proxy.
RELAY_PATHS = {"/api/agent/enroll", "/api/agent/checkin", "/api/agent/report"}
# Idempotent, secret-authenticated calls we can safely queue and replay if central is down.
# Enrollment is NOT cacheable: it needs central to mint a per-device secret, so it must stay online.
CACHEABLE = {"/api/agent/checkin", "/api/agent/report"}
FORWARD_HEADERS = ("x-device-id", "x-device-secret", "content-type")
MAX_SPOOL = 5000  # cap queued calls during a long outage (oldest dropped beyond this)


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        sys.exit(f"No gateway config at {CONFIG_PATH}. Run: python relay.py enroll --server <url> --token <token>")
    return json.loads(CONFIG_PATH.read_text())


def save_config(cfg: dict) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass


def _post(url: str, body: dict, headers: dict, timeout: int = 30) -> tuple[int, bytes]:
    return _post_raw(url, json.dumps(body).encode(), {"Content-Type": "application/json", **headers}, timeout)


def _post_raw(url: str, body: bytes, headers: dict, timeout: int = 30) -> tuple[int, bytes]:
    """POST raw bytes. Returns (status, body); a connection failure/timeout raises (central is down)."""
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _synth_response(cfg: dict, path: str) -> bytes:
    """What the gateway tells a student agent while central is unreachable: keep cycling, no new
    commands. Omit 'agent' so the agent does not try to self-update offline."""
    if path.endswith("/checkin"):
        return json.dumps({"ok": True, "interval": int(cfg.get("heartbeat_seconds", 15) or 15),
                           "commands": [], "cached": True}).encode()
    return json.dumps({"ok": True, "cached": True}).encode()


def enroll(args) -> None:
    server = args.server.rstrip("/")
    hostname = args.hostname or socket.gethostname()
    status, raw = _post(f"{server}/api/gateway/enroll", {"token": args.token, "hostname": hostname}, {})
    if status != 200:
        sys.exit(f"Enrollment failed ({status}): {raw.decode(errors='replace')}")
    data = json.loads(raw)
    cfg = {"central_url": server, "gateway_id": data["gateway_id"], "gateway_secret": data["secret"],
           "hostname": hostname, "lab_id": data.get("lab_id"),
           "listen_host": args.listen_host, "listen_port": args.listen_port,
           "heartbeat_seconds": max(15, int(data.get("interval") or 30))}
    save_config(cfg)
    print(f"Gateway enrolled as {data['gateway_id']} (lab {data.get('lab_id')}). Config written to {CONFIG_PATH}")
    print(f"Point student agents at:  http://{hostname}:{args.listen_port}")


class RelayHandler(BaseHTTPRequestHandler):
    cfg: dict = {}
    server_version = f"KEMGateway/{RELAY_VERSION}"

    def log_message(self, fmt, *a):  # keep the console quiet; failures are printed explicitly
        pass

    def _send(self, status: int, payload: bytes, ctype: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802
        if self.path == "/healthz":
            self._send(200, json.dumps({"ok": True, "role": "gateway", "version": RELAY_VERSION,
                                        "gateway_id": self.cfg.get("gateway_id")}).encode())
        else:
            self._send(404, b'{"error":"not found"}')

    def _spool(self, path: str, body: bytes, device_headers: dict) -> None:
        d = Path(self.cfg["spool_dir"])
        d.mkdir(parents=True, exist_ok=True)
        existing = sorted(d.glob("*.json"))
        for old in existing[: max(0, len(existing) - MAX_SPOOL + 1)]:  # keep the spool bounded
            old.unlink(missing_ok=True)
        rec = {"path": path, "headers": device_headers, "body_b64": base64.b64encode(body).decode(), "ts": time.time()}
        (d / f"{time.time():015.4f}-{os.urandom(4).hex()}.json").write_text(json.dumps(rec))

    def do_POST(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path not in RELAY_PATHS:
            self._send(404, b'{"error":"this gateway only relays agent endpoints"}')
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        device_headers = {h: self.headers.get(h) for h in FORWARD_HEADERS if self.headers.get(h)}
        headers = {"X-Gateway-Id": self.cfg["gateway_id"], "X-Gateway-Secret": self.cfg["gateway_secret"], **device_headers}
        url = self.cfg["central_url"].rstrip("/") + path
        cacheable = path in CACHEABLE
        try:
            req = urllib.request.Request(url, data=body, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=30) as r:
                self._send(r.status, r.read(), r.headers.get("Content-Type", "application/json"))
                return
        except urllib.error.HTTPError as e:
            # A 4xx is a real decision by central (bad secret, device gone) - pass it straight through.
            # A 5xx on a cacheable call is treated like an outage: queue and let the agent keep going.
            if not (cacheable and e.code >= 500):
                self._send(e.code, e.read(), e.headers.get("Content-Type", "application/json"))
                return
        except Exception:  # noqa: BLE001 - central unreachable / timed out
            if not cacheable:
                self._send(502, json.dumps({"error": "gateway could not reach central server; retry"}).encode())
                return
        # Cacheable call + central down/erroring: store it and keep the station cycling.
        self._spool(path, body, device_headers)
        self._send(200, _synth_response(self.cfg, path))


def flush_loop(cfg: dict) -> None:
    """Replay spooled student calls to central, oldest first, once it is reachable again."""
    d = Path(cfg["spool_dir"])
    base = {"X-Gateway-Id": cfg["gateway_id"], "X-Gateway-Secret": cfg["gateway_secret"]}
    while True:
        time.sleep(max(2, int(cfg.get("flush_seconds", 20))))
        if not d.exists():
            continue
        for f in sorted(d.glob("*.json")):
            try:
                rec = json.loads(f.read_text())
                body = base64.b64decode(rec["body_b64"])
            except Exception:  # noqa: BLE001 - corrupt record, drop it
                f.unlink(missing_ok=True)
                continue
            headers = {**base, **rec.get("headers", {})}
            try:
                status, _ = _post_raw(cfg["central_url"].rstrip("/") + rec["path"], body, headers, 30)
            except Exception:  # noqa: BLE001 - central still down; stop and try again next cycle
                break
            if status < 500:          # delivered (2xx) or definitively rejected (4xx) -> done with it
                f.unlink(missing_ok=True)
            else:                     # central is erroring; leave the rest queued
                break


def heartbeat_loop(cfg: dict) -> None:
    url = cfg["central_url"].rstrip("/") + "/api/gateway/checkin"
    headers = {"X-Gateway-Id": cfg["gateway_id"], "X-Gateway-Secret": cfg["gateway_secret"]}
    while True:
        try:
            _post(url, {"agent_version": RELAY_VERSION, "telemetry": {"hostname": cfg.get("hostname", "")}}, headers, 20)
        except Exception as e:  # noqa: BLE001
            print(f"[gateway] heartbeat failed: {e}")
        time.sleep(cfg.get("heartbeat_seconds", 30))


def run(_args) -> None:
    cfg = load_config()
    cfg.setdefault("spool_dir", str(CONFIG_PATH.resolve().parent / "gateway-spool"))
    RelayHandler.cfg = cfg
    threading.Thread(target=heartbeat_loop, args=(cfg,), name="gw-heartbeat", daemon=True).start()
    threading.Thread(target=flush_loop, args=(cfg,), name="gw-flush", daemon=True).start()
    host, port = cfg.get("listen_host", "0.0.0.0"), int(cfg.get("listen_port", 8171))
    httpd = ThreadingHTTPServer((host, port), RelayHandler)
    print(f"[gateway] relay {RELAY_VERSION} for {cfg['central_url']} listening on {host}:{port} "
          f"(gateway {cfg['gateway_id']}, lab {cfg.get('lab_id')}); offline spool at {cfg['spool_dir']}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def main() -> None:
    p = argparse.ArgumentParser(description="KEM Teacher Gateway relay")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enroll", help="enroll this gateway with the central server")
    e.add_argument("--server", required=True, help="central server base URL, e.g. https://kem.example.com")
    e.add_argument("--token", required=True, help="a gateway registration token from the dashboard")
    e.add_argument("--hostname", default="")
    e.add_argument("--listen-host", default="0.0.0.0")
    e.add_argument("--listen-port", type=int, default=8171)
    e.set_defaults(func=enroll)
    r = sub.add_parser("run", help="serve the relay (students connect here)")
    r.set_defaults(func=run)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

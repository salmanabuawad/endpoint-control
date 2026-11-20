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
RELAY_VERSION = "1.0.0"
# Only these paths are relayed to the central server. Everything else is refused so the
# gateway can never be used as an open proxy.
RELAY_PATHS = {"/api/agent/enroll", "/api/agent/checkin", "/api/agent/report"}
FORWARD_HEADERS = ("x-device-id", "x-device-secret", "content-type")


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
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


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

    def do_POST(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path not in RELAY_PATHS:
            self._send(404, b'{"error":"this gateway only relays agent endpoints"}')
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        headers = {"X-Gateway-Id": self.cfg["gateway_id"], "X-Gateway-Secret": self.cfg["gateway_secret"]}
        for h in FORWARD_HEADERS:
            v = self.headers.get(h)
            if v:
                headers[h] = v
        url = self.cfg["central_url"].rstrip("/") + path
        try:
            req = urllib.request.Request(url, data=body, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=30) as r:
                self._send(r.status, r.read(), r.headers.get("Content-Type", "application/json"))
        except urllib.error.HTTPError as e:
            self._send(e.code, e.read(), e.headers.get("Content-Type", "application/json"))
        except Exception as e:  # noqa: BLE001 - the central server is unreachable; tell the agent to retry
            self._send(502, json.dumps({"error": f"gateway could not reach central server: {e}"}).encode())


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
    RelayHandler.cfg = cfg
    threading.Thread(target=heartbeat_loop, args=(cfg,), name="gw-heartbeat", daemon=True).start()
    host, port = cfg.get("listen_host", "0.0.0.0"), int(cfg.get("listen_port", 8171))
    httpd = ThreadingHTTPServer((host, port), RelayHandler)
    print(f"[gateway] relay {RELAY_VERSION} for {cfg['central_url']} listening on {host}:{port} "
          f"(gateway {cfg['gateway_id']}, lab {cfg.get('lab_id')})")
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

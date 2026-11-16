from __future__ import annotations

import secrets
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_from_directory

PORT = 8765

# When packaged by PyInstaller, bundled data lives in sys._MEIPASS.
if getattr(sys, "frozen", False):
    APP_DIR = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
else:
    APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"

SHARED_DIR = Path.home() / "RemoteLab_Shared"
SHARED_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")
lock = threading.Lock()

PAIR_CODE = f"{secrets.randbelow(1_000_000):06d}"
pending: dict[str, dict[str, Any]] = {}
active_tokens: set[str] = set()
messages: list[dict[str, Any]] = []
started_at = time.time()
last_phone_seen = 0.0

# Pairing-code brute-force protection and request-flood cap.
MAX_FAILED_CODES = 5
LOCKOUT_SECONDS = 30
MAX_PENDING = 10
failed_codes = 0
locked_until = 0.0


def device_name() -> str:
    return socket.gethostname()


def safe_equal(a: str, b: str) -> bool:
    """Constant-time comparison that also works with non-ASCII input."""
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def is_laptop() -> bool:
    """True only for requests coming from this laptop itself (the visible device console)."""
    return request.remote_addr in ("127.0.0.1", "::1", "::ffff:127.0.0.1")


def laptop_only():
    """Approving, declining and listing requests must happen ON the laptop."""
    if not is_laptop():
        return jsonify({"error": "This action is only available on the laptop."}), 403
    return None


def phone_authorized() -> bool:
    token = request.headers.get("X-RemoteLab-Token", "")
    if not token:
        return False
    with lock:
        return any(safe_equal(token, valid) for valid in active_tokens)


def cleanup_pending() -> None:
    """Drop expired/finished requests. Caller must hold the lock."""
    now = time.time()
    for key in [k for k, v in pending.items() if now - v["created"] > 300]:
        pending.pop(key, None)


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def phone_page():
    return send_from_directory(STATIC_DIR, "phone.html")


@app.get("/device")
def device_page():
    return send_from_directory(STATIC_DIR, "device.html")


@app.get("/api/info")
def info():
    return jsonify({"device": device_name(), "pair_code_hint": "Enter the code shown in this laptop's terminal."})


@app.post("/api/pair")
def pair():
    global last_phone_seen, failed_codes, locked_until
    data = request.get_json(silent=True) or {}
    code = str(data.get("code", "")).strip()
    with lock:
        if time.time() < locked_until:
            wait = int(locked_until - time.time()) + 1
            return jsonify({"error": f"Too many wrong codes. Try again in {wait} seconds."}), 429
        if not safe_equal(code, PAIR_CODE):
            failed_codes += 1
            if failed_codes >= MAX_FAILED_CODES:
                failed_codes = 0
                locked_until = time.time() + LOCKOUT_SECONDS
            return jsonify({"error": "That pairing code is incorrect."}), 403
        failed_codes = 0
        cleanup_pending()
        if sum(1 for v in pending.values() if v["status"] == "pending") >= MAX_PENDING:
            return jsonify({"error": "Too many pending requests. Try again shortly."}), 429
    request_id = secrets.token_urlsafe(18)
    with lock:
        pending[request_id] = {"status": "pending", "created": time.time(), "token": None}
    last_phone_seen = time.time()
    return jsonify({"request_id": request_id, "status": "awaiting_approval"})


@app.get("/api/pair-status")
def pair_status():
    request_id = request.args.get("id", "")
    with lock:
        item = pending.get(request_id)
        if not item:
            return jsonify({"status": "unknown"}), 404
        if time.time() - item["created"] > 300:
            pending.pop(request_id, None)
            return jsonify({"status": "expired"})
        if item["status"] == "approved":
            return jsonify({"status": "approved", "token": item["token"], "device": device_name()})
        return jsonify({"status": item["status"]})


@app.get("/api/pending")
def get_pending():
    denied = laptop_only()
    if denied:
        return denied
    with lock:
        rows = [
            {"id": key, "age": int(time.time() - value["created"])}
            for key, value in pending.items()
            if value["status"] == "pending" and time.time() - value["created"] <= 300
        ]
    return jsonify({"requests": rows})


@app.post("/api/approve")
def approve():
    denied = laptop_only()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    request_id = str(data.get("id", ""))
    with lock:
        item = pending.get(request_id)
        if not item or item["status"] != "pending":
            return jsonify({"error": "No pending request was found."}), 404
        token = secrets.token_urlsafe(32)
        item["status"] = "approved"
        item["token"] = token
        active_tokens.add(token)
    return jsonify({"status": "approved"})


@app.post("/api/deny")
def deny():
    denied = laptop_only()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    request_id = str(data.get("id", ""))
    with lock:
        item = pending.get(request_id)
        if item:
            item["status"] = "denied"
    return jsonify({"status": "denied"})


@app.get("/api/status")
def status():
    global last_phone_seen
    if not phone_authorized():
        return jsonify({"error": "Not paired."}), 401
    last_phone_seen = time.time()
    return jsonify({
        "device": device_name(),
        "connected": True,
        "uptime_seconds": int(time.time() - started_at),
        "shared_folder": str(SHARED_DIR),
    })


@app.post("/api/message")
def send_message():
    global last_phone_seen
    if not phone_authorized():
        return jsonify({"error": "Not paired."}), 401
    data = request.get_json(silent=True) or {}
    body = str(data.get("message", "")).strip()
    if not body or len(body) > 300:
        return jsonify({"error": "Message must be 1–300 characters."}), 400
    with lock:
        messages.append({"id": secrets.token_hex(8), "text": body, "time": time.strftime("%H:%M:%S")})
        del messages[:-30]
    last_phone_seen = time.time()
    return jsonify({"sent": True})


@app.get("/api/messages")
def get_messages():
    # The visible laptop console (device.html) reads the inbox from this machine;
    # a paired phone reads it with its token. Nobody else can.
    if not (is_laptop() or phone_authorized()):
        return jsonify({"error": "Not paired."}), 401
    after = request.args.get("after", "")
    with lock:
        rows = list(messages)
    if after:
        for index, row in enumerate(rows):
            if row["id"] == after:
                rows = rows[index + 1:]
                break
    return jsonify({"messages": rows})


@app.get("/api/files")
def files():
    if not phone_authorized():
        return jsonify({"error": "Not paired."}), 401
    # Only names and sizes in the dedicated RemoteLab_Shared folder are exposed.
    rows = []
    try:
        SHARED_DIR.mkdir(parents=True, exist_ok=True)
        entries = sorted(SHARED_DIR.iterdir(), key=lambda p: p.name.lower())
    except OSError:
        entries = []
    for item in entries:
        try:
            if item.is_file() and not item.is_symlink():
                rows.append({"name": item.name, "bytes": item.stat().st_size})
        except OSError:
            pass
    return jsonify({"folder": SHARED_DIR.name, "files": rows})


@app.post("/api/disconnect")
def disconnect():
    token = request.headers.get("X-RemoteLab-Token", "")
    with lock:
        for valid in list(active_tokens):
            if safe_equal(token, valid):
                active_tokens.discard(valid)
    return jsonify({"disconnected": True})


def lan_ip() -> str:
    """Best-effort LAN address (no traffic is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("10.255.255.255", 1))
            return probe.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "your-laptop-local-IP"


def main() -> None:
    print("\n" + "=" * 56)
    print(" REMOTELAB — visible, consent-based school-project demo")
    print("=" * 56)
    print(f"Laptop name : {device_name()}")
    print(f"Pairing code: {PAIR_CODE}")
    print(f"Shared folder: {SHARED_DIR}")
    print(f"\nOn the Lenovo, open http://127.0.0.1:{PORT}/device")
    print("On your phone, open the LAN address shown below.")
    print("Keep this window open. Close it or press Ctrl+C to stop RemoteLab.\n")
    print(f"Phone dashboard: http://{lan_ip()}:{PORT}")
    # Open the visible laptop console for the user (a normal browser tab they can close).
    threading.Timer(1.2, lambda: webbrowser.open(f"http://127.0.0.1:{PORT}/device")).start()
    try:
        app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
    except OSError as exc:
        print(f"\nCould not start the server on port {PORT}: {exc}")
        print("Is RemoteLab already running? Close the other window and try again.")
        input("Press Enter to exit...")


if __name__ == "__main__":
    main()

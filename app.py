from __future__ import annotations

import csv
import io
import os
import platform
import re
import secrets
import shutil
import socket
import sqlite3
from functools import wraps
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil
from flask import Flask, jsonify, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from detection_engine import analyze_log_line, analyze_process, correlate, incident_to_dict, rule_catalog

try:
    import win32evtlog
    import win32evtlogutil
except ImportError:
    win32evtlog = None
    win32evtlogutil = None


BASE_DIR = Path(__file__).resolve().parent
app = Flask(__name__)
# A deployment should set SECRET_KEY.  A generated fallback avoids shipping a
# predictable development secret (sessions simply expire when the app restarts).
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
DB_PATH = BASE_DIR / "threat_hunter.db"
DEMO_DB_PATH = BASE_DIR / "threat_hunter_demo.db"
# Seed a fresh checkout with the committed synthetic dataset. Keep using the
# local runtime database once it exists so the repository sample stays pristine.
if not DB_PATH.exists() and DEMO_DB_PATH.exists():
    shutil.copyfile(DEMO_DB_PATH, DB_PATH)


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def database() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_database() -> None:
    with database() as connection:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin', 'analyst')),
              active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS investigations (
              id INTEGER PRIMARY KEY, alert_title TEXT NOT NULL, severity TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'Open', analyst TEXT NOT NULL, notes TEXT DEFAULT '', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reports (
              id INTEGER PRIMARY KEY, title TEXT NOT NULL, alert_count INTEGER NOT NULL,
              created_by TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alert_reports (
              id INTEGER PRIMARY KEY, alert_title TEXT NOT NULL, severity TEXT NOT NULL,
              risk_score INTEGER NOT NULL, summary TEXT NOT NULL, recommended_action TEXT NOT NULL,
              created_by TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alerts (
              id INTEGER PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL,
              risk_score INTEGER NOT NULL, source TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Open',
              explanation TEXT NOT NULL, recommended_action TEXT NOT NULL, timestamp TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evidence (
              id INTEGER PRIMARY KEY, alert_id INTEGER NOT NULL, evidence_type TEXT NOT NULL,
              evidence_detail TEXT NOT NULL, source TEXT NOT NULL, timestamp TEXT NOT NULL,
              FOREIGN KEY(alert_id) REFERENCES alerts(id)
            );
            CREATE TABLE IF NOT EXISTS process_baselines (
              process_key TEXT PRIMARY KEY, samples INTEGER NOT NULL DEFAULT 0,
              cpu_avg REAL NOT NULL DEFAULT 0, memory_avg REAL NOT NULL DEFAULT 0, updated_at TEXT NOT NULL
            );
        """)
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(investigations)")}
        if "analyst_id" not in columns:
            connection.execute("ALTER TABLE investigations ADD COLUMN analyst_id INTEGER")
        if "resolution_note" not in columns:
            connection.execute("ALTER TABLE investigations ADD COLUMN resolution_note TEXT DEFAULT ''")
        if "alert_id" not in columns:
            connection.execute("ALTER TABLE investigations ADD COLUMN alert_id INTEGER")
        if "analyst_note" not in columns:
            connection.execute("ALTER TABLE investigations ADD COLUMN analyst_note TEXT DEFAULT ''")
            connection.execute("UPDATE investigations SET analyst_note = notes WHERE notes != ''")
        if "admin_note" not in columns:
            connection.execute("ALTER TABLE investigations ADD COLUMN admin_note TEXT DEFAULT ''")
        report_columns = {row["name"] for row in connection.execute("PRAGMA table_info(alert_reports)")}
        if "report_type" not in report_columns:
            connection.execute("ALTER TABLE alert_reports ADD COLUMN report_type TEXT NOT NULL DEFAULT 'Individual Alert'")
        if not connection.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            bootstrap_password = os.environ.get("SENTINELOPS_BOOTSTRAP_PASSWORD")
            if not bootstrap_password:
                return
            connection.execute(
                "INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
                ("System Administrator", "admin@localhost", generate_password_hash(bootstrap_password), "admin", now_utc()),
            )


def current_user() -> dict[str, Any] | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    with database() as connection:
        row = connection.execute("SELECT id, name, email, role, active FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row and row["active"] else None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return jsonify({"error": "Please sign in to continue."}), 401
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return jsonify({"error": "Please sign in to continue."}), 401
        if user["role"] != "admin":
            return jsonify({"error": "Administrator access is required."}), 403
        return view(*args, **kwargs)
    return wrapped


init_database()


def process_rows() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    remote_by_pid: dict[int, int] = {}
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.pid and conn.raddr:
                remote_by_pid[conn.pid] = remote_by_pid.get(conn.pid, 0) + 1
    except psutil.AccessDenied:
        pass

    rows: list[dict[str, Any]] = []
    all_indicators = []
    attrs = ["pid", "ppid", "name", "username", "exe", "cmdline", "memory_info", "memory_percent", "cpu_percent", "status"]

    for proc in psutil.process_iter(attrs=attrs):
        try:
            info = proc.info
            mem = info.get("memory_info")
            cmdline = info.get("cmdline") or []
            pid = info.get("pid")
            row = {
                "pid": pid,
                "ppid": info.get("ppid"),
                "name": info.get("name") or "unknown",
                "username": info.get("username") or "unknown",
                "exe": info.get("exe") or "",
                "cmdline": " ".join(cmdline) if isinstance(cmdline, list) else str(cmdline or ""),
                "status": info.get("status") or "unknown",
                "memory_mb": round(getattr(mem, "rss", 0) / (1024 * 1024), 1) if mem else 0,
                "memory_percent": round(float(info.get("memory_percent") or 0), 1),
                "cpu_percent": round(float(info.get("cpu_percent") or 0), 1),
                "remote_count": remote_by_pid.get(pid, 0),
            }
            rows.append(row)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Resolve the process tree before analysis so parent process is real context.
    names_by_pid = {item["pid"]: item["name"] for item in rows}
    with database() as connection:
        for row in rows:
            row["parent_name"] = names_by_pid.get(row["ppid"], "unknown")
            process_key = f"{row['name'].lower()}|{row['username'].lower()}|{row['exe'].lower()}"
            baseline = connection.execute("SELECT samples, cpu_avg, memory_avg FROM process_baselines WHERE process_key = ?", (process_key,)).fetchone()
            row["baseline"] = dict(baseline) if baseline else {"samples": 0, "cpu_avg": 0, "memory_avg": 0}
            indicators = analyze_process(row)
            row["risk"] = min(100, sum(item.score for item in indicators) + (10 if len(indicators) > 1 else 0))
            row["verdict"] = "review" if row["risk"] >= 45 else "monitor" if row["risk"] else "normal"
            row["hunt_rules"] = [{"rule_id": item.rule_id, "rule_name": item.rule_name, "score": item.score, "tactic": item.tactic} for item in indicators]
            all_indicators.extend(indicators)
            samples = int(row["baseline"]["samples"])
            # Running average is enough for a small, explainable recent baseline.
            new_samples = min(samples + 1, 30)
            cpu_avg = (float(row["baseline"]["cpu_avg"]) * min(samples, 29) + row["cpu_percent"]) / new_samples
            memory_avg = (float(row["baseline"]["memory_avg"]) * min(samples, 29) + row["memory_mb"]) / new_samples
            connection.execute("INSERT INTO process_baselines(process_key, samples, cpu_avg, memory_avg, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(process_key) DO UPDATE SET samples=excluded.samples, cpu_avg=excluded.cpu_avg, memory_avg=excluded.memory_avg, updated_at=excluded.updated_at", (process_key, new_samples, cpu_avg, memory_avg, now_utc()))
    rows.sort(key=lambda item: (item["risk"], item["memory_mb"], item["remote_count"]), reverse=True)
    incidents = [incident_to_dict(incident) for incident in correlate(all_indicators)]
    save_alerts(incidents)
    return rows[:120], incidents


def save_alerts(incidents: list[dict[str, Any]]) -> None:
    """Persist hunt alerts and their evidence for the Alert -> Evidence workflow."""
    with database() as connection:
        for incident in incidents:
            timestamp = incident.get("generated_at", now_utc())
            source = ", ".join(sorted({str(item.get("source_type", "unknown")) for item in incident.get("evidence", [])}))
            cursor = connection.execute("INSERT INTO alerts(title, severity, risk_score, source, status, explanation, recommended_action, timestamp) VALUES (?, ?, ?, ?, 'Open', ?, ?, ?)", (incident["title"], incident["severity"], incident["risk_score"], source or "live hunt", incident["explanation"], incident["recommended_action"], timestamp))
            incident["alert_id"] = cursor.lastrowid
            for item in incident.get("evidence", []):
                connection.execute("INSERT INTO evidence(alert_id, evidence_type, evidence_detail, source, timestamp) VALUES (?, ?, ?, ?, ?)", (cursor.lastrowid, item.get("tactic", "context"), item.get("detail", ""), item.get("source_id", ""), timestamp))


def connections() -> list[dict[str, Any]]:
    output = []
    try:
        items = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return output

    for conn in items:
        if not conn.raddr:
            continue
        try:
            process_name = psutil.Process(conn.pid).name() if conn.pid else "unknown"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            process_name = "unknown"
        output.append(
            {
                "pid": conn.pid,
                "process": process_name,
                "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                "status": conn.status,
            }
        )
    return output[:80]


def read_tail(path: Path, lines: int) -> list[str]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return [line.rstrip("\n") for line in handle.readlines()[-lines:]]


def windows_event_tail(channel: str, lines: int) -> list[str]:
    if win32evtlog is None or win32evtlogutil is None:
        raise RuntimeError("Windows Event Log support needs pywin32.")

    handle = win32evtlog.OpenEventLog("localhost", channel)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    output: list[str] = []
    while len(output) < lines:
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        if not events:
            break
        for event in events:
            try:
                message = win32evtlogutil.SafeFormatMessage(event, channel)
            except Exception:
                message = " ".join(str(item) for item in (event.StringInserts or []))
            output.append(f"{event.TimeGenerated} {event.SourceName} {event.EventID & 0xFFFF} {message}".strip())
            if len(output) >= lines:
                break
    win32evtlog.CloseEventLog(handle)
    return output


def scan_lines(lines: list[str], source: str) -> dict[str, Any]:
    indicators = []
    rows = []
    for number, line in enumerate(lines, start=1):
        line_indicators = analyze_log_line(line, source, number)
        indicators.extend(line_indicators)
        match = re.match(r"(?P<timestamp>\S+(?:\s+\S+)?)\s+(?P<event_source>\S+)\s+(?P<event_id>\d+)\s*(?P<message>.*)", line)
        rows.append({"line_number": number, "text": line, "risk": max((item.score for item in line_indicators), default=0), "timestamp": match.group("timestamp") if match else "", "event_source": match.group("event_source") if match else source, "event_id": match.group("event_id") if match else "", "event_type": line_indicators[0].title if line_indicators else "Informational / no rule match", "why_it_matters": line_indicators[0].detail if line_indicators else "No suspicious rule context found."})

    incidents = [incident_to_dict(incident) for incident in correlate(indicators)]
    return {"source": source, "rows": rows, "incidents": incidents, "generated_at": now_utc()}


@app.get("/")
def index() -> str:
    return render_template("index.html")


@app.post("/api/auth/login")
def login() -> Any:
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    selected_role = str(data.get("role", ""))
    with database() as connection:
        row = connection.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not row or not row["active"] or not check_password_hash(row["password_hash"], password) or (selected_role and row["role"] != selected_role):
        return jsonify({"error": "Invalid email or password."}), 401
    session.clear()
    session["user_id"] = row["id"]
    return jsonify({"user": current_user()})


@app.post("/api/auth/logout")
def logout() -> Any:
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/auth/me")
def me() -> Any:
    user = current_user()
    return jsonify({"user": user}) if user else (jsonify({"error": "Not signed in."}), 401)


@app.get("/api/users")
@admin_required
def users() -> Any:
    with database() as connection:
        rows = connection.execute("SELECT id, name, email, role, active, created_at FROM users ORDER BY id DESC").fetchall()
    return jsonify({"users": [dict(row) for row in rows]})


@app.post("/api/users")
@admin_required
def add_user() -> Any:
    data = request.get_json(silent=True) or {}
    name, email, password = (str(data.get(key, "")).strip() for key in ("name", "email", "password"))
    role = str(data.get("role", "analyst"))
    if not name or "@" not in email or len(password) < 8 or role not in {"admin", "analyst"}:
        return jsonify({"error": "Enter a name, valid email, role, and a password of at least 8 characters."}), 400
    try:
        with database() as connection:
            connection.execute("INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (name, email.lower(), generate_password_hash(password), role, now_utc()))
    except sqlite3.IntegrityError:
        return jsonify({"error": "A user with this email already exists."}), 409
    return jsonify({"ok": True}), 201


@app.delete("/api/users/<int:user_id>")
@admin_required
def delete_user(user_id: int) -> Any:
    """Remove an analyst account. Administrator accounts are protected."""
    with database() as connection:
        row = connection.execute("SELECT id, role FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            return jsonify({"error": "User not found."}), 404
        if row["role"] != "analyst":
            return jsonify({"error": "Only analyst accounts can be deleted here."}), 400
        connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return jsonify({"ok": True})


@app.get("/api/investigations")
@login_required
def investigations() -> Any:
    with database() as connection:
        rows = connection.execute("SELECT * FROM investigations ORDER BY id DESC LIMIT 50").fetchall()
    return jsonify({"investigations": [dict(row) for row in rows]})


@app.post("/api/investigations")
@login_required
def create_investigation() -> Any:
    data, user = request.get_json(silent=True) or {}, current_user()
    title = str(data.get("alert_title", "")).strip()
    severity = str(data.get("severity", "medium")).lower()
    notes = str(data.get("notes", "")).strip()
    alert_id = data.get("alert_id")
    if not title or severity not in {"critical", "high", "medium", "low"}:
        return jsonify({"error": "An alert title and valid severity are required."}), 400
    with database() as connection:
        cursor = connection.execute("INSERT INTO investigations (alert_title, severity, analyst, analyst_id, alert_id, notes, analyst_note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (title, severity, user["name"], user["id"], alert_id, notes, notes, now_utc()))
        if alert_id:
            connection.execute("UPDATE alerts SET status = 'Investigating' WHERE id = ?", (alert_id,))
    return jsonify({"id": cursor.lastrowid, "ok": True}), 201


@app.patch("/api/investigations/<int:investigation_id>")
@login_required
def update_investigation(investigation_id: int) -> Any:
    data, user = request.get_json(silent=True) or {}, current_user()
    status_value = str(data.get("status", ""))
    resolution_note = str(data.get("resolution_note", "")).strip()
    analyst_note = str(data.get("analyst_note", "")).strip()
    admin_note = str(data.get("admin_note", "")).strip()
    if status_value not in {"Open", "Investigating", "Resolved", "False Positive"}:
        return jsonify({"error": "Invalid investigation status."}), 400
    if status_value == "False Positive" and not resolution_note:
        return jsonify({"error": "Record why this alert is legitimate before marking it False Positive."}), 400
    with database() as connection:
        item = connection.execute("SELECT analyst_id, alert_id, status, resolution_note, admin_note FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
        if not item:
            return jsonify({"error": "Investigation not found."}), 404
        if user["role"] != "admin" and item["analyst_id"] not in {None, user["id"]}:
            return jsonify({"error": "You can update only investigations assigned to you."}), 403
        if user["role"] != "admin":
            admin_note = item["admin_note"]  # Analysts cannot overwrite the administrator response.
        connection.execute("UPDATE investigations SET status = ?, resolution_note = ?, analyst_note = ?, admin_note = ? WHERE id = ?", (status_value, resolution_note or item["resolution_note"], analyst_note, admin_note, investigation_id))
        if item["alert_id"]:
            connection.execute("UPDATE alerts SET status = ? WHERE id = ?", (status_value, item["alert_id"]))
    return jsonify({"ok": True})


@app.get("/api/alerts")
@admin_required
def stored_alerts() -> Any:
    """Administrator alert queue, retained after a live analyst hunt ends."""
    with database() as connection:
        rows = connection.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify({"alerts": [dict(row) for row in rows]})


@app.get("/api/reports")
@login_required
def reports() -> Any:
    with database() as connection:
        rows = connection.execute("SELECT * FROM reports ORDER BY id DESC LIMIT 30").fetchall()
    return jsonify({"reports": [dict(row) for row in rows]})


@app.get("/api/rules")
@login_required
def rules() -> Any:
    return jsonify({"rules": rule_catalog()})


@app.get("/api/alert-reports")
@login_required
def alert_reports() -> Any:
    with database() as connection:
        rows = connection.execute("SELECT * FROM alert_reports ORDER BY id DESC LIMIT 50").fetchall()
    return jsonify({"reports": [dict(row) for row in rows]})


@app.post("/api/alert-reports")
@login_required
def create_alert_report() -> Any:
    data, user = request.get_json(silent=True) or {}, current_user()
    title = str(data.get("alert_title", "")).strip()
    severity_value = str(data.get("severity", "")).lower()
    summary = str(data.get("summary", "")).strip()
    action = str(data.get("recommended_action", "")).strip()
    report_type = str(data.get("report_type", "Individual Alert")).strip()
    try:
        risk_score = int(data.get("risk_score", 0))
    except (TypeError, ValueError):
        risk_score = 0
    if report_type not in {"Individual Threat", "Individual Alert"}:
        return jsonify({"error": "Invalid report type."}), 400
    if not title or severity_value not in {"critical", "high", "medium", "low"} or not summary or not action:
        return jsonify({"error": "Complete alert information is required to generate a report."}), 400
    created_at = now_utc()
    with database() as connection:
        cursor = connection.execute(
            "INSERT INTO alert_reports (alert_title, severity, risk_score, summary, recommended_action, report_type, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (title, severity_value, risk_score, summary, action, report_type, user["name"], created_at),
        )
    return jsonify({"id": cursor.lastrowid, "created_at": created_at}), 201


@app.get("/api/status")
@login_required
def status() -> Any:
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage(str(BASE_DIR.anchor or BASE_DIR))
    return jsonify(
        {
            "host": socket.gethostname(),
            "platform": platform.platform(),
            "now": now_utc(),
            "cpu_percent": round(psutil.cpu_percent(interval=0.1), 1),
            "memory": {
                "used_gb": round(memory.used / (1024**3), 2),
                "total_gb": round(memory.total / (1024**3), 2),
                "percent": round(memory.percent, 1),
            },
            "disk": {
                "used_gb": round(disk.used / (1024**3), 2),
                "total_gb": round(disk.total / (1024**3), 2),
                "percent": round(disk.percent, 1),
            },
        }
    )


@app.get("/api/snapshot")
@login_required
def snapshot() -> Any:
    processes, incidents = process_rows()
    safe_processes = [
        {"name": item["name"], "pid": item["pid"], "memory_mb": item["memory_mb"]}
        for item in processes if item["verdict"] == "normal"
    ]
    return jsonify({
        "generated_at": now_utc(), "processes": processes, "connections": connections(), "incidents": incidents,
        "safe_processes": safe_processes, "safe_count": len(safe_processes),
    })


@app.get("/api/logs/file")
@login_required
def file_logs() -> Any:
    path_text = request.args.get("path", "").strip()
    line_count = min(int(request.args.get("lines", "200")), 1000)
    if not path_text:
        return jsonify({"error": "Provide a log file path."}), 400
    path = Path(path_text).expanduser()
    if not path.is_file():
        return jsonify({"error": f"File not found: {path}"}), 404
    return jsonify(scan_lines(read_tail(path, line_count), str(path)))


@app.get("/api/logs/windows")
@login_required
def windows_logs() -> Any:
    channel = request.args.get("channel", "System").strip() or "System"
    line_count = min(int(request.args.get("lines", "200")), 1000)
    try:
        return jsonify(scan_lines(windows_event_tail(channel, line_count), f"Windows:{channel}"))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.post("/api/export")
@login_required
def export_report() -> Any:
    incidents = (request.get_json(silent=True) or {}).get("incidents", [])
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["severity", "risk_score", "title", "explanation", "recommended_action"])
    for incident in incidents:
        writer.writerow(
            [
                incident.get("severity", ""),
                incident.get("risk_score", ""),
                incident.get("title", ""),
                incident.get("explanation", ""),
                incident.get("recommended_action", ""),
            ]
        )
    user = current_user()
    created_at = now_utc()
    with database() as connection:
        connection.execute("INSERT INTO reports (title, alert_count, created_by, created_at) VALUES (?, ?, ?, ?)",
            ("Threat investigation export", len(incidents), user["name"], created_at))
    return jsonify({"csv": output.getvalue(), "generated_at": created_at})


if __name__ == "__main__":
    init_database()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=os.environ.get("FLASK_DEBUG") == "1")

"""
Honeypot SOC Dashboard — Flask Backend
Serves the dashboard UI and REST API endpoints for honeypot data.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from sqlalchemy import func, desc
from datetime import datetime, timezone, timedelta

import config
from data_collection.db import init_db, get_session
from data_collection.models import Connection, Credential, Command, Payload, Session

app = Flask(__name__)
CORS(app)

# ── Initialise DB ────────────────────────────────────────────────────
init_db(config.DATABASE_PATH)


# ── Dashboard Page ───────────────────────────────────────────────────

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


# ── API Endpoints ────────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    """Return summary statistics."""
    session = get_session()
    try:
        total_connections = session.query(func.count(Connection.id)).scalar() or 0
        total_credentials = session.query(func.count(Credential.id)).scalar() or 0
        total_commands = session.query(func.count(Command.id)).scalar() or 0
        total_payloads = session.query(func.count(Payload.id)).scalar() or 0
        total_sessions = session.query(func.count(Session.id)).scalar() or 0
        unique_ips = session.query(func.count(func.distinct(Connection.src_ip))).scalar() or 0

        return jsonify({
            "total_connections": total_connections,
            "total_credentials": total_credentials,
            "total_commands": total_commands,
            "total_payloads": total_payloads,
            "total_sessions": total_sessions,
            "unique_ips": unique_ips,
        })
    finally:
        session.close()


@app.route("/api/top-ips")
def api_top_ips():
    """Return top 10 attacker IPs by connection count."""
    session = get_session()
    try:
        results = (
            session.query(Connection.src_ip, func.count(Connection.id).label("count"))
            .group_by(Connection.src_ip)
            .order_by(desc("count"))
            .limit(10)
            .all()
        )
        return jsonify([{"ip": r[0], "count": r[1]} for r in results])
    finally:
        session.close()


@app.route("/api/top-credentials")
def api_top_credentials():
    """Return top 10 most-used credential pairs."""
    session = get_session()
    try:
        results = (
            session.query(
                Credential.username, Credential.password,
                func.count(Credential.id).label("count")
            )
            .group_by(Credential.username, Credential.password)
            .order_by(desc("count"))
            .limit(10)
            .all()
        )
        return jsonify([
            {"username": r[0], "password": r[1], "count": r[2]} for r in results
        ])
    finally:
        session.close()


@app.route("/api/protocol-stats")
def api_protocol_stats():
    """Return connection counts per protocol/honeypot."""
    session = get_session()
    try:
        results = (
            session.query(
                Connection.honeypot_name,
                func.count(Connection.id).label("count")
            )
            .group_by(Connection.honeypot_name)
            .order_by(desc("count"))
            .all()
        )
        return jsonify([{"honeypot": r[0], "count": r[1]} for r in results])
    finally:
        session.close()


@app.route("/api/timeline")
def api_timeline():
    """Return connection counts grouped by hour for the last 24 hours."""
    session = get_session()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        results = (
            session.query(Connection.timestamp)
            .filter(Connection.timestamp >= cutoff)
            .order_by(Connection.timestamp)
            .all()
        )

        # Group by hour
        hours = {}
        for r in results:
            ts = r[0]
            if ts:
                key = ts.strftime("%H:00")
                hours[key] = hours.get(key, 0) + 1

        # Fill in missing hours
        timeline = []
        now = datetime.now(timezone.utc)
        for i in range(24):
            h = (now - timedelta(hours=23 - i)).strftime("%H:00")
            timeline.append({"hour": h, "count": hours.get(h, 0)})

        return jsonify(timeline)
    finally:
        session.close()


@app.route("/api/connections")
def api_connections():
    """Return recent connections with pagination."""
    session = get_session()
    try:
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 50))
        offset = (page - 1) * per_page

        total = session.query(func.count(Connection.id)).scalar() or 0
        results = (
            session.query(Connection)
            .order_by(desc(Connection.timestamp))
            .offset(offset)
            .limit(per_page)
            .all()
        )
        return jsonify({
            "total": total,
            "page": page,
            "data": [{
                "id": c.id,
                "timestamp": c.timestamp.isoformat() if c.timestamp else "",
                "honeypot": c.honeypot_name,
                "protocol": c.protocol,
                "src_ip": c.src_ip,
                "src_port": c.src_port,
                "dst_port": c.dst_port,
            } for c in results]
        })
    finally:
        session.close()


@app.route("/api/credentials")
def api_credentials():
    """Return captured credentials."""
    session = get_session()
    try:
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 50))
        offset = (page - 1) * per_page

        total = session.query(func.count(Credential.id)).scalar() or 0
        results = (
            session.query(Credential)
            .order_by(desc(Credential.timestamp))
            .offset(offset)
            .limit(per_page)
            .all()
        )
        return jsonify({
            "total": total,
            "page": page,
            "data": [{
                "id": c.id,
                "timestamp": c.timestamp.isoformat() if c.timestamp else "",
                "honeypot": c.honeypot_name,
                "src_ip": c.src_ip,
                "username": c.username,
                "password": c.password,
            } for c in results]
        })
    finally:
        session.close()


@app.route("/api/commands")
def api_commands():
    """Return captured commands."""
    session = get_session()
    try:
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 50))
        offset = (page - 1) * per_page

        total = session.query(func.count(Command.id)).scalar() or 0
        results = (
            session.query(Command)
            .order_by(desc(Command.timestamp))
            .offset(offset)
            .limit(per_page)
            .all()
        )
        return jsonify({
            "total": total,
            "page": page,
            "data": [{
                "id": c.id,
                "timestamp": c.timestamp.isoformat() if c.timestamp else "",
                "honeypot": c.honeypot_name,
                "src_ip": c.src_ip,
                "command": c.command,
                "response": c.response,
            } for c in results]
        })
    finally:
        session.close()


@app.route("/api/sessions")
def api_sessions():
    """Return tracked sessions."""
    session = get_session()
    try:
        results = (
            session.query(Session)
            .order_by(desc(Session.start_time))
            .limit(50)
            .all()
        )
        return jsonify([{
            "session_id": s.session_id,
            "honeypot": s.honeypot_name,
            "src_ip": s.src_ip,
            "start_time": s.start_time.isoformat() if s.start_time else "",
            "end_time": s.end_time.isoformat() if s.end_time else "Active",
            "duration": round(s.duration_seconds, 1) if s.duration_seconds else "—",
            "commands_count": s.commands_count or 0,
        } for s in results])
    finally:
        session.close()


@app.route("/api/honeypots")
def api_honeypots():
    """Return honeypot configuration info."""
    honeypots = [
        {"name": "low_ssh",  "port": config.LOW_SSH_PORT,  "type": "Low-Interaction",    "protocol": "SSH"},
        {"name": "low_ftp",  "port": config.LOW_FTP_PORT,  "type": "Low-Interaction",    "protocol": "FTP"},
        {"name": "low_http", "port": config.LOW_HTTP_PORT, "type": "Low-Interaction",    "protocol": "HTTP"},
        {"name": "low_telnet","port": config.LOW_TELNET_PORT,"type":"Low-Interaction",    "protocol": "Telnet"},
        {"name": "low_smb",  "port": config.LOW_SMB_PORT,  "type": "Low-Interaction",    "protocol": "SMB"},
        {"name": "med_ssh",  "port": config.MED_SSH_PORT,  "type": "Medium-Interaction", "protocol": "SSH"},
        {"name": "med_ftp",  "port": config.MED_FTP_PORT,  "type": "Medium-Interaction", "protocol": "FTP"},
        {"name": "med_http", "port": config.MED_HTTP_PORT, "type": "Medium-Interaction", "protocol": "HTTP"},
    ]
    return jsonify(honeypots)


# ── Run ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("  HONEYPOT SOC DASHBOARD")
    print("  Open http://localhost:5000")
    print("=" * 50 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=True)

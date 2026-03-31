"""
Honeypot SOC Dashboard — FastAPI Backend
Serves REST API endpoints for honeypot data.
Frontend is handled by React (see ../frontend).
"""

import os
import sys
import time
import httpx
import asyncio
from collections import OrderedDict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, desc, distinct
from datetime import datetime, timezone, timedelta
from pathlib import Path
import csv
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

import config
from data_collection.db import init_db, get_session
from data_collection.models import Connection, Credential, Command, Payload, Session

# Determine the path to the React build folder
frontend_build_path = Path(__file__).parent.parent / 'frontend' / 'build'

app = FastAPI(title="Honeypot SOC Dashboard API", version="2.0.0")

# ── CORS Middleware ──────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Initialise DB ────────────────────────────────────────────────────
init_db(config.DATABASE_PATH)

# ── Startup timestamp ────────────────────────────────────────────────
_start_time = time.time()


# ═════════════════════════════════════════════════════════════════════
# GeoIP Cache  (TTL = 10 minutes, max 500 entries)
# ═════════════════════════════════════════════════════════════════════
class GeoIPCache:
    """Simple in-memory TTL cache for GeoIP lookups."""
    def __init__(self, ttl: int = 600, max_size: int = 500):
        self._cache: OrderedDict = OrderedDict()
        self._ttl = ttl
        self._max_size = max_size

    def get(self, ip: str):
        entry = self._cache.get(ip)
        if entry is None:
            return None
        if time.time() - entry["ts"] > self._ttl:
            del self._cache[ip]
            return None
        return entry["data"]

    def put(self, ip: str, data: dict):
        if len(self._cache) >= self._max_size:
            self._cache.popitem(last=False)
        self._cache[ip] = {"data": data, "ts": time.time()}

_geo_cache = GeoIPCache()

PRIVATE_IP_PREFIXES = ("127.", "10.", "192.168.", "0.", "169.254.")

def _is_private(ip: str) -> bool:
    if any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES):
        return True
    # 172.16-31.x.x
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2:
            try:
                second = int(parts[1])
                if 16 <= second <= 31:
                    return True
            except ValueError:
                pass
    return False

# MITRE ATT&CK mapping based on protocol
PROTOCOL_MITRE = {
    "ssh": {"technique": "T1110.001", "name": "Brute Force: Password Guessing"},
    "ftp": {"technique": "T1078", "name": "Valid Accounts"},
    "http": {"technique": "T1190", "name": "Exploit Public-Facing App"},
    "telnet": {"technique": "T1021.006", "name": "Remote Services"},
    "smb": {"technique": "T1210", "name": "Exploitation of Remote Services"},
}

PROTOCOL_CLASSIFICATION = {
    "ssh": "SSH Brute Force",
    "ftp": "FTP Credential Harvesting",
    "http": "Web Exploit / Scanner",
    "telnet": "IoT Credential Spray",
    "smb": "Lateral Movement Probe",
}


# ═════════════════════════════════════════════════════════════════════
# API Endpoints
# ═════════════════════════════════════════════════════════════════════

@app.get("/api/stats")
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

        # Last event timestamp
        last_connection = session.query(func.max(Connection.timestamp)).scalar()

        return {
            "total_connections": total_connections,
            "total_credentials": total_credentials,
            "total_commands": total_commands,
            "total_payloads": total_payloads,
            "total_sessions": total_sessions,
            "unique_ips": unique_ips,
            "last_event": last_connection.isoformat() if last_connection else None,
        }
    finally:
        session.close()


@app.get("/api/top-ips")
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
        return [{"ip": r[0], "count": r[1]} for r in results]
    finally:
        session.close()


@app.get("/api/top-credentials")
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
        return [
            {"username": r[0], "password": r[1], "count": r[2]} for r in results
        ]
    finally:
        session.close()


@app.get("/api/protocol-stats")
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
        return [{"honeypot": r[0], "count": r[1]} for r in results]
    finally:
        session.close()


@app.get("/api/timeline")
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

        return timeline
    finally:
        session.close()


@app.get("/api/connections")
def api_connections(page: int = Query(1, ge=1), per_page: int = Query(50, ge=1, le=100)):
    """Return recent connections with pagination."""
    session = get_session()
    try:
        offset = (page - 1) * per_page

        total = session.query(func.count(Connection.id)).scalar() or 0
        results = (
            session.query(Connection)
            .order_by(desc(Connection.timestamp))
            .offset(offset)
            .limit(per_page)
            .all()
        )
        return {
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
        }
    finally:
        session.close()


@app.get("/api/credentials")
def api_credentials(page: int = Query(1, ge=1), per_page: int = Query(50, ge=1, le=100)):
    """Return captured credentials."""
    session = get_session()
    try:
        offset = (page - 1) * per_page

        total = session.query(func.count(Credential.id)).scalar() or 0
        results = (
            session.query(Credential)
            .order_by(desc(Credential.timestamp))
            .offset(offset)
            .limit(per_page)
            .all()
        )
        return {
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
        }
    finally:
        session.close()


@app.get("/api/commands")
def api_commands(page: int = Query(1, ge=1), per_page: int = Query(50, ge=1, le=100)):
    """Return captured commands."""
    session = get_session()
    try:
        offset = (page - 1) * per_page

        total = session.query(func.count(Command.id)).scalar() or 0
        results = (
            session.query(Command)
            .order_by(desc(Command.timestamp))
            .offset(offset)
            .limit(per_page)
            .all()
        )
        return {
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
        }
    finally:
        session.close()


@app.get("/api/sessions")
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
        return [{
            "session_id": s.session_id,
            "honeypot": s.honeypot_name,
            "src_ip": s.src_ip,
            "start_time": s.start_time.isoformat() if s.start_time else "",
            "end_time": s.end_time.isoformat() if s.end_time else "Active",
            "duration": round(s.duration_seconds, 1) if s.duration_seconds else "—",
            "commands_count": s.commands_count or 0,
        } for s in results]
    finally:
        session.close()


@app.get("/api/honeypots")
def api_honeypots():
    """Return honeypot configuration info."""
    return [
        {"name": "low_ssh",  "port": config.LOW_SSH_PORT,  "type": "Low-Interaction",    "protocol": "SSH"},
        {"name": "low_ftp",  "port": config.LOW_FTP_PORT,  "type": "Low-Interaction",    "protocol": "FTP"},
        {"name": "low_http", "port": config.LOW_HTTP_PORT, "type": "Low-Interaction",    "protocol": "HTTP"},
        {"name": "low_telnet","port": config.LOW_TELNET_PORT,"type":"Low-Interaction",    "protocol": "Telnet"},
        {"name": "low_smb",  "port": config.LOW_SMB_PORT,  "type": "Low-Interaction",    "protocol": "SMB"},
        {"name": "med_ssh",  "port": config.MED_SSH_PORT,  "type": "Medium-Interaction", "protocol": "SSH"},
        {"name": "med_ftp",  "port": config.MED_FTP_PORT,  "type": "Medium-Interaction", "protocol": "FTP"},
        {"name": "med_http", "port": config.MED_HTTP_PORT, "type": "Medium-Interaction", "protocol": "HTTP"},
    ]


# ═════════════════════════════════════════════════════════════════════
# Threat Intelligence (REAL data from DB + GeoIP)
# ═════════════════════════════════════════════════════════════════════

@app.get("/api/threat-intelligence")
async def api_threat_intelligence():
    """
    Real threat intelligence: top attacker IPs enriched with GeoIP data.
    No hardcoded country/IP data — everything from the live honeypot DB.
    """
    session = get_session()
    try:
        # Get top 20 attacker IPs with attack counts
        ip_results = (
            session.query(
                Connection.src_ip,
                func.count(Connection.id).label("total_attacks"),
            )
            .group_by(Connection.src_ip)
            .order_by(desc("total_attacks"))
            .limit(20)
            .all()
        )

        if not ip_results:
            return {"threats": [], "summary": {"total_actors": 0, "countries": []}}

        # For each IP, get the protocols they used
        ip_protocols = {}
        for ip_row in ip_results:
            ip = ip_row[0]
            protos = (
                session.query(Connection.protocol, func.count(Connection.id))
                .filter(Connection.src_ip == ip)
                .group_by(Connection.protocol)
                .all()
            )
            ip_protocols[ip] = {p[0]: p[1] for p in protos}

        # Get last seen timestamps
        ip_last_seen = {}
        for ip_row in ip_results:
            ip = ip_row[0]
            last = session.query(func.max(Connection.timestamp)).filter(Connection.src_ip == ip).scalar()
            ip_last_seen[ip] = last.isoformat() if last else None

        # Check if any credential attempts exist for these IPs
        ip_cred_counts = {}
        for ip_row in ip_results:
            ip = ip_row[0]
            cred_count = session.query(func.count(Credential.id)).filter(Credential.src_ip == ip).scalar() or 0
            ip_cred_counts[ip] = cred_count

    finally:
        session.close()

    # Enrich with GeoIP data (async HTTP calls)
    threats = []
    country_counts = {}

    async with httpx.AsyncClient(timeout=5.0) as client:
        for ip_row in ip_results:
            ip = ip_row[0]
            attack_count = ip_row[1]
            protocols = ip_protocols.get(ip, {})
            primary_protocol = max(protocols, key=protocols.get) if protocols else "unknown"

            # Skip private IPs
            if _is_private(ip):
                geo_data = {
                    "country": "Local Network",
                    "countryCode": "LO",
                    "city": "—",
                    "isp": "Internal",
                    "org": "Private Network",
                    "lat": 0,
                    "lon": 0,
                }
            else:
                # Check cache first
                cached = _geo_cache.get(ip)
                if cached:
                    geo_data = cached
                else:
                    try:
                        resp = await client.get(f"http://ip-api.com/json/{ip}")
                        raw = resp.json()
                        if raw.get("status") == "success":
                            geo_data = {
                                "country": raw.get("country", "Unknown"),
                                "countryCode": raw.get("countryCode", "XX"),
                                "city": raw.get("city", "—"),
                                "isp": raw.get("isp", "Unknown"),
                                "org": raw.get("org", "—"),
                                "lat": raw.get("lat", 0),
                                "lon": raw.get("lon", 0),
                            }
                        else:
                            geo_data = {
                                "country": "Unknown",
                                "countryCode": "XX",
                                "city": "—",
                                "isp": "Unknown",
                                "org": "—",
                                "lat": 0,
                                "lon": 0,
                            }
                        _geo_cache.put(ip, geo_data)
                    except Exception:
                        geo_data = {
                            "country": "Lookup Failed",
                            "countryCode": "XX",
                            "city": "—",
                            "isp": "Unknown",
                            "org": "—",
                            "lat": 0,
                            "lon": 0,
                        }

            # Calculate confidence score (0-100) based on attack volume + variety
            max_attacks = ip_results[0][1] if ip_results else 1
            volume_score = min((attack_count / max(max_attacks, 1)) * 80, 80)
            variety_bonus = min(len(protocols) * 5, 15)
            cred_bonus = 5 if ip_cred_counts.get(ip, 0) > 0 else 0
            confidence = min(round(volume_score + variety_bonus + cred_bonus), 100)

            # MITRE mapping from primary protocol
            mitre_info = PROTOCOL_MITRE.get(primary_protocol, {"technique": "T1595", "name": "Active Scanning"})
            classification = PROTOCOL_CLASSIFICATION.get(primary_protocol, "Reconnaissance")

            # Track countries
            country = geo_data["country"]
            country_counts[country] = country_counts.get(country, 0) + attack_count

            threats.append({
                "ip": ip,
                "total_attacks": attack_count,
                "confidence": confidence,
                "country": geo_data["country"],
                "countryCode": geo_data["countryCode"],
                "city": geo_data["city"],
                "isp": geo_data["isp"],
                "org": geo_data["org"],
                "lat": geo_data["lat"],
                "lon": geo_data["lon"],
                "primary_protocol": primary_protocol,
                "protocols": protocols,
                "classification": classification,
                "mitre_technique": mitre_info["technique"],
                "mitre_name": mitre_info["name"],
                "credential_attempts": ip_cred_counts.get(ip, 0),
                "last_seen": ip_last_seen.get(ip),
            })

    # Sort countries by total attacks
    sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)

    return {
        "threats": threats,
        "summary": {
            "total_actors": len(threats),
            "countries": [{"country": c, "attacks": a} for c, a in sorted_countries[:10]],
        }
    }


# ═════════════════════════════════════════════════════════════════════
# System Status
# ═════════════════════════════════════════════════════════════════════

@app.get("/api/system-status")
def api_system_status():
    """Return real system health information."""
    session = get_session()
    try:
        total_connections = session.query(func.count(Connection.id)).scalar() or 0
        last_event = session.query(func.max(Connection.timestamp)).scalar()

        # Database file size
        db_size = 0
        if os.path.exists(config.DATABASE_PATH):
            db_size = os.path.getsize(config.DATABASE_PATH)

        uptime_seconds = time.time() - _start_time
        hours = int(uptime_seconds // 3600)
        minutes = int((uptime_seconds % 3600) // 60)

        # Get active honeypot count from config
        honeypot_configs = [
            {"name": "SSH (Low)", "port": config.LOW_SSH_PORT},
            {"name": "FTP (Low)", "port": config.LOW_FTP_PORT},
            {"name": "HTTP (Low)", "port": config.LOW_HTTP_PORT},
            {"name": "Telnet (Low)", "port": config.LOW_TELNET_PORT},
            {"name": "SMB (Low)", "port": config.LOW_SMB_PORT},
            {"name": "SSH (Med)", "port": config.MED_SSH_PORT},
            {"name": "FTP (Med)", "port": config.MED_FTP_PORT},
            {"name": "HTTP (Med)", "port": config.MED_HTTP_PORT},
        ]

        return {
            "status": "online",
            "uptime": f"{hours}h {minutes}m",
            "uptime_seconds": round(uptime_seconds),
            "database_size_bytes": db_size,
            "database_size": f"{db_size / 1024 / 1024:.1f} MB" if db_size > 0 else "0 KB",
            "total_events": total_connections,
            "last_event": last_event.isoformat() if last_event else None,
            "honeypot_count": len(honeypot_configs),
            "honeypots": honeypot_configs,
            "version": "2.0.0",
        }
    finally:
        session.close()


# ═════════════════════════════════════════════════════════════════════
# Attack Summary (aggregated intelligence)
# ═════════════════════════════════════════════════════════════════════

@app.get("/api/attack-summary")
def api_attack_summary():
    """Aggregated attack intelligence for the dashboard."""
    session = get_session()
    try:
        # Attacks in last hour vs previous hour
        now = datetime.now(timezone.utc)
        one_hour_ago = now - timedelta(hours=1)
        two_hours_ago = now - timedelta(hours=2)

        current_hour = session.query(func.count(Connection.id)).filter(
            Connection.timestamp >= one_hour_ago
        ).scalar() or 0

        previous_hour = session.query(func.count(Connection.id)).filter(
            Connection.timestamp >= two_hours_ago,
            Connection.timestamp < one_hour_ago,
        ).scalar() or 0

        # Protocol breakdown
        protocol_breakdown = (
            session.query(Connection.protocol, func.count(Connection.id))
            .group_by(Connection.protocol)
            .order_by(desc(func.count(Connection.id)))
            .all()
        )

        # Recent 5 unique IPs
        recent_ips = (
            session.query(Connection.src_ip, func.max(Connection.timestamp))
            .group_by(Connection.src_ip)
            .order_by(desc(func.max(Connection.timestamp)))
            .limit(5)
            .all()
        )

        # Trend direction
        if current_hour > previous_hour:
            trend = "increasing"
        elif current_hour < previous_hour:
            trend = "decreasing"
        else:
            trend = "stable"

        return {
            "current_hour_attacks": current_hour,
            "previous_hour_attacks": previous_hour,
            "trend": trend,
            "trend_percent": round(((current_hour - previous_hour) / max(previous_hour, 1)) * 100, 1),
            "protocols": [{"protocol": p[0] or "unknown", "count": p[1]} for p in protocol_breakdown],
            "recent_attackers": [{"ip": r[0], "last_seen": r[1].isoformat() if r[1] else None} for r in recent_ips],
        }
    finally:
        session.close()


# ═════════════════════════════════════════════════════════════════════
# Export & Reporting Endpoints
# ═════════════════════════════════════════════════════════════════════

@app.get("/api/export/csv")
def export_csv():
    """Export all connections as a raw CSV forensic dump."""
    session = get_session()
    try:
        results = session.query(Connection).order_by(desc(Connection.timestamp)).all()

        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(["ID", "Timestamp", "Honeypot", "Protocol", "Source IP", "Source Port", "Dest Port"])

        for c in results:
            writer.writerow([
                c.id,
                c.timestamp.isoformat() if c.timestamp else "",
                c.honeypot_name,
                c.protocol,
                c.src_ip,
                c.src_port,
                c.dst_port
            ])

        content = output.getvalue()
        output.close()

        return Response(
            content=content,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=forensic_dump.csv"}
        )
    finally:
        session.close()

@app.get("/api/export/pdf")
def export_pdf():
    """Generate a high-level PDF Executive Summary."""
    session = get_session()
    try:
        total_connections = session.query(func.count(Connection.id)).scalar() or 0
        total_credentials = session.query(func.count(Credential.id)).scalar() or 0
        unique_ips = session.query(func.count(func.distinct(Connection.src_ip))).scalar() or 0

        top_ips = session.query(Connection.src_ip, func.count(Connection.id).label("c")).group_by(Connection.src_ip).order_by(desc("c")).limit(5).all()

        output = io.BytesIO()
        p = canvas.Canvas(output, pagesize=letter)

        p.setFont("Helvetica-Bold", 20)
        p.drawString(50, 750, "Honeypot SOC - Executive Summary")

        p.setFont("Helvetica", 12)
        p.drawString(50, 720, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        p.setFont("Helvetica-Bold", 14)
        p.drawString(50, 680, "Global Threat Metrics:")
        p.setFont("Helvetica", 12)
        p.drawString(70, 660, f"Total Attack Connections: {total_connections}")
        p.drawString(70, 640, f"Unique Attacker IPs: {unique_ips}")
        p.drawString(70, 620, f"Stolen Credentials Captured: {total_credentials}")

        p.setFont("Helvetica-Bold", 14)
        p.drawString(50, 580, "Top Threat Actors (IPs):")
        p.setFont("Helvetica", 12)
        y = 560
        for ip, count in top_ips:
            p.drawString(70, y, f"IP: {ip} - {count} connection attempts")
            y -= 20

        p.drawString(50, y - 40, "End of Automated Report.")
        p.showPage()
        p.save()

        pdf_bytes = output.getvalue()
        output.close()

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=executive_summary.pdf"}
        )
    finally:
        session.close()

@app.get("/api/export/geo")
def export_geo():
    """Export a simple CSV report grouping top attacking IPs."""
    session = get_session()
    try:
        results = session.query(Connection.src_ip, func.count(Connection.id).label("c")).group_by(Connection.src_ip).order_by(desc("c")).all()

        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(["Source IP", "Total Attacks", "Assumed Threat Level"])

        for ip, count in results:
            threat = "High" if count > 100 else "Medium" if count > 20 else "Low"
            writer.writerow([ip, count, threat])

        content = output.getvalue()
        output.close()

        return Response(
            content=content,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=geo_trends_report.csv"}
        )
    finally:
        session.close()


# ═════════════════════════════════════════════════════════════════════
# Health Check
# ═════════════════════════════════════════════════════════════════════

@app.get("/api/health")
def health_check():
    """Health check endpoint."""
    return {
        "status": "online",
        "service": "honeypot-dashboard",
        "uptime_seconds": round(time.time() - _start_time),
        "version": "2.0.0",
    }


# ═════════════════════════════════════════════════════════════════════
# Static Files (React Frontend)
# ═════════════════════════════════════════════════════════════════════

@app.get("/")
async def serve_root():
    """Serve React index.html"""
    index_path = frontend_build_path / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return JSONResponse(
        {"error": "Frontend not built. Run 'npm run build' in the frontend directory."},
        status_code=404
    )


@app.get("/{full_path:path}")
async def serve_static(full_path: str):
    """Serve static files and fallback to index.html for React Router."""
    if full_path.startswith("api/"):
        return JSONResponse({"error": "Not found"}, status_code=404)

    file_path = frontend_build_path / full_path
    if file_path.exists() and file_path.is_file():
        return FileResponse(file_path)

    # Fallback to index.html for React Router
    index_path = frontend_build_path / "index.html"
    if index_path.exists():
        return FileResponse(index_path)

    return JSONResponse({"error": "Not found"}, status_code=404)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("dashboard:app", host="0.0.0.0", port=8000, reload=True)

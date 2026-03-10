"""
Structured logger for the honeypot layer.
Writes events to:
  1. SQLite database (via SQLAlchemy)
  2. Rotating JSON log files
"""

import json
import os
import logging
import uuid
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from data_collection.db import get_session
from data_collection.models import Connection, Credential, Command, Payload, Session


class HoneypotLogger:
    """Unified logging interface used by all honeypots."""

    def __init__(self, log_dir: str, max_bytes: int = 10_485_760, backup_count: int = 5):
        os.makedirs(log_dir, exist_ok=True)

        # JSON file logger
        self._file_logger = logging.getLogger("honeypot.json")
        self._file_logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(
            os.path.join(log_dir, "honeypot_events.json"),
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._file_logger.addHandler(handler)

    # ── helpers ───────────────────────────────────────────────────────

    def _now(self):
        return datetime.now(timezone.utc)

    def _write_json(self, event: dict):
        """Append a JSON line to the log file."""
        self._file_logger.info(json.dumps(event, default=str))

    # ── public API ────────────────────────────────────────────────────

    def log_connection(self, honeypot_name: str, src_ip: str, src_port: int,
                       dst_port: int, protocol: str):
        """Record a new TCP connection."""
        ts = self._now()
        # DB
        session = get_session()
        try:
            session.add(Connection(
                timestamp=ts, honeypot_name=honeypot_name,
                protocol=protocol, src_ip=src_ip,
                src_port=src_port, dst_port=dst_port,
            ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        # File
        self._write_json({
            "event": "connection",
            "timestamp": ts.isoformat(),
            "honeypot": honeypot_name,
            "protocol": protocol,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_port": dst_port,
        })

    def log_credential(self, honeypot_name: str, src_ip: str,
                       username: str, password: str):
        """Record a captured credential pair."""
        ts = self._now()
        session = get_session()
        try:
            session.add(Credential(
                timestamp=ts, honeypot_name=honeypot_name,
                src_ip=src_ip, username=username, password=password,
            ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        self._write_json({
            "event": "credential",
            "timestamp": ts.isoformat(),
            "honeypot": honeypot_name,
            "src_ip": src_ip,
            "username": username,
            "password": password,
        })

    def log_command(self, honeypot_name: str, src_ip: str,
                    command: str, response: str = None):
        """Record a command entered in a medium-interaction shell."""
        ts = self._now()
        session = get_session()
        try:
            session.add(Command(
                timestamp=ts, honeypot_name=honeypot_name,
                src_ip=src_ip, command=command, response=response,
            ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        self._write_json({
            "event": "command",
            "timestamp": ts.isoformat(),
            "honeypot": honeypot_name,
            "src_ip": src_ip,
            "command": command,
            "response": response,
        })

    def log_payload(self, honeypot_name: str, src_ip: str, data: str):
        """Record a raw payload / data blob."""
        ts = self._now()
        session = get_session()
        try:
            session.add(Payload(
                timestamp=ts, honeypot_name=honeypot_name,
                src_ip=src_ip, data=data, data_length=len(data),
            ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        self._write_json({
            "event": "payload",
            "timestamp": ts.isoformat(),
            "honeypot": honeypot_name,
            "src_ip": src_ip,
            "data_length": len(data),
        })

    def start_session(self, honeypot_name: str, src_ip: str) -> str:
        """Create a tracked session; returns the session_id."""
        sid = uuid.uuid4().hex[:16]
        ts = self._now()
        session = get_session()
        try:
            session.add(Session(
                session_id=sid, honeypot_name=honeypot_name,
                src_ip=src_ip, start_time=ts,
            ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        self._write_json({
            "event": "session_start",
            "timestamp": ts.isoformat(),
            "honeypot": honeypot_name,
            "src_ip": src_ip,
            "session_id": sid,
        })
        return sid

    def end_session(self, session_id: str, commands_count: int = 0):
        """Mark a session as ended and compute its duration."""
        ts = self._now()
        db_session = get_session()
        try:
            sess = db_session.query(Session).filter_by(session_id=session_id).first()
            if sess:
                sess.end_time = ts
                if sess.start_time:
                    sess.duration_seconds = (ts - sess.start_time).total_seconds()
                sess.commands_count = commands_count
                db_session.commit()

                self._write_json({
                    "event": "session_end",
                    "timestamp": ts.isoformat(),
                    "session_id": session_id,
                    "duration_seconds": sess.duration_seconds,
                    "commands_count": commands_count,
                })
        except Exception:
            db_session.rollback()
            raise
        finally:
            db_session.close()

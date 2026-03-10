"""
SQLAlchemy ORM models for honeypot data collection.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, Float
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Connection(Base):
    """Every TCP connection to any honeypot."""
    __tablename__ = "connections"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    honeypot_name = Column(String(64), nullable=False)
    protocol = Column(String(16), nullable=False)    # ssh, ftp, http, telnet, smb
    src_ip = Column(String(45), nullable=False)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False)


class Credential(Base):
    """Captured login attempts."""
    __tablename__ = "credentials"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    honeypot_name = Column(String(64), nullable=False)
    src_ip = Column(String(45), nullable=False)
    username = Column(String(256))
    password = Column(String(256))


class Command(Base):
    """Commands entered by attackers (medium-interaction)."""
    __tablename__ = "commands"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    honeypot_name = Column(String(64), nullable=False)
    src_ip = Column(String(45), nullable=False)
    command = Column(Text, nullable=False)
    response = Column(Text)


class Payload(Base):
    """Raw payloads / data received from attackers."""
    __tablename__ = "payloads"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    honeypot_name = Column(String(64), nullable=False)
    src_ip = Column(String(45), nullable=False)
    data = Column(Text, nullable=False)             # hex or base64 encoded
    data_length = Column(Integer)


class Session(Base):
    """High-level session tracking for medium-interaction honeypots."""
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), unique=True, nullable=False)
    honeypot_name = Column(String(64), nullable=False)
    src_ip = Column(String(45), nullable=False)
    start_time = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    end_time = Column(DateTime)
    duration_seconds = Column(Float)
    commands_count = Column(Integer, default=0)

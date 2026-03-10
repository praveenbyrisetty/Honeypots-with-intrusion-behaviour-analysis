"""
Central configuration for the Adaptive Honeypot Layer.
All ports use high numbers so no admin/root privileges are needed.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Host ──────────────────────────────────────────────────────────────
BIND_HOST = "0.0.0.0"

# ── Low-Interaction Honeypot Ports ────────────────────────────────────
LOW_SSH_PORT = 2222
LOW_FTP_PORT = 2121
LOW_HTTP_PORT = 8080
LOW_TELNET_PORT = 2323
LOW_SMB_PORT = 4450

# ── Medium-Interaction Honeypot Ports ─────────────────────────────────
MED_SSH_PORT = 2223
MED_FTP_PORT = 2122
MED_HTTP_PORT = 8081

# ── Data Collection ───────────────────────────────────────────────────
DATABASE_PATH = os.path.join(BASE_DIR, "data", "honeypot.db")
LOG_DIR = os.path.join(BASE_DIR, "data", "logs")
LOG_MAX_BYTES = 10 * 1024 * 1024   # 10 MB per log file
LOG_BACKUP_COUNT = 5

# ── SSH Honeypot ──────────────────────────────────────────────────────
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
SSH_HOST_KEY_FILE = os.path.join(BASE_DIR, "data", "ssh_host_rsa_key")

# ── FTP Honeypot ──────────────────────────────────────────────────────
FTP_BANNER = "220 ProFTPD 1.3.5e Server (Debian)"

# ── HTTP Honeypot ─────────────────────────────────────────────────────
HTTP_SERVER_HEADER = "Apache/2.4.41 (Ubuntu)"

# ── Telnet Honeypot ───────────────────────────────────────────────────
TELNET_BANNER = "\r\nUbuntu 20.04.6 LTS\r\n"

# ── SMB Honeypot ──────────────────────────────────────────────────────
SMB_SERVER_NAME = "FILESERVER01"

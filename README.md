# Honeypots with Intrusion Behaviour Analysis with ML

This project implements an **Adaptive Honeypot System** designed to detect, log, and analyze intrusion attempts using AI and Machine Learning. By simulating vulnerable services at multiple interaction levels, we capture malicious activity and study attacker behavior in a controlled environment.

## Architecture

```
Adaptive Honeypot System
├── Adaptive Honeypot Layer        ✅ Implemented
│   ├── Low-Interaction Honeypots
│   └── Medium-Interaction Honeypots
├── Traffic Capture & Telemetry     🔜 Planned
├── Feature Engineering Pipeline    🔜 Planned
├── ML Detection Engine             🔜 Planned
├── Behavioral Intelligence Engine  🔜 Planned
├── Adaptive Deception Engine       🔜 Planned
├── RAG Intelligence Layer          🔜 Planned
└── SOC Dashboard & Automation      🔜 Planned
```

## Implemented: Adaptive Honeypot Layer

### Low-Interaction Honeypots

Capture connections and credentials with minimal response — lightweight and fast.

| Service | Port | Description                                                  |
| ------- | ---- | ------------------------------------------------------------ |
| SSH     | 2222 | Fake SSH banner via Paramiko, captures usernames & passwords |
| FTP     | 2121 | Minimal FTP dialogue (USER → PASS → reject)                  |
| HTTP    | 8080 | Fake admin login page, logs GET/POST requests                |
| Telnet  | 2323 | Login prompt with 3 attempts, captures credentials           |
| SMB     | 4450 | SMB2 negotiate response, logs raw payloads                   |

### Medium-Interaction Honeypots

Deeper engagement with fake environments to study attacker behavior.

| Service | Port | Description                                                                                                                                                  |
| ------- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| SSH     | 2223 | Accepts auth → fake bash shell with 15+ commands (`ls`, `cat`, `whoami`, `cd`, `ps`, `ifconfig`, etc.), fake filesystem with `/etc/passwd`, `/root/flag.txt` |
| FTP     | 2122 | Virtual filesystem with fake config files (`secrets.env`, `database.yml`), supports `LIST`, `RETR`, `STOR`, `CWD`                                            |
| HTTP    | 8081 | Fake vulnerable web app — admin dashboard, directory explorer, SQL injection form, command execution form, phpinfo, server-status                            |

### Data Collection

Every event is logged to **two destinations**:

- **SQLite Database** (`data/honeypot.db`) via SQLAlchemy
- **Rotating JSON Log Files** (`data/logs/`)

**Database Tables:**
| Table | Content |
|-------|---------|
| `connections` | Every TCP connection (IP, port, protocol, timestamp) |
| `credentials` | Captured usernames & passwords |
| `commands` | Shell commands from medium-interaction sessions |
| `payloads` | Raw data/payloads received |
| `sessions` | Session tracking with duration & command counts |

## Project Structure

```
backend/
├── run.py                          # Entry point — starts all honeypots
├── config.py                       # Ports, banners, paths
├── requirements.txt                # Python dependencies
├── honeypots/
│   ├── base.py                     # Abstract base class (threaded socket server)
│   ├── low_interaction/
│   │   ├── ssh_honeypot.py
│   │   ├── ftp_honeypot.py
│   │   ├── http_honeypot.py
│   │   ├── telnet_honeypot.py
│   │   └── smb_honeypot.py
│   └── medium_interaction/
│       ├── ssh_honeypot.py
│       ├── ftp_honeypot.py
│       └── http_honeypot.py
└── data_collection/
    ├── db.py                       # SQLite setup
    ├── models.py                   # ORM models (5 tables)
    └── logger.py                   # Dual logging (DB + JSON files)
```

## Getting Started

## workflow
┌──────────────────────────────────────────────────────────────────┐
│                        WORKFLOW                                  │
└──────────────────────────────────────────────────────────────────┘

  1. START (python run.py)
       │
       ▼
  2. INITIALIZE
       ├── Create SQLite database + tables
       ├── Set up JSON log file rotation
       └── Generate SSH host key (if not exists)
       │
       ▼
  3. LAUNCH 8 HONEYPOTS (each in its own thread)
       │
       ├── Low-Interaction (port)          Medium-Interaction (port)
       │   ├── SSH  (2222)                 ├── SSH  (2223)
       │   ├── FTP  (2121)                 ├── FTP  (2122)
       │   ├── HTTP (8080)                 └── HTTP (8081)
       │   ├── Telnet (2323)
       │   └── SMB  (4450)
       │
       ▼
  4. ATTACKER CONNECTS to any port
       │
       ▼
  5. CONNECTION LOGGED → DB + JSON file
       │  (IP, port, protocol, timestamp)
       │
       ▼
  6. HONEYPOT RESPONDS based on interaction level:
       │
       ├── LOW-INTERACTION:
       │     ├── Show banner (SSH/FTP/Telnet)
       │     ├── Capture credentials
       │     ├── Reject login
       │     └── Close connection
       │
       └── MEDIUM-INTERACTION:
             ├── Accept login
             ├── Start a SESSION (tracked with duration)
             ├── Provide fake environment:
             │     ├── SSH → fake bash shell + filesystem
             │     ├── FTP → virtual filesystem with fake secrets
             │     └── HTTP → fake vulnerable web app
             ├── Log every COMMAND / REQUEST
             ├── Log PAYLOADS (raw data)
             └── End session on disconnect/exit
       │
       ▼
  7. ALL DATA STORED
       ├── honeypot.db  (SQLite — 5 tables)
       └── logs/honeypot_events.json  (rotating JSON)
       │
       ▼
  8. Ctrl+C → GRACEFUL SHUTDOWN
       └── Stop all honeypot threads cleanly


### Prerequisites

- Python 3.10+

### Installation

```bash
cd backend
pip install -r requirements.txt
```

### Run

```bash
python run.py
```

All 8 honeypots will start on high ports (no admin privileges required). Press `Ctrl+C` to stop.

### Test a Honeypot

```bash
# SSH (low-interaction — rejects auth)
ssh user@localhost -p 2222

# SSH (medium-interaction — fake shell)
ssh user@localhost -p 2223

# HTTP (medium-interaction — open in browser)
# http://localhost:8081
```

## Tech Stack

- **Language:** Python 3
- **SSH Protocol:** Paramiko
- **Database:** SQLite + SQLAlchemy ORM
- **Logging:** Python `logging` with `RotatingFileHandler`

## License

This project is for educational and research purposes only.

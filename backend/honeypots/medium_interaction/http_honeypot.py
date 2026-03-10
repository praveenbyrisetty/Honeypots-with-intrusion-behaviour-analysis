"""
Medium-interaction HTTP honeypot.
Simulates a vulnerable web application with:
  - Admin login panel
  - Directory listings
  - Fake phpinfo / server-status pages
  - SQL injection / command injection "vulnerable" forms
Logs all requests, form submissions, and payloads.
"""

import socket
import json
from urllib.parse import unquote_plus

from honeypots.base import BaseHoneypot
import config

# ── Page templates ────────────────────────────────────────────────────

_STYLE = """
<style>
  body{font-family:'Segoe UI',Arial,sans-serif;background:#0f0f1a;color:#e0e0e0;margin:0;padding:0;}
  .header{background:linear-gradient(135deg,#1a1a3e,#2d2d6d);padding:16px 32px;border-bottom:2px solid #e94560;}
  .header h1{margin:0;font-size:22px;color:#e94560;}
  .nav{background:#16213e;padding:10px 32px;display:flex;gap:20px;}
  .nav a{color:#7ec8e3;text-decoration:none;font-size:14px;}
  .nav a:hover{color:#e94560;}
  .container{max-width:960px;margin:32px auto;padding:0 20px;}
  .card{background:#16213e;border-radius:10px;padding:24px;margin:16px 0;border:1px solid #2d2d6d;}
  input,textarea{background:#1a1a2e;border:1px solid #2d2d6d;color:#e0e0e0;padding:10px;border-radius:6px;width:95%;margin:6px 0;}
  button{background:#e94560;color:#fff;border:none;padding:10px 24px;border-radius:6px;cursor:pointer;margin-top:8px;}
  table{width:100%;border-collapse:collapse;}
  th,td{padding:8px 12px;border:1px solid #2d2d6d;text-align:left;}
  th{background:#1a1a3e;}
  a{color:#7ec8e3;}
  .dir-icon{color:#f9a826;margin-right:6px;}
  .file-icon{color:#7ec8e3;margin-right:6px;}
</style>
"""

_LOGIN_PAGE = f"""<!DOCTYPE html><html><head><title>Admin Panel</title>{_STYLE}</head>
<body>
<div class="header"><h1>⚡ Server Admin Panel</h1></div>
<div class="container">
<div class="card" style="max-width:400px;margin:60px auto;">
  <h2 style="text-align:center;color:#e94560;">Administrator Login</h2>
  <form method="POST" action="/login">
    <label>Username</label><input name="username" placeholder="admin">
    <label>Password</label><input name="password" type="password" placeholder="password">
    <button type="submit" style="width:100%;">Sign In</button>
  </form>
</div></div></body></html>"""

_DASHBOARD = f"""<!DOCTYPE html><html><head><title>Dashboard</title>{_STYLE}</head>
<body>
<div class="header"><h1>⚡ Server Admin Panel</h1></div>
<div class="nav">
  <a href="/">Dashboard</a>
  <a href="/files/">Files</a>
  <a href="/search">Search</a>
  <a href="/server-status">Server Status</a>
  <a href="/phpinfo.php">PHP Info</a>
  <a href="/cmd">Terminal</a>
</div>
<div class="container">
<div class="card"><h3>System Overview</h3>
  <p>Server: Ubuntu 20.04.6 LTS</p>
  <p>Uptime: 47 days, 3:22</p>
  <p>Load: 0.12 0.08 0.05</p>
  <p>Users online: 1</p>
</div>
<div class="card"><h3>Recent Alerts</h3>
  <table><tr><th>Time</th><th>Event</th><th>Source</th></tr>
  <tr><td>08:12</td><td>Failed login attempt</td><td>10.0.0.5</td></tr>
  <tr><td>07:45</td><td>Port scan detected</td><td>172.16.0.99</td></tr>
  </table>
</div></div></body></html>"""

_DIR_LISTING = f"""<!DOCTYPE html><html><head><title>Index of {{path}}</title>{_STYLE}</head>
<body>
<div class="header"><h1>Index of {{path}}</h1></div>
<div class="nav"><a href="/">Dashboard</a><a href="/files/">Files</a></div>
<div class="container"><div class="card">
<table><tr><th>Name</th><th>Size</th><th>Modified</th></tr>
{{entries}}
</table></div></div></body></html>"""

_SEARCH_PAGE = f"""<!DOCTYPE html><html><head><title>Search</title>{_STYLE}</head>
<body>
<div class="header"><h1>⚡ Database Search</h1></div>
<div class="nav"><a href="/">Dashboard</a><a href="/search">Search</a></div>
<div class="container"><div class="card">
  <h3>Search Users</h3>
  <form method="POST" action="/search">
    <input name="query" placeholder="Enter search query...">
    <button type="submit">Search</button>
  </form>
  <p style="font-size:12px;color:#666;">Query: SELECT * FROM users WHERE name LIKE '%{{query}}%'</p>
  {{results}}
</div></div></body></html>"""

_CMD_PAGE = f"""<!DOCTYPE html><html><head><title>Terminal</title>{_STYLE}</head>
<body>
<div class="header"><h1>⚡ Web Terminal</h1></div>
<div class="nav"><a href="/">Dashboard</a><a href="/cmd">Terminal</a></div>
<div class="container"><div class="card">
  <h3>Execute Command</h3>
  <form method="POST" action="/cmd">
    <label>Command:</label>
    <input name="cmd" placeholder="ls -la" style="font-family:monospace;">
    <button type="submit">Run</button>
  </form>
  <pre style="background:#0f0f1a;padding:16px;border-radius:6px;margin-top:12px;">{{output}}</pre>
</div></div></body></html>"""

_PHPINFO = f"""<!DOCTYPE html><html><head><title>phpinfo()</title>{_STYLE}</head>
<body>
<div class="container"><div class="card">
<h2 style="color:#e94560;">PHP Version 8.1.2</h2>
<table>
<tr><th>System</th><td>Linux ubuntu-server-01 5.4.0-196-generic</td></tr>
<tr><th>Server API</th><td>Apache 2.0 Handler</td></tr>
<tr><th>Document Root</th><td>/var/www/html</td></tr>
<tr><th>MySQL Support</th><td>enabled (mysqlnd 8.1.2)</td></tr>
<tr><th>Loaded Modules</th><td>mod_rewrite, mod_ssl, mod_php</td></tr>
</table></div></div></body></html>"""

_SERVER_STATUS = f"""<!DOCTYPE html><html><head><title>Server Status</title>{_STYLE}</head>
<body>
<div class="container"><div class="card">
<h2>Apache Server Status</h2>
<p>Server Version: Apache/2.4.41 (Ubuntu)</p>
<p>Current Time: Tuesday, 10-Mar-2026 08:30:00 UTC</p>
<p>Restart Time: Sunday, 22-Jan-2026 05:08:00 UTC</p>
<p>Total accesses: 48712 - Total Traffic: 1.2 GB</p>
<p>CPU Usage: u.24 s.18 cu0 cs0 - .00128 CPU load</p>
<p>5 requests/sec - 33.2 kB/second - 6.7 kB/request</p>
</div></div></body></html>"""

# Fake directory structure
_FAKE_DIRS = {
    "/files/": ["backup/", "config/", "logs/", "www/", "upload/"],
    "/files/backup/": ["db_dump_2024.sql.gz (4.2 MB)", "users.csv (128 KB)"],
    "/files/config/": ["database.yml (512 B)", "secrets.env (256 B)", "nginx.conf (2.1 KB)"],
    "/files/logs/": ["access.log (12 MB)", "error.log (3.4 MB)", "auth.log (890 KB)"],
    "/files/www/": ["index.html (8 KB)", "config.php (1.2 KB)", ".htaccess (128 B)"],
}


class MedHTTPHoneypot(BaseHoneypot):
    """Medium-interaction HTTP honeypot — fake vulnerable web application."""

    def __init__(self, host: str = None, port: int = None, logger=None):
        super().__init__(
            name="med_http",
            host=host or config.BIND_HOST,
            port=port or config.MED_HTTP_PORT,
            logger=logger,
        )

    def handle_connection(self, client_socket: socket.socket, client_address: tuple):
        client_socket.settimeout(30)

        try:
            raw = client_socket.recv(8192)
            if not raw:
                return

            request = raw.decode("utf-8", errors="replace")
            lines = request.split("\r\n")
            request_line = lines[0] if lines else ""

            parts = request_line.split(" ")
            method = parts[0] if len(parts) >= 1 else "GET"
            path = parts[1] if len(parts) >= 2 else "/"

            # Parse headers and body
            headers = {}
            body = ""
            in_body = False
            for line in lines[1:]:
                if in_body:
                    body += line
                elif line == "":
                    in_body = True
                elif ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()

            # Log the full request
            if self.hp_logger:
                self.hp_logger.log_payload(
                    honeypot_name="med_http",
                    src_ip=client_address[0],
                    data=request[:4096],
                )
                self.hp_logger.log_command(
                    honeypot_name="med_http",
                    src_ip=client_address[0],
                    command=f"{method} {path}",
                    response=None,
                )

            # Route
            html = self._route(method, path, body, client_address)
            response = self._http_response("200 OK", html)
            client_socket.sendall(response.encode())

        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            self._log.debug(f"Med HTTP error: {e}")

    def _route(self, method: str, path: str, body: str, addr: tuple) -> str:
        """Route request to the appropriate handler."""
        # Login page
        if path == "/login" and method == "POST":
            params = dict(p.split("=", 1) for p in body.split("&") if "=" in p)
            username = unquote_plus(params.get("username", ""))
            password = unquote_plus(params.get("password", ""))
            if self.hp_logger:
                self.hp_logger.log_credential(
                    honeypot_name="med_http",
                    src_ip=addr[0],
                    username=username,
                    password=password,
                )
            return _DASHBOARD

        elif path == "/login" or path == "/admin":
            return _LOGIN_PAGE

        # Dashboard
        elif path == "/":
            return _DASHBOARD

        # Directory listing
        elif path.startswith("/files"):
            normalized = path if path.endswith("/") else path + "/"
            entries_list = _FAKE_DIRS.get(normalized)
            if entries_list:
                entries_html = ""
                for entry in entries_list:
                    if entry.endswith("/"):
                        entries_html += f'<tr><td><span class="dir-icon">📁</span><a href="{normalized}{entry}">{entry}</a></td><td>-</td><td>Mar 10 2026</td></tr>'
                    else:
                        name_size = entry.split(" (")
                        name = name_size[0]
                        size = name_size[1].rstrip(")") if len(name_size) > 1 else "-"
                        entries_html += f'<tr><td><span class="file-icon">📄</span>{name}</td><td>{size}</td><td>Mar 10 2026</td></tr>'
                return _DIR_LISTING.replace("{path}", path).replace("{entries}", entries_html)
            return _DIR_LISTING.replace("{path}", path).replace("{entries}", "<tr><td colspan='3'>Empty directory</td></tr>")

        # Search (fake SQL injection target)
        elif path == "/search":
            query = ""
            results = ""
            if method == "POST" and body:
                params = dict(p.split("=", 1) for p in body.split("&") if "=" in p)
                query = unquote_plus(params.get("query", ""))
                if self.hp_logger:
                    self.hp_logger.log_command(
                        honeypot_name="med_http",
                        src_ip=addr[0],
                        command=f"SEARCH: {query}",
                    )
                # Fake SQL response
                results = (
                    '<table><tr><th>ID</th><th>Name</th><th>Email</th></tr>'
                    '<tr><td>1</td><td>admin</td><td>admin@example.com</td></tr>'
                    '<tr><td>2</td><td>john</td><td>john@example.com</td></tr>'
                    '</table>'
                )
            return _SEARCH_PAGE.replace("{query}", query).replace("{results}", results)

        # Command execution (fake RCE target)
        elif path == "/cmd":
            output = "$ _"
            if method == "POST" and body:
                params = dict(p.split("=", 1) for p in body.split("&") if "=" in p)
                cmd = unquote_plus(params.get("cmd", ""))
                if self.hp_logger:
                    self.hp_logger.log_command(
                        honeypot_name="med_http",
                        src_ip=addr[0],
                        command=f"WEB_CMD: {cmd}",
                    )
                output = f"$ {cmd}\n" + self._fake_cmd_output(cmd)
            return _CMD_PAGE.replace("{output}", output)

        # phpinfo
        elif path == "/phpinfo.php":
            return _PHPINFO

        # Server status
        elif path == "/server-status":
            return _SERVER_STATUS

        # robots.txt
        elif path == "/robots.txt":
            return "User-agent: *\nDisallow: /admin\nDisallow: /config/\nDisallow: /backup/\n"

        # 404
        else:
            return f"<h1>404 Not Found</h1><p>The requested URL {path} was not found.</p>"

    def _fake_cmd_output(self, cmd: str) -> str:
        """Return fake command output."""
        base = cmd.split()[0] if cmd.split() else ""
        if base == "ls":
            return "bin  etc  home  var  tmp  usr  root"
        elif base == "whoami":
            return "www-data"
        elif base == "id":
            return "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        elif base == "uname":
            return "Linux ubuntu-server-01 5.4.0-196-generic"
        elif base == "cat":
            return "Permission denied"
        elif base == "pwd":
            return "/var/www/html"
        else:
            return f"sh: {base}: command not found"

    def _http_response(self, status: str, body: str) -> str:
        return (
            f"HTTP/1.1 {status}\r\n"
            f"Server: {config.HTTP_SERVER_HEADER}\r\n"
            f"Content-Type: text/html; charset=UTF-8\r\n"
            f"Content-Length: {len(body.encode())}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )

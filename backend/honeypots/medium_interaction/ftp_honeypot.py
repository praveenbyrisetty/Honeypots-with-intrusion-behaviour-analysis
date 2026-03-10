"""
Medium-interaction FTP honeypot.
Provides a virtual filesystem that attackers can browse.
Supports: USER, PASS, LIST, PWD, CWD, RETR, STOR, TYPE, SYST, QUIT, PASV.
Logs all commands, credentials, and file transfer attempts.
"""

import socket
import uuid

from honeypots.base import BaseHoneypot
import config

# ── Virtual filesystem ────────────────────────────────────────────────
_VFS = {
    "/": ["backup", "www", "config", "upload"],
    "/backup": ["db_dump_2024.sql.gz", "users_export.csv", "full_backup.tar.gz"],
    "/www": ["index.html", "config.php", ".htaccess", "wp-admin"],
    "/www/wp-admin": ["admin.php", "setup-config.php"],
    "/config": ["database.yml", "secrets.env", "nginx.conf"],
    "/upload": [],
}

_VFS_FILES = {
    "/config/secrets.env": "DB_PASSWORD=super_secret_123\nAPI_KEY=sk-fake-key-1234567890\nAWS_SECRET=AKIAFAKEKEY\n",
    "/config/database.yml": "production:\n  host: db.internal\n  user: admin\n  password: pr0d_p@ss\n",
    "/www/config.php": "<?php\n$db_host = 'localhost';\n$db_user = 'root';\n$db_pass = 'toor';\n?>",
    "/www/.htaccess": "RewriteEngine On\nRewriteRule ^admin /wp-admin [R=301]\n",
    "/backup/users_export.csv": "id,username,email,role\n1,admin,admin@example.com,superadmin\n2,john,john@example.com,editor\n",
}

_DIR_LISTING_TEMPLATE = (
    "drwxr-xr-x 2 root root 4096 Mar 10 08:00 {name}\r\n"
)
_FILE_LISTING_TEMPLATE = (
    "-rw-r--r-- 1 root root {size:>8} Mar 10 08:00 {name}\r\n"
)


class MedFTPHoneypot(BaseHoneypot):
    """Medium-interaction FTP honeypot with a virtual filesystem."""

    def __init__(self, host: str = None, port: int = None, logger=None):
        super().__init__(
            name="med_ftp",
            host=host or config.BIND_HOST,
            port=port or config.MED_FTP_PORT,
            logger=logger,
        )

    def handle_connection(self, client_socket: socket.socket, client_address: tuple):
        client_socket.settimeout(60)
        cwd = "/"
        username = None
        authenticated = False
        session_id = None
        cmd_count = 0

        try:
            # Start session
            if self.hp_logger:
                session_id = self.hp_logger.start_session("med_ftp", client_address[0])

            # Banner
            client_socket.sendall(f"{config.FTP_BANNER}\r\n".encode())

            while True:
                data = client_socket.recv(1024)
                if not data:
                    break

                line = data.decode("utf-8", errors="replace").strip()
                if not line:
                    continue

                self._log.debug(f"FTP [{client_address[0]}]: {line}")
                parts = line.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""
                cmd_count += 1

                # Log every command
                if self.hp_logger:
                    self.hp_logger.log_command(
                        honeypot_name="med_ftp",
                        src_ip=client_address[0],
                        command=line,
                    )

                response = self._handle_ftp_cmd(
                    cmd, arg, client_socket, client_address,
                    cwd, username, authenticated
                )

                if cmd == "USER":
                    username = arg
                elif cmd == "PASS":
                    authenticated = True
                elif cmd == "CWD":
                    new_path = self._resolve(cwd, arg)
                    if new_path in _VFS:
                        cwd = new_path
                elif cmd == "CDUP":
                    parts_p = cwd.rsplit("/", 1)
                    cwd = parts_p[0] if parts_p[0] else "/"
                elif cmd == "QUIT":
                    client_socket.sendall(b"221 Goodbye.\r\n")
                    break

                if response:
                    client_socket.sendall(response.encode())

        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            self._log.debug(f"Med FTP error: {e}")
        finally:
            if self.hp_logger and session_id:
                self.hp_logger.end_session(session_id, cmd_count)

    def _handle_ftp_cmd(self, cmd, arg, sock, addr, cwd, username, authed):
        """Process an FTP command and return the response string."""
        if cmd == "USER":
            return "331 Please specify the password.\r\n"

        elif cmd == "PASS":
            if self.hp_logger:
                self.hp_logger.log_credential(
                    honeypot_name="med_ftp",
                    src_ip=addr[0],
                    username=username or "",
                    password=arg,
                )
            return "230 Login successful.\r\n"

        elif cmd == "SYST":
            return "215 UNIX Type: L8\r\n"

        elif cmd == "TYPE":
            return "200 Switching to Binary mode.\r\n"

        elif cmd == "PWD":
            return f'257 "{cwd}" is the current directory\r\n'

        elif cmd == "CWD":
            target = self._resolve(cwd, arg)
            if target in _VFS:
                return f'250 Directory successfully changed to "{target}".\r\n'
            return "550 Failed to change directory.\r\n"

        elif cmd == "CDUP":
            return "250 Directory successfully changed.\r\n"

        elif cmd == "LIST" or cmd == "NLST":
            target_dir = self._resolve(cwd, arg) if arg else cwd
            entries = _VFS.get(target_dir)
            if entries is None:
                return "550 No such directory.\r\n"

            listing = ""
            for name in entries:
                child = f"{target_dir.rstrip('/')}/{name}"
                if child in _VFS:
                    listing += _DIR_LISTING_TEMPLATE.format(name=name)
                else:
                    size = len(_VFS_FILES.get(child, "")) or 1024
                    listing += _FILE_LISTING_TEMPLATE.format(name=name, size=size)

            # Send listing inline (simulating passive mode transfer on control)
            return (
                "150 Here comes the directory listing.\r\n"
                + listing
                + "226 Directory send OK.\r\n"
            )

        elif cmd == "RETR":
            filepath = self._resolve(cwd, arg)
            content = _VFS_FILES.get(filepath)
            if content:
                return (
                    "150 Opening BINARY mode data connection.\r\n"
                    f"{content}"
                    "226 Transfer complete.\r\n"
                )
            return "550 File not found.\r\n"

        elif cmd == "STOR":
            return "150 Ok to send data.\r\n226 Transfer complete.\r\n"

        elif cmd == "PASV":
            return "227 Entering Passive Mode (127,0,0,1,39,57).\r\n"

        elif cmd == "FEAT":
            return "211-Features:\r\n PASV\r\n UTF8\r\n211 End\r\n"

        elif cmd == "QUIT":
            return ""

        else:
            return f"502 Command not implemented: {cmd}\r\n"

    def _resolve(self, cwd: str, path: str) -> str:
        """Resolve relative/absolute path in virtual FS."""
        if path.startswith("/"):
            return path.rstrip("/") or "/"
        combined = f"{cwd.rstrip('/')}/{path}"
        parts = []
        for p in combined.split("/"):
            if p == "..":
                if parts:
                    parts.pop()
            elif p and p != ".":
                parts.append(p)
        return "/" + "/".join(parts) if parts else "/"

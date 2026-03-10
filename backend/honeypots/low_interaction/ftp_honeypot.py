"""
Low-interaction FTP honeypot.
Speaks just enough FTP to capture credentials, then rejects login.
"""

import socket

from honeypots.base import BaseHoneypot
import config


class LowFTPHoneypot(BaseHoneypot):
    """Low-interaction FTP honeypot — banner, USER, PASS, reject."""

    def __init__(self, host: str = None, port: int = None, logger=None):
        super().__init__(
            name="low_ftp",
            host=host or config.BIND_HOST,
            port=port or config.LOW_FTP_PORT,
            logger=logger,
        )

    def handle_connection(self, client_socket: socket.socket, client_address: tuple):
        client_socket.settimeout(30)
        username = None

        try:
            # Send FTP banner
            client_socket.sendall(f"{config.FTP_BANNER}\r\n".encode())

            while True:
                data = client_socket.recv(1024)
                if not data:
                    break

                line = data.decode("utf-8", errors="replace").strip()
                self._log.debug(f"FTP [{client_address[0]}]: {line}")

                parts = line.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                if cmd == "USER":
                    username = arg
                    client_socket.sendall(b"331 Please specify the password.\r\n")

                elif cmd == "PASS":
                    password = arg
                    if self.hp_logger:
                        self.hp_logger.log_credential(
                            honeypot_name="low_ftp",
                            src_ip=client_address[0],
                            username=username or "",
                            password=password,
                        )
                    client_socket.sendall(b"530 Login incorrect.\r\n")

                elif cmd == "QUIT":
                    client_socket.sendall(b"221 Goodbye.\r\n")
                    break

                else:
                    client_socket.sendall(b"530 Please login with USER and PASS.\r\n")

        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            self._log.debug(f"FTP error: {e}")

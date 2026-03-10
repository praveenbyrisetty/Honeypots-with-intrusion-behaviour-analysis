"""
Low-interaction Telnet honeypot.
Presents a login prompt, captures credentials, always rejects.
"""

import socket

from honeypots.base import BaseHoneypot
import config


class LowTelnetHoneypot(BaseHoneypot):
    """Low-interaction Telnet honeypot — login prompt, credential capture."""

    def __init__(self, host: str = None, port: int = None, logger=None):
        super().__init__(
            name="low_telnet",
            host=host or config.BIND_HOST,
            port=port or config.LOW_TELNET_PORT,
            logger=logger,
        )

    def handle_connection(self, client_socket: socket.socket, client_address: tuple):
        client_socket.settimeout(30)

        try:
            # Send banner
            client_socket.sendall(config.TELNET_BANNER.encode())

            # Ask for username
            client_socket.sendall(b"login: ")
            username_data = client_socket.recv(1024)
            if not username_data:
                return
            username = username_data.decode("utf-8", errors="replace").strip()

            # Ask for password
            client_socket.sendall(b"Password: ")
            password_data = client_socket.recv(1024)
            if not password_data:
                return
            password = password_data.decode("utf-8", errors="replace").strip()

            # Log credentials
            if self.hp_logger:
                self.hp_logger.log_credential(
                    honeypot_name="low_telnet",
                    src_ip=client_address[0],
                    username=username,
                    password=password,
                )

            # Reject
            client_socket.sendall(b"\r\nLogin incorrect\r\n")

            # Give them a couple more tries
            for _ in range(2):
                client_socket.sendall(b"\r\nlogin: ")
                udata = client_socket.recv(1024)
                if not udata:
                    break
                u = udata.decode("utf-8", errors="replace").strip()

                client_socket.sendall(b"Password: ")
                pdata = client_socket.recv(1024)
                if not pdata:
                    break
                p = pdata.decode("utf-8", errors="replace").strip()

                if self.hp_logger:
                    self.hp_logger.log_credential(
                        honeypot_name="low_telnet",
                        src_ip=client_address[0],
                        username=u,
                        password=p,
                    )
                client_socket.sendall(b"\r\nLogin incorrect\r\n")

        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            self._log.debug(f"Telnet error: {e}")

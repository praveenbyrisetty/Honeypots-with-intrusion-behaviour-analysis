"""
Low-interaction SSH honeypot.
Presents an SSH banner, accepts auth attempts (always rejects), logs credentials.
Uses paramiko for SSH protocol handling.
"""

import logging
import socket
import threading
import paramiko

from honeypots.base import BaseHoneypot
import config


class _SSHServerInterface(paramiko.ServerInterface):
    """Paramiko server interface that rejects all auth and logs attempts."""

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
                honeypot_name="low_ssh",
                src_ip=self.client_ip,
                username=username,
                password=password,
            )
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"


class LowSSHHoneypot(BaseHoneypot):
    """Low-interaction SSH honeypot."""

    def __init__(self, host: str = None, port: int = None, logger=None):
        super().__init__(
            name="low_ssh",
            host=host or config.BIND_HOST,
            port=port or config.LOW_SSH_PORT,
            logger=logger,
        )
        self._host_key = self._get_or_create_host_key()

    def _get_or_create_host_key(self) -> paramiko.RSAKey:
        """Load or generate the SSH host RSA key."""
        import os
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

            server = _SSHServerInterface(client_address[0], self.hp_logger)
            transport.start_server(server=server)

            # Wait up to 30s for auth; it will always fail
            channel = transport.accept(30)
            if channel:
                channel.close()
        except Exception as e:
            self._log.debug(f"SSH session error: {e}")
        finally:
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass

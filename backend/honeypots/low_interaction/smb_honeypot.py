"""
Low-interaction SMB honeypot.
Responds with a minimal SMB negotiate response to log connection attempts.
"""

import socket
import struct

from honeypots.base import BaseHoneypot
import config

# Minimal SMB2 Negotiate Response (simplified)
_SMB2_HEADER = (
    b"\x00\x00\x00\x8a"  # NetBIOS length
    b"\xfeSMB"            # SMB2 magic
    b"\x40\x00"           # Header length
    b"\x00\x00"           # Credit charge
    b"\x00\x00\x00\x00"   # Status: SUCCESS
    b"\x00\x00"           # Command: NEGOTIATE
    b"\x01\x00"           # Credits granted
    b"\x01\x00\x00\x00"   # Flags: response
    b"\x00\x00\x00\x00"   # Next command
    b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Message ID
    b"\x00\x00\x00\x00"   # Process ID
    b"\x00\x00\x00\x00"   # Tree ID
    b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Session ID
)

_SMB2_BODY = (
    b"\x41\x00"           # Structure size
    b"\x01\x00"           # Security mode
    b"\x11\x03"           # Dialect: SMB 3.1.1
    b"\x00\x00"           # Negotiate context count
)

_SMB2_NEGOTIATE_RESPONSE = (
    _SMB2_HEADER
    + b"\x00" * 16        # Signature
    + _SMB2_BODY
    + b"\x00" * 16        # Server GUID
    + b"\x07\x00\x00\x00" # Capabilities
    + b"\x00\x00\x10\x00" # Max transact size
    + b"\x00\x00\x10\x00" # Max read size
    + b"\x00\x00\x10\x00" # Max write size
)


class LowSMBHoneypot(BaseHoneypot):
    """Low-interaction SMB honeypot — responds to negotiate, logs connections."""

    def __init__(self, host: str = None, port: int = None, logger=None):
        super().__init__(
            name="low_smb",
            host=host or config.BIND_HOST,
            port=port or config.LOW_SMB_PORT,
            logger=logger,
        )

    def handle_connection(self, client_socket: socket.socket, client_address: tuple):
        client_socket.settimeout(30)

        try:
            # Read the initial negotiate request
            data = client_socket.recv(4096)
            if not data:
                return

            # Log the raw negotiate payload
            if self.hp_logger:
                self.hp_logger.log_payload(
                    honeypot_name="low_smb",
                    src_ip=client_address[0],
                    data=data.hex(),
                )

            # Send a minimal negotiate response
            client_socket.sendall(_SMB2_NEGOTIATE_RESPONSE)

            # Read one more packet (session setup attempt) before closing
            try:
                more_data = client_socket.recv(4096)
                if more_data and self.hp_logger:
                    self.hp_logger.log_payload(
                        honeypot_name="low_smb",
                        src_ip=client_address[0],
                        data=more_data.hex(),
                    )
            except (socket.timeout, ConnectionResetError):
                pass

        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            self._log.debug(f"SMB error: {e}")
